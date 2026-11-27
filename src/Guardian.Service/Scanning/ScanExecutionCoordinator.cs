using Guardian.Contracts.Ipc;
using Guardian.Contracts.Scanning;
using Microsoft.Extensions.Logging;

namespace Guardian.Service.Scanning;

/// <summary>
/// Implémentation thread-safe de la coordination des analyses rapides, complètes (tout le disque) et personnalisées.
/// </summary>
public sealed class ScanExecutionCoordinator : IScanExecutionCoordinator, IDisposable
{
    private readonly IScanOrchestrator _scanOrchestrator;
    private readonly ILogger<ScanExecutionCoordinator> _logger;
    private readonly object _gate = new();

    private bool _isRunning;
    private Guid? _activeScanId;
    private ScanScope? _activeScope;
    private int _percent;
    private string _currentPath = string.Empty;
    private int _filesProcessed;
    private int _totalFiles;
    private int _findingsCount;
    private string _statusMessage = "Idle";
    private ScanSummary? _lastCompletedSummary;
    private CancellationTokenSource? _activeCts;

    /// <summary>
    /// Initialise le coordinateur d'exécution de scan.
    /// </summary>
    /// <param name="scanOrchestrator">Orchestrateur de scan de fichiers.</param>
    /// <param name="logger">Journaliseur structuré.</param>
    public ScanExecutionCoordinator(
        IScanOrchestrator scanOrchestrator,
        ILogger<ScanExecutionCoordinator> logger)
    {
        _scanOrchestrator = scanOrchestrator ?? throw new ArgumentNullException(nameof(scanOrchestrator));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public Task<(bool Accepted, string Message, IpcScanStatusDto Status)> StartScanAsync(
        ScanScope scope,
        string? customPath,
        CancellationToken serviceStoppingToken = default)
    {
        if (!Enum.IsDefined(scope))
        {
            return Task.FromResult((false, "Invalid scan scope.", GetStatus()));
        }

        string? normalizedCustomPath = null;
        if (scope == ScanScope.Custom)
        {
            if (string.IsNullOrWhiteSpace(customPath))
            {
                return Task.FromResult((false, "Custom path is required for Custom scan scope.", GetStatus()));
            }

            normalizedCustomPath = Path.GetFullPath(customPath);
            if (!File.Exists(normalizedCustomPath) && !Directory.Exists(normalizedCustomPath))
            {
                return Task.FromResult((false, "Custom scan target path does not exist.", GetStatus()));
            }
        }

        Guid scanId;
        CancellationTokenSource linkedCts;
        IpcScanStatusDto snapshot;

        lock (_gate)
        {
            if (_isRunning)
            {
                return Task.FromResult((false, "A scan is already running.", GetStatusUnsafe()));
            }

            scanId = Guid.NewGuid();
            linkedCts = CancellationTokenSource.CreateLinkedTokenSource(serviceStoppingToken);

            _isRunning = true;
            _activeScanId = scanId;
            _activeScope = scope;
            _percent = 0;
            _currentPath = string.Empty;
            _filesProcessed = 0;
            _totalFiles = 0;
            _findingsCount = 0;
            _statusMessage = $"Starting {scope} scan...";
            _activeCts = linkedCts;

            snapshot = GetStatusUnsafe();
        }

        _logger.LogInformation("Accepted {Scope} scan request {ScanId}.", scope, scanId);

        _ = Task.Run(async () => await ExecuteScanAsync(scanId, scope, normalizedCustomPath, linkedCts).ConfigureAwait(false), CancellationToken.None);

        return Task.FromResult((true, $"Started {scope} scan.", snapshot));
    }

    /// <inheritdoc />
    public IpcScanStatusDto GetStatus()
    {
        lock (_gate)
        {
            return GetStatusUnsafe();
        }
    }

    /// <inheritdoc />
    public bool CancelActiveScan()
    {
        lock (_gate)
        {
            if (!_isRunning || _activeCts is null)
            {
                return false;
            }

            _statusMessage = "Canceling scan...";
            _activeCts.Cancel();
            return true;
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        lock (_gate)
        {
            _activeCts?.Cancel();
            _activeCts?.Dispose();
            _activeCts = null;
        }
    }

    private async Task ExecuteScanAsync(
        Guid scanId,
        ScanScope scope,
        string? customPath,
        CancellationTokenSource linkedCts)
    {
        var progress = new SynchronousProgress<ScanProgressInfo>(info =>
        {
            lock (_gate)
            {
                if (_activeScanId != scanId)
                {
                    return;
                }

                _percent = Math.Clamp(info.Percent, 0, 100);
                _currentPath = info.CurrentPath;
                _filesProcessed = info.FilesProcessed;
                _totalFiles = info.FilesTotal;
                _findingsCount = info.ThreatsFound;
                _statusMessage = $"Scanning ({_filesProcessed}/{_totalFiles})...";
            }
        });

        try
        {
            var summary = await _scanOrchestrator.RunAsync(
                new ScanJobRequest { Scope = scope, CustomPath = customPath },
                progress,
                linkedCts.Token).ConfigureAwait(false);

            lock (_gate)
            {
                if (_activeScanId == scanId)
                {
                    var total = summary.FilesScanned + summary.FilesSkipped;
                    _isRunning = false;
                    _percent = 100;
                    _currentPath = string.Empty;
                    _filesProcessed = total;
                    _totalFiles = total;
                    _findingsCount = summary.Findings.Count;
                    _lastCompletedSummary = summary;
                    _statusMessage = $"Scan completed: {summary.FilesScanned} scanned, {summary.Findings.Count} finding(s).";
                }
            }

            _logger.LogInformation(
                "Completed {Scope} scan {ScanId}: {Scanned} scanned, {Skipped} skipped, {Findings} finding(s).",
                scope,
                scanId,
                summary.FilesScanned,
                summary.FilesSkipped,
                summary.Findings.Count);
        }
        catch (OperationCanceledException)
        {
            lock (_gate)
            {
                if (_activeScanId == scanId)
                {
                    _isRunning = false;
                    _currentPath = string.Empty;
                    _statusMessage = "Scan canceled.";
                }
            }

            _logger.LogInformation("Scan {ScanId} was canceled.", scanId);
        }
        catch (Exception ex)
        {
            lock (_gate)
            {
                if (_activeScanId == scanId)
                {
                    _isRunning = false;
                    _currentPath = string.Empty;
                    _statusMessage = $"Scan failed: {ex.Message}";
                }
            }

            _logger.LogError(ex, "Scan {ScanId} failed unexpectedly.", scanId);
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_activeCts, linkedCts))
                {
                    _activeCts = null;
                }
            }

            linkedCts.Dispose();
        }
    }

    private IpcScanStatusDto GetStatusUnsafe()
    {
        return new IpcScanStatusDto(
            ActiveScanId: _activeScanId,
            IsRunning: _isRunning,
            Scope: _activeScope,
            Percent: _percent,
            CurrentPath: _currentPath,
            FilesProcessed: _filesProcessed,
            TotalFiles: _totalFiles,
            FindingsCount: _findingsCount,
            StatusMessage: _statusMessage,
            LastCompletedSummary: _lastCompletedSummary);
    }

    private sealed class SynchronousProgress<T>(Action<T> onReport) : IProgress<T>
    {
        public void Report(T value) => onReport(value);
    }
}
