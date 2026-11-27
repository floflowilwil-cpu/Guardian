using Guardian.Contracts.Common;
using Guardian.Contracts.Memory;
using Guardian.Contracts.System;
using Guardian.SystemMonitor.Configuration;
using Guardian.SystemMonitor.Detection;
using Guardian.SystemMonitor.Events;
using Guardian.SystemMonitor.Sensors;
using Guardian.Windows.Memory;
using Guardian.Windows.Processes;
using Guardian.Windows.Registry;
using Guardian.Windows.Security;
using Guardian.Windows.Services;
using Guardian.Windows.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Guardian.SystemMonitor;

/// <summary>
/// Implémentation principale unifiée de <see cref="ISystemMonitor"/> et <see cref="IBehaviorMonitor"/> :
/// inventaire en lecture seule, capteurs différentiels (processus, persistance, tâches planifiées,
/// posture Windows, supports amovibles, rafales fichiers) et balayage mémoire défensif.
/// </summary>
public sealed class SystemMonitorService : ISystemMonitor, IBehaviorMonitor, IDisposable
{
    private readonly IWindowsProcessAdapter _processAdapter;
    private readonly IWindowsServiceAdapter _serviceAdapter;
    private readonly IWindowsRegistryAdapter _registryAdapter;
    private readonly IWindowsScheduledTaskAdapter _scheduledTaskAdapter;
    private readonly IWindowsSecurityPostureReader _postureReader;
    private readonly IWindowsAuthenticodeVerifier _authenticodeVerifier;
    private readonly IWindowsMemoryAdapter _memoryAdapter;
    private readonly IRemovableDriveProvider _removableDriveProvider;
    private readonly BoundedSystemEventStore _eventStore;
    private readonly WindowsEtwCapabilityProbe _etwProbe;
    private readonly IOptions<SystemMonitorOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<SystemMonitorService> _logger;

    private readonly ProcessActivityTracker _processTracker;
    private readonly PersistenceChangeTracker _persistenceTracker;
    private readonly SecurityPostureChangeTracker _postureTracker;
    private readonly FileBurstDetector _burstDetector;
    private readonly RemovableDriveTracker _removableDriveTracker;
    private readonly DirectoryBurstSensor _burstSensor;

    private readonly object _lifecycleGate = new();
    private readonly SemaphoreSlim _cycleGate = new(1, 1);

    private CancellationTokenSource? _loopCts;
    private Task? _loopTask;
    private volatile bool _isRunning;
    private bool _disposed;
    private DateTimeOffset? _startedAtUtc;
    private DateTimeOffset? _lastObservationUtc;
    private DateTimeOffset? _lastMemorySweepUtc;
    private EtwCapabilityStatus _etwCapability;

    /// <summary>
    /// Initialise le service de surveillance système et comportementale.
    /// </summary>
    /// <param name="processAdapter">Adaptateur processus Win32 en lecture seule.</param>
    /// <param name="serviceAdapter">Adaptateur services Windows SCM.</param>
    /// <param name="registryAdapter">Adaptateur registre et dossiers de démarrage.</param>
    /// <param name="scheduledTaskAdapter">Adaptateur XML des tâches planifiées.</param>
    /// <param name="postureReader">Lecteur passif de posture sécurité Windows.</param>
    /// <param name="authenticodeVerifier">Vérificateur SHA-256 et Authenticode.</param>
    /// <param name="memoryAdapter">Analyseur défensif des métadonnées mémoire.</param>
    /// <param name="removableDriveProvider">Fournisseur d'inventaire des lecteurs amovibles.</param>
    /// <param name="eventStore">Tampon borné d'événements comportementaux.</param>
    /// <param name="etwProbe">Sonde de disponibilité ETW.</param>
    /// <param name="options">Options validées de surveillance.</param>
    /// <param name="timeProvider">Horloge injectée.</param>
    /// <param name="logger">Journaliseur structuré.</param>
    public SystemMonitorService(
        IWindowsProcessAdapter processAdapter,
        IWindowsServiceAdapter serviceAdapter,
        IWindowsRegistryAdapter registryAdapter,
        IWindowsScheduledTaskAdapter scheduledTaskAdapter,
        IWindowsSecurityPostureReader postureReader,
        IWindowsAuthenticodeVerifier authenticodeVerifier,
        IWindowsMemoryAdapter memoryAdapter,
        IRemovableDriveProvider removableDriveProvider,
        BoundedSystemEventStore eventStore,
        WindowsEtwCapabilityProbe etwProbe,
        IOptions<SystemMonitorOptions> options,
        TimeProvider timeProvider,
        ILogger<SystemMonitorService> logger)
    {
        _processAdapter = processAdapter ?? throw new ArgumentNullException(nameof(processAdapter));
        _serviceAdapter = serviceAdapter ?? throw new ArgumentNullException(nameof(serviceAdapter));
        _registryAdapter = registryAdapter ?? throw new ArgumentNullException(nameof(registryAdapter));
        _scheduledTaskAdapter = scheduledTaskAdapter ?? throw new ArgumentNullException(nameof(scheduledTaskAdapter));
        _postureReader = postureReader ?? throw new ArgumentNullException(nameof(postureReader));
        _authenticodeVerifier = authenticodeVerifier ?? throw new ArgumentNullException(nameof(authenticodeVerifier));
        _memoryAdapter = memoryAdapter ?? throw new ArgumentNullException(nameof(memoryAdapter));
        _removableDriveProvider = removableDriveProvider ?? throw new ArgumentNullException(nameof(removableDriveProvider));
        _eventStore = eventStore ?? throw new ArgumentNullException(nameof(eventStore));
        _etwProbe = etwProbe ?? throw new ArgumentNullException(nameof(etwProbe));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        var opts = _options.Value;
        _processTracker = new ProcessActivityTracker(_timeProvider, opts.MemoryAlertCooldownMinutes);
        _persistenceTracker = new PersistenceChangeTracker(_timeProvider);
        _postureTracker = new SecurityPostureChangeTracker(_timeProvider);
        _burstDetector = new FileBurstDetector(
            _timeProvider,
            opts.FileBurstWindowSeconds,
            opts.FileBurstThreshold,
            opts.FileBurstCooldownSeconds);
        _removableDriveTracker = new RemovableDriveTracker(_timeProvider);
        _burstSensor = new DirectoryBurstSensor(_burstDetector, _eventStore, _logger);
        _etwCapability = new EtwCapabilityStatus(
            FeatureAvailabilityStatus.Unavailable,
            CanSubscribeUserModeProviders: false,
            RequiresElevationForFullEtw: false,
            Summary: "Not yet initialized.");
    }

    /// <inheritdoc />
    public event EventHandler<SystemSecurityEventDto>? EventDetected
    {
        add => _eventStore.EventDetected += value;
        remove => _eventStore.EventDetected -= value;
    }

    /// <summary>
    /// Indique si la boucle de surveillance système est actuellement active.
    /// </summary>
    public bool IsRunning => _isRunning;

    /// <summary>
    /// Horodatage UTC du dernier cycle d'observation achevé, s'il existe.
    /// </summary>
    public DateTimeOffset? LastObservationUtc => _lastObservationUtc;

    /// <summary>
    /// Statut vérifiable de la capacité ETW observée au démarrage.
    /// </summary>
    public EtwCapabilityStatus EtwCapability => _etwCapability;

    /// <inheritdoc />
    public Task StartAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        lock (_lifecycleGate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_isRunning)
            {
                return Task.CompletedTask;
            }

            _etwCapability = _etwProbe.Probe();
            _startedAtUtc = _timeProvider.GetUtcNow();

            var opts = _options.Value;
            if (opts.EnableFileSystemWatch && opts.WatchedDirectories.Count > 0)
            {
                _burstSensor.Start(opts.WatchedDirectories);
            }

            var cts = new CancellationTokenSource();
            _loopCts = cts;
            _isRunning = true;
            _loopTask = Task.Run(() => RunPollingLoopAsync(cts.Token), CancellationToken.None);

            _logger.LogInformation(
                "SystemMonitor started (ETW={EtwAvailability}, BurstWatchers={WatcherCount}).",
                _etwCapability.Availability,
                _burstSensor.ActiveWatcherCount);
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        CancellationTokenSource? cts;
        Task? loopTask;

        lock (_lifecycleGate)
        {
            if (!_isRunning)
            {
                _burstSensor.Stop();
                return;
            }

            _isRunning = false;
            cts = _loopCts;
            loopTask = _loopTask;
            _loopCts = null;
            _loopTask = null;
        }

        _burstSensor.Stop();

        if (cts is not null)
        {
            await cts.CancelAsync().ConfigureAwait(false);
        }

        if (loopTask is not null)
        {
            try
            {
                await loopTask.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested || (cts?.IsCancellationRequested ?? false))
            {
                // Arrêt attendu lors de l'annulation.
            }
        }

        cts?.Dispose();
        _logger.LogInformation("SystemMonitor stopped.");
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<ProcessInfoDto>> GetProcessesAsync(
        bool includeModules = false,
        CancellationToken cancellationToken = default) =>
        _processAdapter.GetProcessesAsync(includeModules, cancellationToken);

    /// <inheritdoc />
    public Task<IReadOnlyList<WindowsServiceInfoDto>> GetServicesAsync(CancellationToken cancellationToken = default) =>
        _serviceAdapter.GetServicesAsync(cancellationToken);

    /// <inheritdoc />
    public async Task<IReadOnlyList<StartupEntryDto>> GetStartupEntriesAsync(CancellationToken cancellationToken = default)
    {
        var registryEntries = await _registryAdapter.GetStartupEntriesAsync(cancellationToken).ConfigureAwait(false);
        var scheduledTasks = await _scheduledTaskAdapter.GetScheduledTasksAsync(cancellationToken).ConfigureAwait(false);

        if (scheduledTasks.Count == 0)
        {
            return registryEntries;
        }

        var merged = new List<StartupEntryDto>(registryEntries.Count + scheduledTasks.Count);
        merged.AddRange(registryEntries);
        merged.AddRange(scheduledTasks);
        return merged;
    }

    /// <inheritdoc />
    public Task<WindowsSecurityPostureDto> GetSecurityPostureAsync(CancellationToken cancellationToken = default) =>
        _postureReader.ReadPostureAsync(cancellationToken);

    /// <inheritdoc />
    public Task<FileIntegrityResultDto> VerifyFileIntegrityAsync(
        string filePath,
        string? expectedSha256 = null,
        CancellationToken cancellationToken = default) =>
        _authenticodeVerifier.VerifyFileAsync(filePath, expectedSha256, cancellationToken);

    /// <inheritdoc />
    public Task<IReadOnlyList<SystemSecurityEventDto>> GetRecentEventsAsync(
        int maxCount = 100,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(_eventStore.GetRecent(maxCount));
    }

    /// <summary>
    /// Exécute un cycle complet d'observation différentielle de façon synchrone et thread-safe
    /// (utile aussi bien pour la boucle de fond que pour les tests déterministes).
    /// </summary>
    /// <param name="includeMemorySweep">Force un balayage défensif des métadonnées mémoire pendant ce cycle.</param>
    /// <param name="includeProcessModules">Indique s'il faut collecter les modules chargés lors de l'inventaire processus.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Liste des événements produits et publiés durant ce cycle.</returns>
    public async Task<IReadOnlyList<SystemSecurityEventDto>> RunSingleObservationCycleAsync(
        bool includeMemorySweep = false,
        bool includeProcessModules = false,
        CancellationToken cancellationToken = default)
    {
        await _cycleGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var generated = new List<SystemSecurityEventDto>();

            await RunStepSafelyAsync(async ct =>
            {
                var processes = await _processAdapter.GetProcessesAsync(includeProcessModules, ct).ConfigureAwait(false);
                generated.AddRange(_processTracker.EvaluateProcessSnapshot(processes));
            }, "ProcessSnapshot", cancellationToken).ConfigureAwait(false);

            await RunStepSafelyAsync(async ct =>
            {
                var services = await _serviceAdapter.GetServicesAsync(ct).ConfigureAwait(false);
                generated.AddRange(_persistenceTracker.EvaluateServices(services));
            }, "ServicesSnapshot", cancellationToken).ConfigureAwait(false);

            await RunStepSafelyAsync(async ct =>
            {
                var startupEntries = await GetStartupEntriesAsync(ct).ConfigureAwait(false);
                generated.AddRange(_persistenceTracker.EvaluateStartupEntries(startupEntries));
            }, "StartupPersistenceSnapshot", cancellationToken).ConfigureAwait(false);

            if (_options.Value.EnablePostureWatch)
            {
                await RunStepSafelyAsync(async ct =>
                {
                    var posture = await _postureReader.ReadPostureAsync(ct).ConfigureAwait(false);
                    generated.AddRange(_postureTracker.EvaluatePosture(posture));
                }, "SecurityPostureSnapshot", cancellationToken).ConfigureAwait(false);
            }

            if (_options.Value.EnableRemovableDriveWatch)
            {
                await RunStepSafelyAsync(_ =>
                {
                    var drives = _removableDriveProvider.GetRemovableDrives();
                    generated.AddRange(_removableDriveTracker.EvaluateDrives(drives));
                    return Task.CompletedTask;
                }, "RemovableDrivesSnapshot", cancellationToken).ConfigureAwait(false);
            }

            if (includeMemorySweep && _options.Value.EnableMemorySweep)
            {
                await RunStepSafelyAsync(async ct =>
                {
                    var memoryReports = await _memoryAdapter.ScanAllAccessibleProcessesAsync(ct).ConfigureAwait(false);
                    generated.AddRange(_processTracker.EvaluateMemoryReports(memoryReports));
                    _lastMemorySweepUtc = _timeProvider.GetUtcNow();
                }, "MemoryMetadataSweep", cancellationToken).ConfigureAwait(false);
            }

            foreach (var evt in generated)
            {
                _eventStore.Publish(evt);
            }

            _lastObservationUtc = _timeProvider.GetUtcNow();
            return generated;
        }
        finally
        {
            _cycleGate.Release();
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        lock (_lifecycleGate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _isRunning = false;
            _loopCts?.Cancel();
            _loopCts?.Dispose();
            _loopCts = null;
        }

        _burstSensor.Dispose();
        _cycleGate.Dispose();
    }

    private async Task RunPollingLoopAsync(CancellationToken stoppingToken)
    {
        var opts = _options.Value;
        var pollInterval = TimeSpan.FromSeconds(Math.Max(1, opts.PollingIntervalSeconds));
        var memoryInterval = TimeSpan.FromSeconds(Math.Max(5, opts.MemoryScanIntervalSeconds));

        using var timer = new PeriodicTimer(pollInterval, _timeProvider);

        try
        {
            var initialMemoryDue = ShouldRunMemorySweep();
            await RunSingleObservationCycleAsync(initialMemoryDue, includeProcessModules: false, stoppingToken).ConfigureAwait(false);

            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                var memoryDue = ShouldRunMemorySweep(memoryInterval);
                await RunSingleObservationCycleAsync(memoryDue, includeProcessModules: false, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Arrêt normal du moniteur.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SystemMonitor polling loop terminated unexpectedly.");
        }
    }

    private bool ShouldRunMemorySweep(TimeSpan? interval = null)
    {
        if (!_options.Value.EnableMemorySweep)
        {
            return false;
        }

        var baseline = _lastMemorySweepUtc ?? _startedAtUtc;
        if (baseline is null)
        {
            return false;
        }

        var threshold = interval ?? TimeSpan.FromSeconds(Math.Max(5, _options.Value.MemoryScanIntervalSeconds));
        return _timeProvider.GetUtcNow() - baseline.Value >= threshold;
    }

    private async Task RunStepSafelyAsync(
        Func<CancellationToken, Task> step,
        string stepName,
        CancellationToken cancellationToken)
    {
        try
        {
            await step(cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "SystemMonitor observation step '{StepName}' failed and will retry on next cycle.", stepName);
        }
    }
}
