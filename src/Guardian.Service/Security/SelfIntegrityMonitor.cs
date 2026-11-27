using Guardian.Contracts.Common;
using Guardian.Contracts.Health;
using Guardian.Service.Configuration;
using Guardian.Windows.Environment;
using Guardian.Windows.Security;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Guardian.Service.Security;

/// <summary>
/// Surveille l'auto-intégrité des binaires Guardian (SHA-256 + Authenticode) et les ACL du répertoire de données.
/// </summary>
public sealed class SelfIntegrityMonitor : ISelfIntegrityMonitor, IDisposable
{
    private readonly IWindowsAuthenticodeVerifier _authenticodeVerifier;
    private readonly IWindowsAclInspector _aclInspector;
    private readonly IWindowsPrivilegeInspector _privilegeInspector;
    private readonly IGuardianHealthService _healthService;
    private readonly IOptions<GuardianServiceOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<SelfIntegrityMonitor> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Dictionary<string, string> _baselineHashes = new(StringComparer.OrdinalIgnoreCase);

    private bool _baselineInitialized;
    private string _monitoredDirectory = string.Empty;

    /// <summary>
    /// Initialise le moniteur d'auto-intégrité du service Guardian.
    /// </summary>
    /// <param name="authenticodeVerifier">Vérificateur SHA-256 et Authenticode.</param>
    /// <param name="aclInspector">Inspecteur des permissions NTFS.</param>
    /// <param name="privilegeInspector">Inspecteur de chemins standards Guardian.</param>
    /// <param name="healthService">Service central de santé Guardian.</param>
    /// <param name="options">Options validées du service.</param>
    /// <param name="timeProvider">Fournisseur d'horloge injecté.</param>
    /// <param name="logger">Journaliseur structuré.</param>
    public SelfIntegrityMonitor(
        IWindowsAuthenticodeVerifier authenticodeVerifier,
        IWindowsAclInspector aclInspector,
        IWindowsPrivilegeInspector privilegeInspector,
        IGuardianHealthService healthService,
        IOptions<GuardianServiceOptions> options,
        TimeProvider timeProvider,
        ILogger<SelfIntegrityMonitor> logger)
    {
        _authenticodeVerifier = authenticodeVerifier ?? throw new ArgumentNullException(nameof(authenticodeVerifier));
        _aclInspector = aclInspector ?? throw new ArgumentNullException(nameof(aclInspector));
        _privilegeInspector = privilegeInspector ?? throw new ArgumentNullException(nameof(privilegeInspector));
        _healthService = healthService ?? throw new ArgumentNullException(nameof(healthService));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public async Task<SelfIntegrityReportDto> InitializeBaselineAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var options = _options.Value;
            _monitoredDirectory = ResolveMonitoredDirectory(options);
            _baselineHashes.Clear();

            var onlyGuardianPrefixed = string.IsNullOrWhiteSpace(options.IntegrityMonitoredDirectory);
            var files = DiscoverMonitoredBinaries(_monitoredDirectory, onlyGuardianPrefixed);

            foreach (var file in files)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var result = await _authenticodeVerifier.VerifyFileAsync(file, expectedSha256: null, cancellationToken)
                    .ConfigureAwait(false);

                if (result.Exists && !string.IsNullOrWhiteSpace(result.Sha256))
                {
                    _baselineHashes[file] = result.Sha256;
                }
            }

            _baselineInitialized = true;
            return await EvaluateInternalAsync(options, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <inheritdoc />
    public async Task<SelfIntegrityReportDto> VerifyIntegrityAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!_baselineInitialized)
            {
                _gate.Release();
                try
                {
                    return await InitializeBaselineAsync(cancellationToken).ConfigureAwait(false);
                }
                finally
                {
                    await _gate.WaitAsync(CancellationToken.None).ConfigureAwait(false);
                }
            }

            return await EvaluateInternalAsync(_options.Value, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            if (_gate.CurrentCount == 0)
            {
                _gate.Release();
            }
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _gate.Dispose();
    }

    private async Task<SelfIntegrityReportDto> EvaluateInternalAsync(
        GuardianServiceOptions options,
        CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var anomalies = new List<string>();
        var verifiedCount = 0;

        foreach (var (filePath, expectedHash) in _baselineHashes.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var fileName = Path.GetFileName(filePath);
            var verification = await _authenticodeVerifier
                .VerifyFileAsync(filePath, expectedHash, cancellationToken)
                .ConfigureAwait(false);

            if (!verification.Exists)
            {
                anomalies.Add($"Monitored binary missing: '{fileName}'.");
                continue;
            }

            if (verification.ExpectedHashMatched == false)
            {
                anomalies.Add($"Unauthorized modification detected (SHA-256 mismatch) on '{fileName}'.");
                continue;
            }

            if (options.RequireSignedBinaries && !verification.IsSignatureValid)
            {
                anomalies.Add($"Binary '{fileName}' does not have a valid Authenticode signature.");
                continue;
            }

            verifiedCount++;
        }

        var onlyGuardianPrefixed = string.IsNullOrWhiteSpace(options.IntegrityMonitoredDirectory);
        var currentFiles = DiscoverMonitoredBinaries(_monitoredDirectory, onlyGuardianPrefixed);
        foreach (var currentFile in currentFiles)
        {
            if (!_baselineHashes.ContainsKey(currentFile))
            {
                anomalies.Add($"Unexpected binary detected in monitored directory: '{Path.GetFileName(currentFile)}'.");
            }
        }

        AclAuditResult? aclAudit = null;
        var dataDirectory = ResolveDataDirectory(options);
        if (!string.IsNullOrWhiteSpace(dataDirectory) && Directory.Exists(dataDirectory))
        {
            aclAudit = _aclInspector.AuditPathAcl(dataDirectory);
            if (aclAudit.Availability == FeatureAvailabilityStatus.Available && !aclAudit.IsRestrictive)
            {
                anomalies.AddRange(aclAudit.Findings);
            }
        }

        var status = anomalies.Count == 0 ? GuardianHealthStatus.Healthy : GuardianHealthStatus.Degraded;
        var availability = anomalies.Count == 0 ? FeatureAvailabilityStatus.Available : FeatureAvailabilityStatus.Degraded;
        var summary = anomalies.Count == 0
            ? $"Self-integrity verified ({verifiedCount}/{_baselineHashes.Count} binary/binaries intact)."
            : $"Self-integrity check detected {anomalies.Count} anomaly/anomalies.";

        if (anomalies.Count > 0)
        {
            _logger.LogWarning(
                "Self-integrity check flagged {Count} anomaly/anomalies in '{Directory}'.",
                anomalies.Count,
                _monitoredDirectory);
        }

        await _healthService.ReportComponentHealthAsync(
            new ComponentHealthReport(
                ComponentName: GuardianServiceConstants.SelfIntegrityComponentName,
                Status: status,
                Summary: summary,
                LastUpdatedUtc: now,
                LastHeartbeatUtc: now,
                Availability: availability,
                Reasons: anomalies),
            cancellationToken).ConfigureAwait(false);

        return new SelfIntegrityReportDto(
            CheckedAtUtc: now,
            Status: status,
            BaselineFileCount: _baselineHashes.Count,
            VerifiedFileCount: verifiedCount,
            Anomalies: anomalies,
            DataDirectoryAclAudit: aclAudit);
    }

    private string ResolveMonitoredDirectory(GuardianServiceOptions options)
    {
        return !string.IsNullOrWhiteSpace(options.IntegrityMonitoredDirectory)
            ? Path.GetFullPath(options.IntegrityMonitoredDirectory)
            : Path.GetFullPath(AppContext.BaseDirectory);
    }

    private string ResolveDataDirectory(GuardianServiceOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.DataDirectoryOverride))
        {
            return Path.GetFullPath(options.DataDirectoryOverride);
        }

        return _privilegeInspector.GetStandardPaths().DataDirectory;
    }

    private static IReadOnlyList<string> DiscoverMonitoredBinaries(string directory, bool onlyGuardianPrefixed)
    {
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
        {
            return [];
        }

        var patternPrefix = onlyGuardianPrefixed ? "Guardian" : string.Empty;
        var dllFiles = Directory.EnumerateFiles(directory, $"{patternPrefix}*.dll", SearchOption.TopDirectoryOnly);
        var exeFiles = Directory.EnumerateFiles(directory, $"{patternPrefix}*.exe", SearchOption.TopDirectoryOnly);

        return dllFiles
            .Concat(exeFiles)
            .Select(Path.GetFullPath)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
