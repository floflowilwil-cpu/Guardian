using Guardian.Contracts.Common;
using Guardian.Contracts.Health;
using Guardian.Service.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Guardian.Service.Security;

/// <summary>
/// Travailleur périodique initialisant et contrôlant l'auto-intégrité du service Guardian.
/// </summary>
public sealed class SelfIntegrityWorker : BackgroundService
{
    private readonly ISelfIntegrityMonitor _monitor;
    private readonly IGuardianHealthService _healthService;
    private readonly IOptions<GuardianServiceOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<SelfIntegrityWorker> _logger;
    private DateTimeOffset _lastCheckUtc;

    /// <summary>
    /// Initialise le travailleur périodique d'auto-intégrité.
    /// </summary>
    /// <param name="monitor">Moniteur d'auto-intégrité.</param>
    /// <param name="healthService">Service central de santé Guardian.</param>
    /// <param name="options">Options validées du service.</param>
    /// <param name="timeProvider">Fournisseur d'horloge injecté.</param>
    /// <param name="logger">Journaliseur structuré.</param>
    public SelfIntegrityWorker(
        ISelfIntegrityMonitor monitor,
        IGuardianHealthService healthService,
        IOptions<GuardianServiceOptions> options,
        TimeProvider timeProvider,
        ILogger<SelfIntegrityWorker> logger)
    {
        _monitor = monitor ?? throw new ArgumentNullException(nameof(monitor));
        _healthService = healthService ?? throw new ArgumentNullException(nameof(healthService));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        var initialReport = await _monitor.InitializeBaselineAsync(cancellationToken).ConfigureAwait(false);
        _lastCheckUtc = _timeProvider.GetUtcNow();
        _logger.LogInformation(
            "Self-integrity baseline initialized with {Count} file(s); status={Status}.",
            initialReport.BaselineFileCount,
            initialReport.Status);

        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var heartbeatInterval = TimeSpan.FromSeconds(Math.Max(1, _options.Value.HeartbeatIntervalSeconds));
        var integrityInterval = TimeSpan.FromMinutes(Math.Max(1, _options.Value.IntegrityCheckIntervalMinutes));
        using var timer = new PeriodicTimer(heartbeatInterval, _timeProvider);

        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                var now = _timeProvider.GetUtcNow();
                if (now - _lastCheckUtc >= integrityInterval)
                {
                    await _monitor.VerifyIntegrityAsync(stoppingToken).ConfigureAwait(false);
                    _lastCheckUtc = _timeProvider.GetUtcNow();
                    continue;
                }

                await _healthService
                    .RecordHeartbeatAsync(GuardianServiceConstants.SelfIntegrityComponentName, now, stoppingToken)
                    .ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Arrêt propre demandé.
        }
    }

    /// <inheritdoc />
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken).ConfigureAwait(false);

        var now = _timeProvider.GetUtcNow();
        await _healthService.ReportComponentHealthAsync(
            new ComponentHealthReport(
                ComponentName: GuardianServiceConstants.SelfIntegrityComponentName,
                Status: GuardianHealthStatus.Stopped,
                Summary: "Self-integrity monitor stopped cleanly.",
                LastUpdatedUtc: now,
                LastHeartbeatUtc: now,
                Availability: FeatureAvailabilityStatus.Unavailable,
                Reasons: ["Self-integrity monitor stopped."]),
            cancellationToken).ConfigureAwait(false);
    }
}
