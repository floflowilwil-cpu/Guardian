using Guardian.Contracts.Common;
using Guardian.Contracts.Health;
using Guardian.Service.Configuration;
using Guardian.Windows.Environment;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Guardian.Service.Hosting;

/// <summary>
/// Travailleur résident principal du service Guardian assurant le démarrage autonome des moteurs,
/// l'émission régulière du heartbeat et la transition explicite vers l'état <c>Stopped</c> lors de l'arrêt.
/// </summary>
public sealed class GuardianCoreHostWorker : BackgroundService
{
    private readonly IGuardianHealthService _healthService;
    private readonly IWindowsPrivilegeInspector _privilegeInspector;
    private readonly IOptions<GuardianServiceOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<GuardianCoreHostWorker> _logger;

    /// <summary>
    /// Initialise le travailleur hôte principal du service Guardian.
    /// </summary>
    /// <param name="healthService">Service d'agrégation de santé.</param>
    /// <param name="privilegeInspector">Inspecteur d'environnement et de privilèges Windows.</param>
    /// <param name="options">Options validées du service.</param>
    /// <param name="timeProvider">Fournisseur d'horloge injecté.</param>
    /// <param name="logger">Journaliseur structuré.</param>
    public GuardianCoreHostWorker(
        IGuardianHealthService healthService,
        IWindowsPrivilegeInspector privilegeInspector,
        IOptions<GuardianServiceOptions> options,
        TimeProvider timeProvider,
        ILogger<GuardianCoreHostWorker> logger)
    {
        _healthService = healthService ?? throw new ArgumentNullException(nameof(healthService));
        _privilegeInspector = privilegeInspector ?? throw new ArgumentNullException(nameof(privilegeInspector));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        var env = _privilegeInspector.GetEnvironmentInfo();

        var status = env.IsWindows ? GuardianHealthStatus.Healthy : GuardianHealthStatus.Degraded;
        var availability = env.IsWindows ? FeatureAvailabilityStatus.Available : FeatureAvailabilityStatus.Degraded;
        IReadOnlyList<string> reasons = env.IsWindows
            ? []
            : ["Guardian host is running on a non-Windows platform."];

        var summary = env.IsWindows
            ? $"Guardian service host active ({env.WindowsEdition}, privilege={env.CurrentPrivilege})."
            : "Guardian service host active in degraded non-Windows mode.";

        _logger.LogInformation(
            "Starting {ServiceName} on {OsVersion} ({Edition}) with privilege {Privilege}.",
            _options.Value.ServiceName,
            env.OsVersion,
            env.WindowsEdition,
            env.CurrentPrivilege);

        await _healthService.ReportComponentHealthAsync(
            new ComponentHealthReport(
                ComponentName: GuardianServiceConstants.HostComponentName,
                Status: status,
                Summary: summary,
                LastUpdatedUtc: now,
                LastHeartbeatUtc: now,
                Availability: availability,
                Reasons: reasons),
            cancellationToken).ConfigureAwait(false);

        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromSeconds(_options.Value.HeartbeatIntervalSeconds);
        using var timer = new PeriodicTimer(interval, _timeProvider);

        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                var now = _timeProvider.GetUtcNow();
                await _healthService.RecordHeartbeatAsync(
                    GuardianServiceConstants.HostComponentName,
                    now,
                    stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Arrêt propre demandé par l'hôte ou le SCM.
        }
    }

    /// <inheritdoc />
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Stopping {ServiceName} cleanly.", _options.Value.ServiceName);

        await base.StopAsync(cancellationToken).ConfigureAwait(false);

        var now = _timeProvider.GetUtcNow();
        await _healthService.ReportComponentHealthAsync(
            new ComponentHealthReport(
                ComponentName: GuardianServiceConstants.HostComponentName,
                Status: GuardianHealthStatus.Stopped,
                Summary: "Guardian service host has stopped cleanly.",
                LastUpdatedUtc: now,
                LastHeartbeatUtc: now,
                Availability: FeatureAvailabilityStatus.Unavailable,
                Reasons: ["Service host stopped."]),
            cancellationToken).ConfigureAwait(false);
    }
}
