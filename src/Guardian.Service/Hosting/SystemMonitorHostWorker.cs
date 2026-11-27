using Guardian.Contracts.Common;
using Guardian.Contracts.Health;
using Guardian.Service.Configuration;
using Guardian.Service.Watchdog;
using Guardian.SystemMonitor;
using Guardian.Windows.Environment;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Guardian.Service.Hosting;

/// <summary>
/// Travailleur hébergeant <see cref="SystemMonitorService"/> au sein de l'hôte <c>Guardian.Service</c>
/// tout en exposant son heartbeat au watchdog et à l'agrégateur de santé.
/// </summary>
public sealed class SystemMonitorHostWorker : BackgroundService, IMonitoredComponent
{
    private readonly SystemMonitorService _systemMonitor;
    private readonly IGuardianHealthService _healthService;
    private readonly IWindowsPrivilegeInspector _privilegeInspector;
    private readonly IOptions<GuardianServiceOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<SystemMonitorHostWorker> _logger;
    private readonly SemaphoreSlim _restartGate = new(1, 1);

    private volatile bool _isHealthy;
    private DateTimeOffset? _lastHeartbeatUtc;

    /// <summary>
    /// Initialise le travailleur hôte du moniteur système.
    /// </summary>
    /// <param name="systemMonitor">Instance singleton de <see cref="SystemMonitorService"/>.</param>
    /// <param name="healthService">Service central de santé Guardian.</param>
    /// <param name="privilegeInspector">Inspecteur d'environnement Windows.</param>
    /// <param name="options">Options validées du service.</param>
    /// <param name="timeProvider">Horloge injectée.</param>
    /// <param name="logger">Journaliseur structuré.</param>
    public SystemMonitorHostWorker(
        SystemMonitorService systemMonitor,
        IGuardianHealthService healthService,
        IWindowsPrivilegeInspector privilegeInspector,
        IOptions<GuardianServiceOptions> options,
        TimeProvider timeProvider,
        ILogger<SystemMonitorHostWorker> logger)
    {
        _systemMonitor = systemMonitor ?? throw new ArgumentNullException(nameof(systemMonitor));
        _healthService = healthService ?? throw new ArgumentNullException(nameof(healthService));
        _privilegeInspector = privilegeInspector ?? throw new ArgumentNullException(nameof(privilegeInspector));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public string ComponentName => GuardianServiceConstants.SystemMonitorComponentName;

    /// <inheritdoc />
    public bool IsHealthy => _isHealthy;

    /// <inheritdoc />
    public DateTimeOffset? LastHeartbeatUtc => _lastHeartbeatUtc;

    /// <inheritdoc />
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        await _systemMonitor.StartAsync(cancellationToken).ConfigureAwait(false);

        var now = _timeProvider.GetUtcNow();
        _isHealthy = true;
        _lastHeartbeatUtc = now;

        await PublishHealthAsync(now, isStopping: false, cancellationToken).ConfigureAwait(false);
        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromSeconds(Math.Max(1, _options.Value.HeartbeatIntervalSeconds));
        using var timer = new PeriodicTimer(interval, _timeProvider);

        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                var now = _timeProvider.GetUtcNow();
                _isHealthy = _systemMonitor.IsRunning;
                _lastHeartbeatUtc = now;

                await PublishHealthAsync(now, isStopping: false, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Arrêt propre demandé par l'hôte.
        }
    }

    /// <inheritdoc />
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _isHealthy = false;
        var now = _timeProvider.GetUtcNow();
        _lastHeartbeatUtc = now;

        try
        {
            await _systemMonitor.StopAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "SystemMonitor encountered an error while stopping.");
        }

        await PublishHealthAsync(now, isStopping: true, CancellationToken.None).ConfigureAwait(false);
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task RestartAsync(CancellationToken cancellationToken = default)
    {
        await _restartGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _logger.LogWarning("Restarting SystemMonitor subsystem via watchdog request.");
            await _systemMonitor.StopAsync(cancellationToken).ConfigureAwait(false);
            await _systemMonitor.StartAsync(cancellationToken).ConfigureAwait(false);

            var now = _timeProvider.GetUtcNow();
            _isHealthy = _systemMonitor.IsRunning;
            _lastHeartbeatUtc = now;
            await PublishHealthAsync(now, isStopping: false, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _restartGate.Release();
        }
    }

    /// <inheritdoc />
    public override void Dispose()
    {
        _restartGate.Dispose();
        base.Dispose();
    }

    private Task PublishHealthAsync(
        DateTimeOffset now,
        bool isStopping,
        CancellationToken cancellationToken)
    {
        var env = _privilegeInspector.GetEnvironmentInfo();

        if (isStopping)
        {
            return _healthService.ReportComponentHealthAsync(
                new ComponentHealthReport(
                    ComponentName: ComponentName,
                    Status: GuardianHealthStatus.Stopped,
                    Summary: "SystemMonitor stopped cleanly.",
                    LastUpdatedUtc: now,
                    LastHeartbeatUtc: now,
                    Availability: FeatureAvailabilityStatus.Unavailable,
                    Reasons: ["SystemMonitor host worker stopped."]),
                cancellationToken);
        }

        if (!_systemMonitor.IsRunning || !_isHealthy)
        {
            return _healthService.ReportComponentHealthAsync(
                new ComponentHealthReport(
                    ComponentName: ComponentName,
                    Status: GuardianHealthStatus.Degraded,
                    Summary: "SystemMonitor background loop is not active.",
                    LastUpdatedUtc: now,
                    LastHeartbeatUtc: now,
                    Availability: FeatureAvailabilityStatus.Degraded,
                    Reasons: ["SystemMonitor background polling loop stopped unexpectedly."]),
                cancellationToken);
        }

        var status = env.IsWindows ? GuardianHealthStatus.Healthy : GuardianHealthStatus.Degraded;
        var availability = env.IsWindows ? FeatureAvailabilityStatus.Available : FeatureAvailabilityStatus.Degraded;
        IReadOnlyList<string> reasons = env.IsWindows
            ? []
            : ["SystemMonitor is running in non-Windows degraded mode."];

        var summary = env.IsWindows
            ? $"SystemMonitor active (ETW={_systemMonitor.EtwCapability.Availability}, lastCycle={_systemMonitor.LastObservationUtc?.ToString("O") ?? "initializing"})."
            : "SystemMonitor active in non-Windows degraded mode.";

        return _healthService.ReportComponentHealthAsync(
            new ComponentHealthReport(
                ComponentName: ComponentName,
                Status: status,
                Summary: summary,
                LastUpdatedUtc: now,
                LastHeartbeatUtc: now,
                Availability: availability,
                Reasons: reasons),
            cancellationToken);
    }
}
