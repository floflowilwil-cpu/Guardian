using Guardian.Contracts.Common;
using Guardian.Contracts.Health;
using Guardian.Service.Configuration;
using Guardian.Service.Health;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Guardian.Service.Watchdog;

/// <summary>
/// Service d'arrière-plan surveillant les sous-systèmes du service Guardian et déclenchant des reprises bornées
/// sans dissimulation ni boucle infinie de redémarrage.
/// </summary>
public sealed class GuardianWatchdogService : BackgroundService
{
    private readonly IEnumerable<IMonitoredComponent> _monitoredComponents;
    private readonly WatchdogTracker _tracker;
    private readonly GuardianHealthService _healthService;
    private readonly IOptions<GuardianServiceOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<GuardianWatchdogService> _logger;

    /// <summary>
    /// Initialise le service watchdog du service résident Guardian.
    /// </summary>
    /// <param name="monitoredComponents">Sous-systèmes enregistrés pour la surveillance watchdog.</param>
    /// <param name="tracker">Suivi d'état et disjoncteur anti-boucle.</param>
    /// <param name="healthService">Service d'agrégation de santé Guardian.</param>
    /// <param name="options">Options validées du service.</param>
    /// <param name="timeProvider">Fournisseur d'horloge injecté.</param>
    /// <param name="logger">Journaliseur structuré.</param>
    public GuardianWatchdogService(
        IEnumerable<IMonitoredComponent> monitoredComponents,
        WatchdogTracker tracker,
        GuardianHealthService healthService,
        IOptions<GuardianServiceOptions> options,
        TimeProvider timeProvider,
        ILogger<GuardianWatchdogService> logger)
    {
        _monitoredComponents = monitoredComponents ?? throw new ArgumentNullException(nameof(monitoredComponents));
        _tracker = tracker ?? throw new ArgumentNullException(nameof(tracker));
        _healthService = healthService ?? throw new ArgumentNullException(nameof(healthService));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        _healthService.SetWatchdogSnapshotProvider(_tracker.CaptureSnapshot);

        foreach (var component in _monitoredComponents)
        {
            _tracker.RegisterComponent(component.ComponentName);
        }

        var now = _timeProvider.GetUtcNow();
        await _healthService.ReportComponentHealthAsync(
            new ComponentHealthReport(
                ComponentName: GuardianServiceConstants.WatchdogComponentName,
                Status: GuardianHealthStatus.Healthy,
                Summary: "Guardian watchdog active with bounded restart policy.",
                LastUpdatedUtc: now,
                LastHeartbeatUtc: now,
                Availability: FeatureAvailabilityStatus.Available,
                Reasons: []),
            cancellationToken).ConfigureAwait(false);

        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromSeconds(_options.Value.WatchdogCheckIntervalSeconds);
        using var timer = new PeriodicTimer(interval, _timeProvider);

        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                await RunCheckCycleAsync(stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Arrêt propre demandé.
        }
    }

    /// <summary>
    /// Exécute un cycle complet de vérification des composants surveillés et applique le disjoncteur si nécessaire.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    public async Task RunCheckCycleAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var options = _options.Value;
        var staleThreshold = TimeSpan.FromSeconds(options.HeartbeatStaleThresholdSeconds);
        var openBreakers = new List<string>();

        foreach (var component in _monitoredComponents)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var now = _timeProvider.GetUtcNow();
            var isStale = component.LastHeartbeatUtc.HasValue &&
                          (now - component.LastHeartbeatUtc.Value) > staleThreshold;

            if (component.IsHealthy && !isStale)
            {
                _tracker.UpdateComponentObservation(
                    component.ComponentName,
                    isHealthy: true,
                    component.LastHeartbeatUtc);

                await _healthService.ReportComponentHealthAsync(
                    new ComponentHealthReport(
                        ComponentName: component.ComponentName,
                        Status: GuardianHealthStatus.Healthy,
                        Summary: $"Component '{component.ComponentName}' passed watchdog check.",
                        LastUpdatedUtc: now,
                        LastHeartbeatUtc: component.LastHeartbeatUtc ?? now,
                        Availability: FeatureAvailabilityStatus.Available,
                        Reasons: []),
                    cancellationToken).ConfigureAwait(false);
                continue;
            }

            var failureReason = !component.IsHealthy
                ? $"Component '{component.ComponentName}' reported unhealthy state."
                : $"Component '{component.ComponentName}' heartbeat expired.";

            if (_tracker.TryReserveRestart(component.ComponentName, failureReason, out var reservedState))
            {
                _logger.LogWarning(
                    "Watchdog attempting bounded restart ({Attempt}/{Max}) for {Component}: {Reason}",
                    reservedState.RestartsInCurrentWindow,
                    reservedState.MaxRestartsInWindow,
                    component.ComponentName,
                    failureReason);

                try
                {
                    await component.RestartAsync(cancellationToken).ConfigureAwait(false);

                    var afterRestartNow = _timeProvider.GetUtcNow();
                    if (component.IsHealthy)
                    {
                        _tracker.UpdateComponentObservation(
                            component.ComponentName,
                            isHealthy: true,
                            component.LastHeartbeatUtc ?? afterRestartNow);

                        await _healthService.ReportComponentHealthAsync(
                            new ComponentHealthReport(
                                ComponentName: component.ComponentName,
                                Status: GuardianHealthStatus.Healthy,
                                Summary: $"Component '{component.ComponentName}' recovered after watchdog restart.",
                                LastUpdatedUtc: afterRestartNow,
                                LastHeartbeatUtc: component.LastHeartbeatUtc ?? afterRestartNow,
                                Availability: FeatureAvailabilityStatus.Available,
                                Reasons: []),
                            cancellationToken).ConfigureAwait(false);
                    }
                    else
                    {
                        var postRestartReason = $"Component '{component.ComponentName}' remained unhealthy after restart attempt.";
                        _tracker.UpdateComponentObservation(
                            component.ComponentName,
                            isHealthy: false,
                            component.LastHeartbeatUtc,
                            postRestartReason);

                        await _healthService.ReportComponentHealthAsync(
                            new ComponentHealthReport(
                                ComponentName: component.ComponentName,
                                Status: GuardianHealthStatus.Degraded,
                                Summary: postRestartReason,
                                LastUpdatedUtc: afterRestartNow,
                                LastHeartbeatUtc: component.LastHeartbeatUtc,
                                Availability: FeatureAvailabilityStatus.Degraded,
                                Reasons: [postRestartReason]),
                            cancellationToken).ConfigureAwait(false);
                    }
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    var errorReason = $"Watchdog restart failed for '{component.ComponentName}': {ex.Message}";
                    _logger.LogError(ex, "Watchdog restart threw an exception for {Component}.", component.ComponentName);

                    _tracker.UpdateComponentObservation(
                        component.ComponentName,
                        isHealthy: false,
                        component.LastHeartbeatUtc,
                        errorReason);

                    await _healthService.ReportComponentHealthAsync(
                        new ComponentHealthReport(
                            ComponentName: component.ComponentName,
                            Status: GuardianHealthStatus.Degraded,
                            Summary: errorReason,
                            LastUpdatedUtc: _timeProvider.GetUtcNow(),
                            LastHeartbeatUtc: component.LastHeartbeatUtc,
                            Availability: FeatureAvailabilityStatus.Degraded,
                            Reasons: [errorReason]),
                        cancellationToken).ConfigureAwait(false);
                }
            }
            else
            {
                var breakerReason =
                    $"Watchdog circuit breaker open for '{component.ComponentName}' after {reservedState.RestartsInCurrentWindow}/{reservedState.MaxRestartsInWindow} restart(s): {failureReason}";

                openBreakers.Add(breakerReason);
                _logger.LogCritical(
                    "Watchdog circuit breaker OPEN for {Component} ({Restarts}/{Max}). Manual intervention or diagnostics required.",
                    component.ComponentName,
                    reservedState.RestartsInCurrentWindow,
                    reservedState.MaxRestartsInWindow);

                await _healthService.ReportComponentHealthAsync(
                    new ComponentHealthReport(
                        ComponentName: component.ComponentName,
                        Status: GuardianHealthStatus.Degraded,
                        Summary: breakerReason,
                        LastUpdatedUtc: now,
                        LastHeartbeatUtc: component.LastHeartbeatUtc,
                        Availability: FeatureAvailabilityStatus.Degraded,
                        Reasons: [breakerReason]),
                    cancellationToken).ConfigureAwait(false);
            }
        }

        var checkNow = _timeProvider.GetUtcNow();
        var watchdogDegraded = openBreakers.Count > 0;
        await _healthService.ReportComponentHealthAsync(
            new ComponentHealthReport(
                ComponentName: GuardianServiceConstants.WatchdogComponentName,
                Status: watchdogDegraded ? GuardianHealthStatus.Degraded : GuardianHealthStatus.Healthy,
                Summary: watchdogDegraded
                    ? $"Watchdog detected {openBreakers.Count} component(s) with open circuit breaker."
                    : "Guardian watchdog active and all monitored components are within bounds.",
                LastUpdatedUtc: checkNow,
                LastHeartbeatUtc: checkNow,
                Availability: watchdogDegraded ? FeatureAvailabilityStatus.Degraded : FeatureAvailabilityStatus.Available,
                Reasons: openBreakers),
            cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        await base.StopAsync(cancellationToken).ConfigureAwait(false);

        var now = _timeProvider.GetUtcNow();
        await _healthService.ReportComponentHealthAsync(
            new ComponentHealthReport(
                ComponentName: GuardianServiceConstants.WatchdogComponentName,
                Status: GuardianHealthStatus.Stopped,
                Summary: "Guardian watchdog stopped cleanly.",
                LastUpdatedUtc: now,
                LastHeartbeatUtc: now,
                Availability: FeatureAvailabilityStatus.Unavailable,
                Reasons: ["Watchdog service stopped."]),
            cancellationToken).ConfigureAwait(false);
    }
}
