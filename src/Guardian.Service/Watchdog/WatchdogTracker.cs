using Guardian.Contracts.Common;
using Guardian.Contracts.Health;
using Guardian.Service.Configuration;
using Microsoft.Extensions.Options;

namespace Guardian.Service.Watchdog;

/// <summary>
/// Suit de manière déterministe les battements et redémarrages des composants surveillés
/// avec disjoncteur anti-boucle sur fenêtre glissante.
/// </summary>
public sealed class WatchdogTracker
{
    private readonly object _gate = new();
    private readonly Dictionary<string, TrackedComponent> _components = new(StringComparer.OrdinalIgnoreCase);
    private readonly IOptions<GuardianServiceOptions> _options;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initialise le suivi du watchdog avec la politique de fenêtre et le fournisseur d'horloge.
    /// </summary>
    /// <param name="options">Options validées du service Guardian.</param>
    /// <param name="timeProvider">Fournisseur d'horloge optionnel (par défaut <see cref="TimeProvider.System"/>).</param>
    public WatchdogTracker(
        IOptions<GuardianServiceOptions> options,
        TimeProvider? timeProvider = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Enregistre un composant à suivre par le watchdog s'il n'existe pas encore.
    /// </summary>
    /// <param name="componentName">Nom canonique du composant.</param>
    public void RegisterComponent(string componentName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(componentName);

        lock (_gate)
        {
            if (!_components.ContainsKey(componentName))
            {
                _components[componentName] = new TrackedComponent(componentName);
            }
        }
    }

    /// <summary>
    /// Met à jour l'état observé d'un composant et purge les redémarrages expirés de la fenêtre glissante.
    /// </summary>
    /// <param name="componentName">Nom canonique du composant.</param>
    /// <param name="isHealthy">Indique si le composant est sain au moment du contrôle.</param>
    /// <param name="lastHeartbeatUtc">Horodatage UTC du dernier heartbeat connu.</param>
    /// <param name="failureReason">Motif éventuel de dégradation.</param>
    public void UpdateComponentObservation(
        string componentName,
        bool isHealthy,
        DateTimeOffset? lastHeartbeatUtc,
        string? failureReason = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(componentName);

        var now = _timeProvider.GetUtcNow();
        var options = _options.Value;
        var window = TimeSpan.FromMinutes(options.WatchdogRestartWindowMinutes);

        lock (_gate)
        {
            var entry = GetOrCreateUnsafe(componentName);
            PruneExpiredRestarts(entry, now, window);
            entry.LastHeartbeatUtc = lastHeartbeatUtc;

            if (isHealthy)
            {
                if (entry.RestartTimestampsUtc.Count < options.WatchdogMaxRestartsInWindow)
                {
                    entry.CircuitBreakerOpen = false;
                }

                entry.Status = entry.CircuitBreakerOpen
                    ? GuardianHealthStatus.Degraded
                    : GuardianHealthStatus.Healthy;

                if (!entry.CircuitBreakerOpen)
                {
                    entry.LastFailureReason = null;
                }
            }
            else
            {
                entry.Status = GuardianHealthStatus.Degraded;
                if (!string.IsNullOrWhiteSpace(failureReason))
                {
                    entry.LastFailureReason = failureReason;
                }
            }
        }
    }

    /// <summary>
    /// Tente de réserver un redémarrage automatique dans la limite autorisée pour la fenêtre courante.
    /// </summary>
    /// <param name="componentName">Nom canonique du composant en défaut.</param>
    /// <param name="failureReason">Motif de la défaillance constatée.</param>
    /// <param name="state">État mis à jour du composant après évaluation du disjoncteur.</param>
    /// <returns><see langword="true"/> si le redémarrage est autorisé ; <see langword="false"/> si le disjoncteur est ouvert.</returns>
    public bool TryReserveRestart(
        string componentName,
        string failureReason,
        out WatchdogComponentStateDto state)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(componentName);
        ArgumentException.ThrowIfNullOrWhiteSpace(failureReason);

        var now = _timeProvider.GetUtcNow();
        var options = _options.Value;
        var window = TimeSpan.FromMinutes(options.WatchdogRestartWindowMinutes);
        var maxRestarts = options.WatchdogMaxRestartsInWindow;

        lock (_gate)
        {
            var entry = GetOrCreateUnsafe(componentName);
            PruneExpiredRestarts(entry, now, window);

            entry.LastFailureReason = failureReason;
            entry.Status = GuardianHealthStatus.Degraded;

            if (entry.RestartTimestampsUtc.Count >= maxRestarts)
            {
                entry.CircuitBreakerOpen = true;
                state = ToDto(entry, maxRestarts);
                return false;
            }

            entry.RestartTimestampsUtc.Enqueue(now);
            entry.CircuitBreakerOpen = false;
            state = ToDto(entry, maxRestarts);
            return true;
        }
    }

    /// <summary>
    /// Capture un instantané cohérent de l'ensemble des composants surveillés par le watchdog.
    /// </summary>
    /// <returns>Instantané complet incluant l'état agrégé du watchdog.</returns>
    public WatchdogSnapshot CaptureSnapshot()
    {
        var now = _timeProvider.GetUtcNow();
        var options = _options.Value;
        var window = TimeSpan.FromMinutes(options.WatchdogRestartWindowMinutes);
        var maxRestarts = options.WatchdogMaxRestartsInWindow;

        lock (_gate)
        {
            var dtos = new List<WatchdogComponentStateDto>(_components.Count);
            var degraded = false;

            foreach (var entry in _components.Values.OrderBy(c => c.ComponentName, StringComparer.OrdinalIgnoreCase))
            {
                PruneExpiredRestarts(entry, now, window);
                if (entry.CircuitBreakerOpen || entry.Status is GuardianHealthStatus.Degraded or GuardianHealthStatus.Stopped)
                {
                    degraded = true;
                }

                dtos.Add(ToDto(entry, maxRestarts));
            }

            return new WatchdogSnapshot(
                CapturedAtUtc: now,
                OverallStatus: degraded ? GuardianHealthStatus.Degraded : GuardianHealthStatus.Healthy,
                Components: dtos);
        }
    }

    private TrackedComponent GetOrCreateUnsafe(string componentName)
    {
        if (!_components.TryGetValue(componentName, out var entry))
        {
            entry = new TrackedComponent(componentName);
            _components[componentName] = entry;
        }

        return entry;
    }

    private static void PruneExpiredRestarts(TrackedComponent entry, DateTimeOffset now, TimeSpan window)
    {
        while (entry.RestartTimestampsUtc.Count > 0 &&
               (now - entry.RestartTimestampsUtc.Peek()) >= window)
        {
            _ = entry.RestartTimestampsUtc.Dequeue();
        }
    }

    private static WatchdogComponentStateDto ToDto(TrackedComponent entry, int maxRestarts)
    {
        return new WatchdogComponentStateDto(
            ComponentName: entry.ComponentName,
            Status: entry.Status,
            LastHeartbeatUtc: entry.LastHeartbeatUtc,
            RestartsInCurrentWindow: entry.RestartTimestampsUtc.Count,
            MaxRestartsInWindow: maxRestarts,
            CircuitBreakerOpen: entry.CircuitBreakerOpen,
            LastFailureReason: entry.LastFailureReason);
    }

    private sealed class TrackedComponent(string componentName)
    {
        public string ComponentName { get; } = componentName;
        public GuardianHealthStatus Status { get; set; } = GuardianHealthStatus.Unknown;
        public DateTimeOffset? LastHeartbeatUtc { get; set; }
        public Queue<DateTimeOffset> RestartTimestampsUtc { get; } = new();
        public bool CircuitBreakerOpen { get; set; }
        public string? LastFailureReason { get; set; }
    }
}
