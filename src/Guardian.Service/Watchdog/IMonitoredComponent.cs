namespace Guardian.Service.Watchdog;

/// <summary>
/// Contrat interne représentant un sous-système du service surveillé et relançable par le watchdog.
/// </summary>
public interface IMonitoredComponent
{
    /// <summary>
    /// Nom canonique du composant suivi dans les rapports de santé.
    /// </summary>
    string ComponentName { get; }

    /// <summary>
    /// Indique si le composant s'estime actuellement opérationnel.
    /// </summary>
    bool IsHealthy { get; }

    /// <summary>
    /// Horodatage UTC du dernier battement émis par ce composant.
    /// </summary>
    DateTimeOffset? LastHeartbeatUtc { get; }

    /// <summary>
    /// Tente un redémarrage propre et borné du composant après défaillance.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    Task RestartAsync(CancellationToken cancellationToken = default);
}
