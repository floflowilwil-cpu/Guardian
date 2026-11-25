namespace Guardian.Contracts.System;

/// <summary>
/// Contrat de surveillance et corrélation comportementale temps réel.
/// </summary>
/// <remarks>
/// <para><b>Vie privée :</b> n'observe ni ne journalise aucune frappe clavier ni donnée privée.</para>
/// </remarks>
public interface IBehaviorMonitor
{
    /// <summary>
    /// Événement déclenché lorsqu'un comportement ou indicateur système pertinent est détecté.
    /// </summary>
    event EventHandler<SystemSecurityEventDto>? EventDetected;

    /// <summary>
    /// Démarre l'écoute des événements comportementaux.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    Task StartAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Arrête l'écoute des événements comportementaux.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    Task StopAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Retourne les événements comportementaux récents conservés en mémoire bornée.
    /// </summary>
    /// <param name="maxCount">Nombre maximal d'événements à retourner.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Liste ordonnée des événements récents.</returns>
    Task<IReadOnlyList<SystemSecurityEventDto>> GetRecentEventsAsync(int maxCount = 100, CancellationToken cancellationToken = default);
}
