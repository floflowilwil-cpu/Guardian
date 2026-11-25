using Guardian.Contracts.AI.Models;

namespace Guardian.Contracts.AI;

/// <summary>
/// Contrat de gestion de la mémoire locale des indicateurs de compromission et profils d'incidents.
/// Ne stocke aucune donnée privée, mot de passe, frappe clavier ou contenu personnel.
/// </summary>
public interface IThreatMemoryService
{
    /// <summary>
    /// Enregistre un signal de sécurité qualifié dans la mémoire locale à des fins de corrélation temporelle.
    /// </summary>
    Task RecordSignalAsync(SecuritySignal signal, CancellationToken cancellationToken = default);

    /// <summary>
    /// Enregistre un incident consolidé avec son graphe d'attaque.
    /// </summary>
    Task RecordIncidentGraphAsync(ThreatGraph graph, CancellationToken cancellationToken = default);

    /// <summary>
    /// Récupère l'historique récent des signaux associés à une entité (ex: binaire SHA256 ou PID).
    /// </summary>
    Task<IReadOnlyList<SecuritySignal>> GetSignalsForEntityAsync(string entityId, TimeSpan window, CancellationToken cancellationToken = default);

    /// <summary>
    /// Détermine si une entité présente une récurrence suspecte ou correspond à un schéma d'incident connu.
    /// </summary>
    Task<bool> HasRecentSuspiciousHistoryAsync(string entityId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Purge les signaux expirés selon la politique de rétention pour préserver l'espace et la confidentialité.
    /// </summary>
    Task PurgeExpiredSignalsAsync(TimeSpan maxAge, CancellationToken cancellationToken = default);
}
