using Guardian.Contracts.Common;
using Guardian.Contracts.Network;
using Guardian.Contracts.System;

namespace Guardian.Contracts.Data;

/// <summary>
/// Contrat de persistance des événements système, réseau et d'audit.
/// </summary>
/// <remarks>
/// <para><b>Privilèges :</b> accès réservé aux composants du service ; les clients d'interface passent par l'IPC.</para>
/// <para><b>Vie privée :</b> aucun contenu privé, mot de passe, secret ni frappe clavier n'est conservé ; l'export éventuel est expurgé.</para>
/// <para><b>Audit :</b> les événements d'audit sont en ajout seul. Ils ne sont supprimés que par la purge de rétention, et seulement sur demande explicite.</para>
/// <para><b>Rétention :</b> la durée est configurable ; la purge est périodique et pilotée par l'infrastructure.</para>
/// </remarks>
public interface IEventRepository
{
    /// <summary>
    /// Enregistre un événement système ou comportemental.
    /// </summary>
    /// <param name="systemEvent">Événement à enregistrer.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    Task AppendSystemEventAsync(SystemSecurityEventDto systemEvent, CancellationToken cancellationToken = default);

    /// <summary>
    /// Enregistre un événement réseau.
    /// </summary>
    /// <param name="networkEvent">Événement à enregistrer.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    Task AppendNetworkEventAsync(NetworkEventDto networkEvent, CancellationToken cancellationToken = default);

    /// <summary>
    /// Enregistre un événement d'audit (ajout seul).
    /// </summary>
    /// <param name="auditEvent">Événement à enregistrer.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    Task AppendAuditEventAsync(AuditEventDto auditEvent, CancellationToken cancellationToken = default);

    /// <summary>
    /// Recherche des événements système, du plus récent au plus ancien.
    /// </summary>
    /// <param name="query">Filtre et pagination.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Page d'événements système.</returns>
    Task<PagedResult<SystemSecurityEventDto>> QuerySystemEventsAsync(EventQuery query, CancellationToken cancellationToken = default);

    /// <summary>
    /// Recherche des événements réseau, du plus récent au plus ancien.
    /// </summary>
    /// <param name="query">Filtre et pagination.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Page d'événements réseau.</returns>
    Task<PagedResult<NetworkEventDto>> QueryNetworkEventsAsync(EventQuery query, CancellationToken cancellationToken = default);

    /// <summary>
    /// Recherche des événements d'audit, du plus récent au plus ancien.
    /// </summary>
    /// <param name="query">Filtre et pagination (la gravité minimale est ignorée).</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Page d'événements d'audit.</returns>
    Task<PagedResult<AuditEventDto>> QueryAuditEventsAsync(EventQuery query, CancellationToken cancellationToken = default);

    /// <summary>
    /// Applique la politique de rétention en supprimant les événements plus anciens que la date indiquée.
    /// </summary>
    /// <param name="cutoffUtc">Date limite UTC de rétention.</param>
    /// <param name="includeAudit">Si <see langword="true"/>, purge aussi les événements d'audit ; faux par défaut.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Nombre d'événements supprimés par catégorie.</returns>
    Task<RetentionPurgeResult> PurgeOlderThanAsync(DateTimeOffset cutoffUtc, bool includeAudit = false, CancellationToken cancellationToken = default);
}
