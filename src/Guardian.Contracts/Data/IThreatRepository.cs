namespace Guardian.Contracts.Data;

/// <summary>
/// Contrat de persistance des menaces et de leurs preuves.
/// </summary>
/// <remarks>
/// <para><b>Privilèges :</b> accès réservé aux composants du service ; les clients d'interface passent par l'IPC.</para>
/// <para><b>Vie privée :</b> aucun contenu de fichier, mot de passe, secret ou frappe clavier n'est conservé.</para>
/// <para><b>Intégrité :</b> écritures atomiques et schéma versionné par migrations ; un échec de stockage est signalé par exception d'infrastructure, jamais ignoré silencieusement.</para>
/// <para><b>Audit :</b> tout changement d'état d'une menace est journalisé via <see cref="Common.AuditEventDto"/>.</para>
/// </remarks>
public interface IThreatRepository
{
    /// <summary>
    /// Crée ou met à jour une menace et ses preuves.
    /// </summary>
    /// <param name="threat">Menace à enregistrer.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    Task UpsertAsync(ThreatRecordDto threat, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrouve une menace par son identifiant.
    /// </summary>
    /// <param name="threatId">Identifiant de la menace.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>La menace ou <see langword="null"/> si elle n'existe pas.</returns>
    Task<ThreatRecordDto?> GetByIdAsync(Guid threatId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Recherche des menaces selon un filtre paginé, de la plus récente à la plus ancienne.
    /// </summary>
    /// <param name="query">Filtre et pagination.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Page de menaces correspondant au filtre.</returns>
    Task<PagedResult<ThreatRecordDto>> QueryAsync(ThreatQuery query, CancellationToken cancellationToken = default);

    /// <summary>
    /// Change l'état d'une menace.
    /// </summary>
    /// <param name="threatId">Identifiant de la menace.</param>
    /// <param name="newStatus">Nouvel état.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns><see langword="true"/> si la menace existait et a été mise à jour ; sinon <see langword="false"/>.</returns>
    Task<bool> UpdateStatusAsync(Guid threatId, ThreatStatus newStatus, CancellationToken cancellationToken = default);

    /// <summary>
    /// Ajoute une preuve à une menace existante.
    /// </summary>
    /// <param name="threatId">Identifiant de la menace.</param>
    /// <param name="evidence">Preuve à ajouter.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns><see langword="true"/> si la menace existait ; sinon <see langword="false"/>.</returns>
    Task<bool> AddEvidenceAsync(Guid threatId, ThreatEvidenceDto evidence, CancellationToken cancellationToken = default);

    /// <summary>
    /// Supprime les menaces closes (résolues ou écartées) plus anciennes que la date indiquée.
    /// </summary>
    /// <param name="cutoffUtc">Date limite UTC de rétention.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Nombre de menaces supprimées.</returns>
    Task<int> PurgeClosedOlderThanAsync(DateTimeOffset cutoffUtc, CancellationToken cancellationToken = default);
}
