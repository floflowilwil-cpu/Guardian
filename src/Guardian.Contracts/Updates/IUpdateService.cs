namespace Guardian.Contracts.Updates;

/// <summary>
/// Contrat des mises à jour signées des composants Guardian (application, signatures, modèles, règles).
/// </summary>
/// <remarks>
/// <para><b>Chaîne de confiance :</b> manifeste signé, vérification de la signature avant toute installation, contrôle de l'empreinte de chaque composant, validation de la source. Une signature ou un manifeste invalide entraîne un rejet, jamais une installation partielle.</para>
/// <para><b>Anti-downgrade :</b> toute version antérieure à la version installée est rejetée (<see cref="UpdateRejectionReason.DowngradeNotAllowed"/>). Le retour arrière passe uniquement par <see cref="RollbackAsync"/>.</para>
/// <para><b>Atomicité :</b> téléchargement et installation atomiques, avec conservation de la version précédente pour le rollback.</para>
/// <para><b>Privilèges :</b> l'installation exige une autorisation administrateur ; le contrôle de disponibilité reste accessible en lecture.</para>
/// <para><b>Audit :</b> chaque contrôle, installation, rejet et rollback est journalisé via <see cref="Common.AuditEventDto"/> et conservé dans l'historique.</para>
/// </remarks>
public interface IUpdateService
{
    /// <summary>
    /// Retourne les versions installées de chaque composant mis à jour.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Composants avec leur version installée.</returns>
    Task<IReadOnlyList<UpdateComponentInfoDto>> GetInstalledVersionsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Récupère et vérifie le manifeste signé, puis indique les mises à jour disponibles.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Résultat du contrôle ; un manifeste rejeté est exprimé par une erreur de diagnostic.</returns>
    Task<UpdateCheckResultDto> CheckForUpdatesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Télécharge, vérifie puis installe une mise à jour validée par le manifeste signé.
    /// </summary>
    /// <param name="request">Composant et version cible.</param>
    /// <param name="progress">Rapporteur de progression, facultatif.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Résultat final, y compris en cas de rejet ou de retour arrière automatique.</returns>
    Task<UpdateResultDto> InstallUpdateAsync(UpdateInstallRequest request, IProgress<UpdateProgressDto>? progress = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Restaure la version précédente d'un composant.
    /// </summary>
    /// <param name="kind">Famille du composant à restaurer.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Résultat du retour arrière.</returns>
    Task<UpdateResultDto> RollbackAsync(UpdateComponentKind kind, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retourne l'historique des mises à jour, de la plus récente à la plus ancienne.
    /// </summary>
    /// <param name="maxCount">Nombre maximal d'entrées.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Entrées d'historique.</returns>
    Task<IReadOnlyList<UpdateHistoryEntryDto>> GetHistoryAsync(int maxCount = 50, CancellationToken cancellationToken = default);
}
