namespace Guardian.Contracts.Memory;

/// <summary>
/// Contrat d'analyse défensive des métadonnées mémoire et régions exécutables suspectes.
/// </summary>
/// <remarks>
/// <para><b>Vie privée stricte :</b> seules les métadonnées de protection mémoire (ex. <c>VirtualQueryEx</c>) sont consultées ;
/// aucune lecture de contenu privé, mot de passe, jeton ou secret utilisateur n'est autorisée.</para>
/// <para><b>Exclusion explicite :</b> les processus critiques d'identifiants (tel que <c>lsass</c>) doivent être ignorés.</para>
/// </remarks>
public interface IMemoryAnalyzer
{
    /// <summary>
    /// Analyse les métadonnées mémoire d'un processus ciblé.
    /// </summary>
    /// <param name="processId">Identifiant du processus cible.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Rapport d'analyse défensive et statut d'accès réel.</returns>
    Task<MemoryAnalysisReportDto> AnalyzeProcessAsync(int processId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Analyse l'ensemble des processus accessibles en excluant les processus protégés sensibles.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Rapports d'analyse défensive produits pour les processus traités.</returns>
    Task<IReadOnlyList<MemoryAnalysisReportDto>> ScanAllAccessibleProcessesAsync(CancellationToken cancellationToken = default);
}
