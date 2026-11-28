namespace Guardian.Contracts.Sandbox;

/// <summary>
/// Analyse dynamique d'un fichier dans une machine virtuelle jetable et isolée.
/// Une implémentation ne doit JAMAIS exécuter un échantillon sur l'hôte.
/// </summary>
public interface ISandboxOrchestrator
{
    Task<SandboxAvailability> GetAvailabilityAsync(
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Analyse le fichier. Si la sandbox est indisponible, retourne un résultat de statut
    /// <see cref="SandboxRunStatus.Unavailable"/> et un verdict inconclusif, jamais « sain ».
    /// </summary>
    Task<SandboxAnalysisResult> AnalyzeAsync(
        SandboxAnalysisRequest request,
        CancellationToken cancellationToken = default);
}
