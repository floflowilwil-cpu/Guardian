namespace Guardian.Contracts.Heuristics;

/// <summary>
/// Analyse statique et heuristique d'un fichier, sans jamais l'exécuter.
/// </summary>
public interface IHeuristicAnalyzer
{
    Task<HeuristicAnalysisResult> AnalyzeAsync(
        string filePath,
        CancellationToken cancellationToken = default);
}