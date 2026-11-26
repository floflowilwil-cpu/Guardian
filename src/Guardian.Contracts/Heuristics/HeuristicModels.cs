using Guardian.Contracts.AI.Models;

namespace Guardian.Contracts.Heuristics;

/// <summary>Indice de suspicion relevé par une règle heuristique.</summary>
public sealed record HeuristicFinding
{
    public required string RuleId { get; init; }
    public required string Description { get; init; }

    /// <summary>Contribution au score, entre 0.0 et 1.0.</summary>
    public required double Weight { get; init; }

    public required SignalSeverity Severity { get; init; }
}

/// <summary>Résultat de l'analyse heuristique statique d'un fichier.</summary>
public sealed record HeuristicAnalysisResult
{
    public required string FilePath { get; init; }

    /// <summary>
    /// Score de suspicion entre 0.0 et 1.0, même échelle que
    /// <c>RiskEvaluationContext.HeuristicScore</c>.
    /// </summary>
    public required double Score { get; init; }

    public required IReadOnlyList<HeuristicFinding> Findings { get; init; }
}