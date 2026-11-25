using Guardian.Contracts.AI.Models;

namespace Guardian.Contracts.AI;

/// <summary>
/// Contrat de détection d'anomalies structurelles et comportementales (e.g. Isolation Forest).
/// </summary>
public interface IAnomalyDetector
{
    /// <summary>
    /// Évalue l'atypicité d'une observation par rapport aux distributions normales apprises.
    /// </summary>
    /// <param name="context">Observation à analyser sous forme vectorielle.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Score d'anomalie [0, 1] et verdict.</returns>
    Task<AnomalyDetectionResult> DetectAnomalyAsync(
        AnomalyEvaluationContext context, 
        CancellationToken cancellationToken = default);
}
