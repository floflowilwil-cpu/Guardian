using Guardian.Contracts.AI.Models;

namespace Guardian.Contracts.AI;

/// <summary>
/// Contrat de calcul du score de risque composite calibré et pondéré.
/// Fait la synthèse entre signatures, heuristiques, modèles IA et données contextuelles.
/// </summary>
public interface IRiskScorer
{
    /// <summary>
    /// Calcule le score de risque global (0 à 100) pour une entité donnée en pondérant l'ensemble des sources disponibles.
    /// Fournit l'explication détaillée des facteurs contributeurs.
    /// </summary>
    /// <param name="context">Données contextuelles et scores partiels des moteurs.</param>
    /// <param name="cancellationToken">Jeton d'annulation de l'opération.</param>
    /// <returns>Score de risque calibré, niveau de menace et facteurs explicatifs.</returns>
    Task<RiskScoreResult> CalculateRiskScoreAsync(
        RiskEvaluationContext context, 
        CancellationToken cancellationToken = default);
}
