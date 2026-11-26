using Guardian.Contracts.AI;
using Guardian.Contracts.AI.Models;

namespace Guardian.AI.Risk;

/// <summary>
/// Moteur de scoring de risque composite (IRiskScorer).
/// Agrège signatures, heuristiques, modèles IA, télémétrie comportementale et réputation.
/// Calibre la probabilité résultante et formule une recommandation d'action conforme à Guardian.Policy.
/// </summary>
public sealed class RiskScoringEngine : IRiskScorer
{
    public const string DefaultVersion = "v1.5.0-risk-engine";

    private readonly ExplainabilityEngine _explainer;
    private readonly ProbabilityCalibrator _calibrator;

    public RiskScoringEngine(
        ExplainabilityEngine? explainer = null, 
        ProbabilityCalibrator? calibrator = null)
    {
        _explainer = explainer ?? new ExplainabilityEngine();
        _calibrator = calibrator ?? new ProbabilityCalibrator();
    }

    /// <inheritdoc />
    public Task<RiskScoreResult> CalculateRiskScoreAsync(
        RiskEvaluationContext context, 
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentException.ThrowIfNullOrWhiteSpace(context.EntityId);
        cancellationToken.ThrowIfCancellationRequested();

        ValidateScore(context.SignatureScore, nameof(context.SignatureScore));
        ValidateScore(context.HeuristicScore, nameof(context.HeuristicScore));
        ValidateScore(context.AiClassifierScore, nameof(context.AiClassifierScore));
        ValidateScore(context.BehavioralScore, nameof(context.BehavioralScore));
        ValidateScore(context.AnomalyScore, nameof(context.AnomalyScore));
        if (context.AssociatedNetworkEventCount < 0 || context.AssociatedProcessEventCount < 0 || context.AssociatedRegistryEventCount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(context), "Les nombres d'événements associés doivent être positifs ou nuls.");
        }

        double totalWeightedScore = 0.0;
        double totalWeights = 0.0;
        int activeSignalsCount = 0;

        // 1. Signature / Hash / Réputation locale (Poids fort si présent)
        if (context.SignatureScore.HasValue)
        {
            double sigWeight = 0.35;
            totalWeightedScore += context.SignatureScore.Value * sigWeight;
            totalWeights += sigWeight;
            if (context.SignatureScore.Value > 0.5) activeSignalsCount++;
        }

        // 2. Score du classifieur fourni par le moteur de détection.
        if (context.AiClassifierScore.HasValue)
        {
            double aiWeight = 0.25;
            totalWeightedScore += context.AiClassifierScore.Value * aiWeight;
            totalWeights += aiWeight;
            if (context.AiClassifierScore.Value > 0.5) activeSignalsCount++;
        }

        // 3. Heuristiques statiques
        if (context.HeuristicScore.HasValue)
        {
            double heurWeight = 0.20;
            totalWeightedScore += context.HeuristicScore.Value * heurWeight;
            totalWeights += heurWeight;
            if (context.HeuristicScore.Value > 0.5) activeSignalsCount++;
        }

        // 4. Analyse comportementale dynamique
        if (context.BehavioralScore.HasValue)
        {
            double behWeight = 0.25;
            totalWeightedScore += context.BehavioralScore.Value * behWeight;
            totalWeights += behWeight;
            if (context.BehavioralScore.Value > 0.5) activeSignalsCount++;
        }

        // 5. Détecteur d'anomalie
        if (context.AnomalyScore.HasValue)
        {
            double anomWeight = 0.15;
            totalWeightedScore += context.AnomalyScore.Value * anomWeight;
            totalWeights += anomWeight;
            if (context.AnomalyScore.Value > 0.6) activeSignalsCount++;
        }

        // Normalisation de base
        double baseProbability = totalWeights > 0.0 ? (totalWeightedScore / totalWeights) : 0.0;

        // Une signature ou un chemin système n'efface jamais des signaux de menace.
        // Ces attributs sont communiqués à la politique pour encadrer la réponse.

        // Corroboration multi-sources (Défense en profondeur : boost si plusieurs moteurs convergent)
        if (activeSignalsCount >= 3)
        {
            baseProbability = Math.Min(1.0, baseProbability * 1.25);
        }

        // Événements réseau/processus associés
        long associatedEventCount = (long)context.AssociatedNetworkEventCount + context.AssociatedProcessEventCount + context.AssociatedRegistryEventCount;
        if (associatedEventCount > 0)
        {
            double activityBoost = Math.Min(0.15, associatedEventCount * 0.03);
            baseProbability = Math.Min(1.0, baseProbability + activityBoost);
        }

        baseProbability = Math.Clamp(baseProbability, 0.0, 1.0);

        // Calibration probabiliste
        double calibratedProbability = _calibrator.Calibrate(baseProbability);

        // Score normalisé sur échelle [0.0, 100.0]
        double score = Math.Round(calibratedProbability * 100.0, 1);

        // Détermination du niveau de risque
        RiskLevel level = score switch
        {
            >= 90.0 => RiskLevel.Critical,
            >= 70.0 => RiskLevel.High,
            >= 40.0 => RiskLevel.Medium,
            >= 20.0 => RiskLevel.Low,
            _ => RiskLevel.Minimal
        };

        // Calcul de confiance
        double evidenceCoverage = totalWeights / 1.20;
        double confidence = Math.Clamp(0.35 + (evidenceCoverage * 0.45) + (activeSignalsCount * 0.05), 0.0, 0.95);

        // Détermination de la recommandation pour Guardian.Policy
        string recommendedAction = totalWeights == 0.0 ? "RequireUserConfirmation" : level switch
        {
            RiskLevel.Critical => context.IsKnownSystemComponent ? "RequireUserConfirmation" : "Quarantine",
            RiskLevel.High => context.IsKnownSystemComponent ? "RequireUserConfirmation" : "Block",
            RiskLevel.Medium => "Warn",
            RiskLevel.Low => "Monitor",
            _ => "Allow"
        };

        // Explications détaillées des facteurs
        var factors = _explainer.ExplainRiskContext(context);

        var caveats = new List<string>
        {
            "Score heuristique pondéré; sa calibration statistique doit être validée sur un corpus représentatif avant tout usage opérationnel.",
            "L'IA formule une recommandation; l'exécution finale est strictement régie par les règles de Guardian.Policy."
        };

        if (totalWeights == 0.0)
        {
            caveats.Add("Aucun score de détection n'a été fourni; le résultat ne constitue pas une évaluation de sécurité.");
        }

        if (context.IsKnownSystemComponent && level >= RiskLevel.High)
        {
            caveats.Add("ATTENTION : Composant système ciblé. Une confirmation humaine est obligatoire pour prévenir toute interruption de l'OS.");
        }

        return Task.FromResult(new RiskScoreResult
        {
            EntityId = context.EntityId,
            Score = score,
            Level = level,
            CalibratedProbability = calibratedProbability,
            Confidence = Math.Round(confidence, 4),
            ContributingFactors = factors,
            RecommendedPolicyAction = recommendedAction,
            ModelVersion = DefaultVersion,
            Caveats = caveats
        });
    }

    private static void ValidateScore(double? score, string parameterName)
    {
        if (score.HasValue && (!double.IsFinite(score.Value) || score.Value < 0.0 || score.Value > 1.0))
        {
            throw new ArgumentOutOfRangeException(parameterName, "Un score fourni doit être fini et compris entre 0 et 1.");
        }
    }
}
