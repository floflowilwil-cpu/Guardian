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
    public const string DefaultVersion = "v1.4.0-risk-engine";

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
        cancellationToken.ThrowIfCancellationRequested();

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

        // 2. Modèle d'intelligence artificielle (ML.NET / Tree Ensemble)
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

        // Modificateurs de contexte : Signature numérique et composant système
        if (context.HasValidDigitalSignature)
        {
            baseProbability *= 0.35; // Forte atténuation pour les binaires signés
        }

        if (context.IsKnownSystemComponent)
        {
            baseProbability *= 0.20; // Protection contre les faux positifs système
        }

        // Corroboration multi-sources (Défense en profondeur : boost si plusieurs moteurs convergent)
        if (activeSignalsCount >= 3)
        {
            baseProbability = Math.Min(1.0, baseProbability * 1.25);
        }

        // Événements réseau/processus associés
        if (context.AssociatedNetworkEventCount > 0 || context.AssociatedProcessEventCount > 0)
        {
            double activityBoost = Math.Min(0.15, (context.AssociatedNetworkEventCount + context.AssociatedProcessEventCount) * 0.03);
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
        double confidence = Math.Clamp(0.55 + (activeSignalsCount * 0.1) + (context.HasValidDigitalSignature ? 0.05 : 0.0), 0.5, 0.99);

        // Détermination de la recommandation pour Guardian.Policy
        string recommendedAction = level switch
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
            "Score composite résultant de la pondération de sources multiples.",
            "L'IA formule une recommandation; l'exécution finale est strictement régie par les règles de Guardian.Policy."
        };

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
}
