using Guardian.AI.Risk;
using Guardian.Contracts.AI.Models;

namespace Guardian.AI.Governance;

/// <summary>
/// Pipeline d'évaluation, métriques et validation de la gouvernance des modèles d'IA.
/// Calcule de manière reproductible la précision, le rappel, le score F1, la calibration (score de Brier)
/// et les taux de faux positifs/négatifs sur les jeux de données de référence.
/// </summary>
public sealed class ModelGovernancePipeline
{
    // Critères stricts de déploiement (Deployment Gates)
    public const double MinimumAccuracy = 0.90;
    public const double MinimumPrecision = 0.88;
    public const double MinimumRecall = 0.88;
    public const double MinimumF1 = 0.88;
    public const double MaximumFalsePositiveRate = 0.03; // Strict : max 3% de faux positifs
    public const double MaximumBrierScore = 0.12;

    /// <summary>
    /// Évalue un modèle sur un jeu de test labellisé et calcule toutes les métriques d'acceptation.
    /// </summary>
    public ModelEvaluationReport Evaluate(
        string modelId,
        string modelVersion,
        IReadOnlyList<(ThreatClassificationResult Prediction, ThreatVerdict TrueLabel)> testResults,
        double averageLatencyMs)
    {
        if (testResults.Count == 0)
        {
            throw new ArgumentException("Le jeu de test ne peut pas être vide.", nameof(testResults));
        }

        int truePositives = 0;
        int falsePositives = 0;
        int trueNegatives = 0;
        int falseNegatives = 0;

        var brierPairs = new List<(double Prob, bool Actual)>();

        foreach (var (prediction, trueLabel) in testResults)
        {
            bool isActualMalicious = trueLabel == ThreatVerdict.Malicious || trueLabel == ThreatVerdict.Suspicious;
            bool isPredictedMalicious = prediction.Verdict == ThreatVerdict.Malicious || prediction.Verdict == ThreatVerdict.Suspicious;

            brierPairs.Add((prediction.CalibratedProbability, isActualMalicious));

            if (isPredictedMalicious && isActualMalicious)
            {
                truePositives++;
            }
            else if (isPredictedMalicious && !isActualMalicious)
            {
                falsePositives++;
            }
            else if (!isPredictedMalicious && !isActualMalicious)
            {
                trueNegatives++;
            }
            else if (!isPredictedMalicious && isActualMalicious)
            {
                falseNegatives++;
            }
        }

        int total = testResults.Count;
        int benignTotal = trueNegatives + falsePositives;
        int maliciousTotal = truePositives + falseNegatives;

        double accuracy = (double)(truePositives + trueNegatives) / total;
        double precision = (truePositives + falsePositives) > 0 ? (double)truePositives / (truePositives + falsePositives) : 1.0;
        double recall = (truePositives + falseNegatives) > 0 ? (double)truePositives / (truePositives + falseNegatives) : 1.0;
        double f1 = (precision + recall) > 0 ? (2.0 * precision * recall) / (precision + recall) : 0.0;
        double fpr = benignTotal > 0 ? (double)falsePositives / benignTotal : 0.0;
        double fnr = maliciousTotal > 0 ? (double)falseNegatives / maliciousTotal : 0.0;
        double brier = ProbabilityCalibrator.CalculateBrierScore(brierPairs);

        bool meetsGate = accuracy >= MinimumAccuracy &&
                         precision >= MinimumPrecision &&
                         recall >= MinimumRecall &&
                         f1 >= MinimumF1 &&
                         fpr <= MaximumFalsePositiveRate &&
                         brier <= MaximumBrierScore;

        return new ModelEvaluationReport
        {
            ModelId = modelId,
            ModelVersion = modelVersion,
            TotalSamples = total,
            BenignSamples = benignTotal,
            MaliciousSamples = maliciousTotal,
            Accuracy = Math.Round(accuracy, 4),
            Precision = Math.Round(precision, 4),
            Recall = Math.Round(recall, 4),
            F1Score = Math.Round(f1, 4),
            BrierScoreCalibration = Math.Round(brier, 4),
            FalsePositiveRate = Math.Round(fpr, 4),
            FalseNegativeRate = Math.Round(fnr, 4),
            AverageLatencyMs = Math.Round(averageLatencyMs, 2),
            MeetsDeploymentGate = meetsGate
        };
    }
}
