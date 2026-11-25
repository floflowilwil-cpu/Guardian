using System.Diagnostics;
using Guardian.AI.Anomaly;
using Guardian.AI.FeatureExtraction;
using Guardian.AI.Risk;
using Guardian.Contracts.AI;
using Guardian.Contracts.AI.Models;

namespace Guardian.AI.Classification;

/// <summary>
/// Orchestrateur de classification de menaces (IThreatClassifier).
/// Intègre extraction statique, règles heuristiques, anomalie, calibration et explications.
/// </summary>
public sealed class ThreatClassifier : IThreatClassifier
{
    private readonly PeFeatureExtractor _extractor;
    private readonly TreeBasedMalwareClassifier _classifier;
    private readonly ProbabilityCalibrator _calibrator;
    private readonly ExplainabilityEngine _explainer;
    private readonly IsolationForestAnomalyDetector _anomalyDetector;
    private readonly IAiSecurityGuard? _securityGuard;

    // Seuils de décision calibrés
    public const double MaliciousThreshold = 0.70;
    public const double SuspiciousThreshold = 0.40;

    public ThreatClassifier(
        PeFeatureExtractor? extractor = null,
        TreeBasedMalwareClassifier? classifier = null,
        ProbabilityCalibrator? calibrator = null,
        ExplainabilityEngine? explainer = null,
        IsolationForestAnomalyDetector? anomalyDetector = null,
        IAiSecurityGuard? securityGuard = null)
    {
        _extractor = extractor ?? new PeFeatureExtractor();
        _classifier = classifier ?? new TreeBasedMalwareClassifier();
        _calibrator = calibrator ?? new ProbabilityCalibrator();
        _explainer = explainer ?? new ExplainabilityEngine();
        _anomalyDetector = anomalyDetector ?? new IsolationForestAnomalyDetector();
        _securityGuard = securityGuard;
    }

    /// <inheritdoc />
    public async Task<ThreatClassificationResult> ClassifyFeaturesAsync(
        FileFeatureVector features, 
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(features);
        var stopwatch = Stopwatch.StartNew();

        try
        {
            ValidateFeatures(features);
            // 1. Contrôle de sécurité contre les entrées adversariales si le garde est configuré
            if (_securityGuard != null)
            {
                var securityCheck = await _securityGuard.InspectFeaturesAsync(features, cancellationToken);
                if (!securityCheck.IsSafe)
                {
                    return new ThreatClassificationResult
                    {
                        Verdict = ThreatVerdict.Suspicious,
                        Probability = 0.85,
                        CalibratedProbability = 0.88,
                        Confidence = securityCheck.RiskConfidence,
                        AnomalyScore = 0.95,
                        ThreatFamily = "Adversarial.EvasionAttempt",
                        ModelVersion = TreeBasedMalwareClassifier.DefaultModelVersion,
                        LatencyMs = stopwatch.Elapsed.TotalMilliseconds,
                        ContributingFactors =
                        [
                            new ContributingFactor
                            {
                                Name = "Manipulation adversariale détectée",
                                Weight = 0.9,
                                ScoreContribution = 0.85,
                                RawValue = 1.0,
                                Impact = FactorImpact.IncreasesRisk,
                                Explanation = securityCheck.AnalysisDetail
                            }
                        ],
                        Limitations = ["Évaluation biaisée par une altération intentionnelle de la structure du fichier."]
                    };
                }
            }

            // 2. Inférence du modèle ensembliste
            var (rawProb, confidence, _) = _classifier.Predict(features);

            // 3. Calibration probabiliste
            double calibratedProb = _calibrator.Calibrate(rawProb);

            // 4. Calcul du score d'anomalie
            double[] anomalyVector =
            [
                features.FileSizeBytes,
                features.ShannonEntropy,
                features.SectionCount,
                features.SuspiciousApiCallCount,
                features.IsPackedOrObfuscated ? 1.0 : 0.0
            ];

            var anomalyResult = await _anomalyDetector.DetectAnomalyAsync(
                new AnomalyEvaluationContext
                {
                    EntityId = features.Sha256,
                    FeatureVector = anomalyVector
                },
                cancellationToken);

            // 5. Explicabilité : extraction des facteurs déterminants
            var factors = _explainer.ExplainFileFeatures(features, calibratedProb);

            // 6. Détermination du verdict
            ThreatVerdict verdict;
            string? threatFamily = null;

            if (calibratedProb >= MaliciousThreshold)
            {
                verdict = ThreatVerdict.Malicious;
                threatFamily = features.IsPackedOrObfuscated ? "Trojan.PackedHeur" : "Generic.MalwareHeur";
            }
            else if (calibratedProb >= SuspiciousThreshold || anomalyResult.IsAnomaly)
            {
                verdict = ThreatVerdict.Suspicious;
                threatFamily = anomalyResult.IsAnomaly ? "Suspicious.StructuralAnomaly" : "Suspicious.Heuristics";
            }
            else
            {
                verdict = ThreatVerdict.Clean;
            }

            // 7. Limitations et avertissements méthodologiques obligatoires
            var limitations = new List<string>
            {
                "Classification probabiliste locale basée sur des caractéristiques statiques.",
                "Ne remplace pas une analyse dynamique sous sandbox pour les échantillons obfusqués complexes.",
                "Toute décision de remédiation définitive est soumise à la gouvernance de Guardian.Policy."
            };

            stopwatch.Stop();

            return new ThreatClassificationResult
            {
                Verdict = verdict,
                Probability = rawProb,
                CalibratedProbability = calibratedProb,
                Confidence = confidence,
                AnomalyScore = anomalyResult.AnomalyScore,
                ThreatFamily = threatFamily,
                ModelVersion = TreeBasedMalwareClassifier.DefaultModelVersion,
                LatencyMs = Math.Round(stopwatch.Elapsed.TotalMilliseconds, 2),
                ContributingFactors = factors,
                Limitations = limitations
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            stopwatch.Stop();
            return new ThreatClassificationResult
            {
                Verdict = ThreatVerdict.Error,
                Probability = 0.5,
                CalibratedProbability = 0.5,
                Confidence = 0.0,
                AnomalyScore = 0.0,
                ThreatFamily = null,
                ModelVersion = TreeBasedMalwareClassifier.DefaultModelVersion,
                LatencyMs = stopwatch.Elapsed.TotalMilliseconds,
                ContributingFactors = [],
                Limitations = ["L'inférence a échoué; aucun verdict de sécurité fiable n'est disponible."]
            };
        }
    }

    /// <inheritdoc />
    public async Task<ThreatClassificationResult> ClassifyFileAsync(
        string filePath, 
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var features = await _extractor.ExtractAsync(filePath, cancellationToken);
            return await ClassifyFeaturesAsync(features, cancellationToken);
        }
        catch (FileNotFoundException)
        {
            return new ThreatClassificationResult
            {
                Verdict = ThreatVerdict.Error,
                Probability = 0.0,
                CalibratedProbability = 0.0,
                Confidence = 0.0,
                ModelVersion = TreeBasedMalwareClassifier.DefaultModelVersion,
                ContributingFactors = [],
                Limitations = ["Fichier introuvable; aucun verdict de sécurité n'est disponible."]
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception)
        {
            return new ThreatClassificationResult
            {
                Verdict = ThreatVerdict.Error,
                Probability = 0.0,
                CalibratedProbability = 0.0,
                Confidence = 0.0,
                ModelVersion = TreeBasedMalwareClassifier.DefaultModelVersion,
                ContributingFactors = [],
                Limitations = ["L'extraction des caractéristiques a échoué; aucun verdict de sécurité n'est disponible."]
            };
        }
    }

    private static void ValidateFeatures(FileFeatureVector features)
    {
        if (features.FileSizeBytes < 0 || features.SectionCount < 0 || features.ExecutableSectionCount < 0 ||
            features.AnomalousSectionNameCount < 0 || features.ImportedLibrariesCount < 0 ||
            features.ImportedFunctionsCount < 0 || features.SuspiciousApiCallCount < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(features), "Les tailles et compteurs doivent être positifs ou nuls.");
        }

        if (!IsInRange(features.ShannonEntropy, 0.0, 8.0) ||
            !IsInRange(features.MaxSectionEntropy, 0.0, 8.0) ||
            !IsInRange(features.SuspiciousStringRatio, 0.0, 1.0) ||
            !double.IsFinite(features.ByteDistributionVariance) || features.ByteDistributionVariance < 0.0 ||
            features.CustomFeatures.Any(pair => !double.IsFinite(pair.Value)))
        {
            throw new ArgumentOutOfRangeException(nameof(features), "Les caractéristiques numériques doivent être finies et dans leurs plages documentées.");
        }
    }

    private static bool IsInRange(double value, double minimum, double maximum) =>
        double.IsFinite(value) && value >= minimum && value <= maximum;
}
