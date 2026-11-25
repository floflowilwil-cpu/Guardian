using System.Diagnostics;
using Guardian.Contracts.AI;
using Guardian.Contracts.AI.Models;

namespace Guardian.AI.Health;

/// <summary>
/// Service d'observabilité et de diagnostic de santé du sous-système d'intelligence artificielle.
/// Révèle l'état réel (Healthy, Degraded, Stopped) à destination du service résident et du tableau de bord.
/// </summary>
public sealed class AiHealthService
{
    private readonly IThreatClassifier _classifier;
    private readonly IAnomalyDetector _anomalyDetector;
    private readonly ILocalAiAssistant _assistant;
    private readonly IModelRegistry _modelRegistry;

    public AiHealthService(
        IThreatClassifier classifier,
        IAnomalyDetector anomalyDetector,
        ILocalAiAssistant assistant,
        IModelRegistry modelRegistry)
    {
        _classifier = classifier;
        _anomalyDetector = anomalyDetector;
        _assistant = assistant;
        _modelRegistry = modelRegistry;
    }

    /// <summary>
    /// Exécute un auto-test complet du sous-système IA et produit le rapport de santé.
    /// </summary>
    public async Task<AiHealthStatus> CheckHealthAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var stopwatch = Stopwatch.StartNew();
        bool classifierOk = false;
        bool anomalyOk = false;
        bool assistantOk = false;
        string activeVersion = "unknown";
        string? degradedReason = null;

        try
        {
            var activeModel = await _modelRegistry.GetActiveModelAsync(cancellationToken);
            activeVersion = activeModel.Version;

            // 1. Test du classifieur sur un vecteur synthétique sain
            var testVector = new FileFeatureVector
            {
                FilePath = "health_probe.exe",
                Sha256 = "0000000000000000000000000000000000000000000000000000000000000000",
                FileSizeBytes = 100000,
                ShannonEntropy = 5.2,
                HasPeHeader = true,
                SectionCount = 4,
                ExecutableSectionCount = 1,
                AnomalousSectionNameCount = 0,
                MaxSectionEntropy = 5.5,
                ImportedLibrariesCount = 5,
                ImportedFunctionsCount = 20,
                SuspiciousApiCallCount = 0,
                HasValidDigitalSignature = true,
                HasTlsCallback = false,
                HasResources = true,
                HasDebugInfo = true,
                IsPackedOrObfuscated = false,
                SuspiciousStringRatio = 0.01,
                ByteDistributionVariance = 12000.0
            };

            var classifResult = await _classifier.ClassifyFeaturesAsync(testVector, cancellationToken);
            classifierOk = classifResult.Verdict == ThreatVerdict.Clean;

            // 2. Test du détecteur d'anomalies
            var anomalyResult = await _anomalyDetector.DetectAnomalyAsync(
                new AnomalyEvaluationContext
                {
                    EntityId = "health_probe",
                    FeatureVector = [100000, 5.2, 4, 0, 1.0, 0.0]
                }, 
                cancellationToken);
            anomalyOk = !anomalyResult.IsAnomaly;

            // 3. Test de l'assistant local
            var assistantResult = await _assistant.AskAssistantAsync(
                new AssistantRequest { Query = "Statut système" }, 
                cancellationToken);
            assistantOk = !assistantResult.HasSecurityWarning;
        }
        catch (Exception ex)
        {
            degradedReason = $"Erreur d'auto-test du sous-système IA : {ex.Message}";
        }

        stopwatch.Stop();
        double latency = Math.Round(stopwatch.Elapsed.TotalMilliseconds, 2);

        EngineHealthState state;
        if (classifierOk && anomalyOk && assistantOk)
        {
            state = EngineHealthState.Healthy;
        }
        else if (classifierOk || anomalyOk)
        {
            state = EngineHealthState.Degraded;
            degradedReason ??= "Un ou plusieurs composants secondaires de l'IA sont indisponibles.";
        }
        else
        {
            state = EngineHealthState.Stopped;
            degradedReason ??= "Moteurs d'IA inopérants.";
        }

        return new AiHealthStatus
        {
            State = state,
            ActiveModelVersion = activeVersion,
            ClassifierOperational = classifierOk,
            AnomalyDetectorOperational = anomalyOk,
            AssistantOperational = assistantOk,
            AverageInferenceLatencyMs = latency,
            DegradedReason = degradedReason
        };
    }
}
