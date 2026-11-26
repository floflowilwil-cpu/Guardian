using Guardian.AI.Classification;
using Guardian.Contracts.AI;
using Guardian.Contracts.AI.Models;

namespace Guardian.AI.Governance;

/// <summary>
/// Registre en mémoire des métadonnées de l'implémentation active.
/// Il ne charge, ne signe ni ne valide actuellement de fichier de modèle.
/// </summary>
public sealed class ModelRegistry : IModelRegistry
{
    private readonly Dictionary<string, ModelMetadata> _registeredModels = new(StringComparer.OrdinalIgnoreCase);
    private readonly ModelGovernancePipeline _governancePipeline = new();
    private readonly IThreatClassifier _classifier;
    private string _activeVersion;

    public ModelRegistry(IThreatClassifier? classifier = null)
    {
        _classifier = classifier ?? new ThreatClassifier();
        
        var active = new ModelMetadata
        {
            ModelId = "guardian-static-rules",
            Version = TreeBasedMalwareClassifier.DefaultModelVersion,
            Architecture = "Règles heuristiques pondérées, non entraînées; paramètres de calibration provisoires",
            Sha256Hash = string.Empty,
            TrainedAtUtc = DateTime.MinValue,
            Accuracy = 0.0,
            Precision = 0.0,
            Recall = 0.0,
            F1Score = 0.0,
            BrierScoreCalibration = 0.0,
            FalsePositiveRate = 0.0,
            InputFeatures =
            [
                "ShannonEntropy", "MaxSectionEntropy", "IsPackedOrObfuscated",
                "AnomalousSectionNameCount", "SuspiciousApiCallCount", "ExecutableSectionCount",
                "SuspiciousStringRatio", "ByteDistributionVariance"
            ],
            IsSigned = false
        };
        _registeredModels[active.Version] = active;
        _activeVersion = active.Version;
    }

    /// <inheritdoc />
    public Task<ModelMetadata> GetActiveModelAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(_registeredModels[_activeVersion]);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<ModelMetadata>> GetAvailableVersionsAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<IReadOnlyList<ModelMetadata>>(_registeredModels.Values.OrderByDescending(m => m.TrainedAtUtc).ToList());
    }

    /// <inheritdoc />
    public async Task<ModelEvaluationReport> EvaluateModelAsync(
        string modelVersion, 
        IReadOnlyList<(FileFeatureVector Features, ThreatVerdict TrueLabel)> testSet, 
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!_registeredModels.ContainsKey(modelVersion))
        {
            throw new ArgumentException("Version inconnue dans le registre.", nameof(modelVersion));
        }

        if (!string.Equals(modelVersion, _activeVersion, StringComparison.OrdinalIgnoreCase))
        {
            throw new NotSupportedException("Seule l'implémentation active peut être évaluée; le chargement de modèles versionnés n'est pas disponible.");
        }

        var predictions = new List<(ThreatClassificationResult Prediction, ThreatVerdict TrueLabel)>();
        double totalLatency = 0.0;

        foreach (var (features, trueLabel) in testSet)
        {
            var result = await _classifier.ClassifyFeaturesAsync(features, cancellationToken);
            predictions.Add((result, trueLabel));
            totalLatency += result.LatencyMs;
        }

        double avgLatency = testSet.Count > 0 ? totalLatency / testSet.Count : 0.0;
        return _governancePipeline.Evaluate("guardian-static-rules", modelVersion, predictions, avgLatency);
    }

    /// <inheritdoc />
    public Task<ModelRollbackResult> RollbackToVersionAsync(
        string targetVersion, 
        string reason, 
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!_registeredModels.ContainsKey(targetVersion))
        {
            return Task.FromResult(new ModelRollbackResult
            {
                Success = false,
                PreviousVersion = _activeVersion,
                ActiveVersion = _activeVersion,
                Reason = $"La version cible '{targetVersion}' n'existe pas dans le registre en mémoire."
            });
        }

        if (string.Equals(targetVersion, _activeVersion, StringComparison.OrdinalIgnoreCase))
        {
            return Task.FromResult(new ModelRollbackResult
            {
                Success = false,
                PreviousVersion = _activeVersion,
                ActiveVersion = _activeVersion,
                Reason = "Aucune version antérieure chargée n'est disponible pour effectuer un rollback."
            });
        }

        string previous = _activeVersion;
        _activeVersion = targetVersion;

        return Task.FromResult(new ModelRollbackResult
        {
            Success = true,
            PreviousVersion = previous,
            ActiveVersion = _activeVersion,
            Reason = $"Rollback réussi vers '{targetVersion}'. Motif : {reason}"
        });
    }

    /// <inheritdoc />
    public Task<bool> VerifyModelIntegrityAsync(string modelVersion, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_registeredModels.TryGetValue(modelVersion, out var metadata))
        {
            return Task.FromResult(metadata.IsSigned && !string.IsNullOrEmpty(metadata.Sha256Hash));
        }

        return Task.FromResult(false);
    }

    /// <summary>
    /// Point d'extension réservé; l'import sécurisé d'une version de modèle n'est pas disponible.
    /// </summary>
    public void RegisterModel(ModelMetadata metadata)
    {
        ArgumentNullException.ThrowIfNull(metadata);
        throw new NotSupportedException("Le chargement et la vérification cryptographique de modèles ne sont pas implémentés.");
    }

}
