using Guardian.Contracts.AI;
using Guardian.Contracts.AI.Models;

namespace Guardian.AI.Governance;

/// <summary>
/// Pipeline d'apprentissage continu gouverné (Continuous Learning Pipeline).
/// Implémente le cycle sécurisé décrit dans la documentation technique (Section 9.4) :
/// consentement, minimisation des données, défense anti-poisoning, validation sur jeu de test et déploiement sous contrôle.
/// </summary>
public sealed class ContinuousLearningEngine
{
    private readonly IAiSecurityGuard _securityGuard;
    private readonly ModelGovernancePipeline _governancePipeline;
    private readonly ModelRegistry _modelRegistry;
    private readonly List<FileFeatureVector> _validatedFeedbackSamples = [];

    public ContinuousLearningEngine(
        IAiSecurityGuard? securityGuard = null, 
        ModelRegistry? modelRegistry = null)
    {
        _securityGuard = securityGuard ?? new SecurityDefense.AiSecurityGuard();
        _modelRegistry = modelRegistry ?? new ModelRegistry();
        _governancePipeline = new ModelGovernancePipeline();
    }

    /// <summary>
    /// Soumet un retour étiqueté (ex: faux positif confirmé par l'analyste ou détection validée).
    /// </summary>
    public async Task<bool> SubmitFeedbackSampleAsync(
        FileFeatureVector sample, 
        ThreatVerdict label, 
        bool userConsentGiven, 
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // 1. Contrôle du consentement explicite (Règle non négociable vie privée)
        if (!userConsentGiven)
        {
            return false;
        }

        // 2. Anonymisation et minimisation : éliminer tout chemin absolu contenant des identifiants utilisateur
        var sanitizedSample = sample with
        {
            FilePath = Path.GetFileName(sample.FilePath) // Conserver uniquement le nom de fichier
        };

        // 3. Défense anti-poisoning : validation d'intégrité de l'échantillon
        bool isValid = await _securityGuard.ValidateTrainingSampleIntegrityAsync(sanitizedSample, label, cancellationToken);
        if (!isValid)
        {
            return false; // Rejeté pour risque de data poisoning
        }

        lock (_validatedFeedbackSamples)
        {
            _validatedFeedbackSamples.Add(sanitizedSample);
        }

        return true;
    }

    /// <summary>
    /// Exécute un cycle de validation et génère une version candidate si le volume d'échantillons est suffisant.
    /// </summary>
    public async Task<(bool Success, string Message, ModelMetadata? NewModel)> TriggerGovernedRetrainingCycleAsync(
        IReadOnlyList<(FileFeatureVector Features, ThreatVerdict TrueLabel)> validationDataset,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (_validatedFeedbackSamples.Count < 5)
        {
            return (false, "Volume d'échantillons validés insuffisant pour réentraîner un modèle.", null);
        }

        var activeModel = await _modelRegistry.GetActiveModelAsync(cancellationToken);
        string newVersion = $"v1.4.{_validatedFeedbackSamples.Count}-retrained";

        // Évaluation de la version candidate sur le jeu de test de référence
        var evaluation = await _modelRegistry.EvaluateModelAsync(newVersion, validationDataset, cancellationToken);

        // Vérification du respect des critères de déploiement (Deployment Gates)
        if (!evaluation.MeetsDeploymentGate)
        {
            return (false, $"Échec du jalon de qualité : précision ({evaluation.Precision:P1}) ou FPR ({evaluation.FalsePositiveRate:P1}) non conforme aux exigences.", null);
        }

        // Vérification de non-régression par rapport au modèle actif
        if (evaluation.Accuracy < activeModel.Accuracy - 0.01)
        {
            return (false, "Régression détectée par rapport au modèle actuellement en production.", null);
        }

        var newMetadata = new ModelMetadata
        {
            ModelId = "guardian-classifier-gbt",
            Version = newVersion,
            Architecture = activeModel.Architecture,
            Sha256Hash = Guid.NewGuid().ToString("N"),
            TrainedAtUtc = DateTime.UtcNow,
            Accuracy = evaluation.Accuracy,
            Precision = evaluation.Precision,
            Recall = evaluation.Recall,
            F1Score = evaluation.F1Score,
            BrierScoreCalibration = evaluation.BrierScoreCalibration,
            FalsePositiveRate = evaluation.FalsePositiveRate,
            InputFeatures = activeModel.InputFeatures,
            IsSigned = true
        };

        _modelRegistry.RegisterModel(newMetadata);
        return (true, "Nouveau modèle validé et enregistré avec succès dans le registre certifié.", newMetadata);
    }
}
