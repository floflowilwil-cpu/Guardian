using Guardian.Contracts.AI.Models;

namespace Guardian.Contracts.AI;

/// <summary>
/// Contrat de gouvernance, versionnement, évaluation et rollback des modèles d'IA.
/// </summary>
public interface IModelRegistry
{
    /// <summary>
    /// Récupère les métadonnées du modèle actuellement actif.
    /// </summary>
    Task<ModelMetadata> GetActiveModelAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Liste les versions historiques de modèles disponibles pour un éventuel retour en arrière.
    /// </summary>
    Task<IReadOnlyList<ModelMetadata>> GetAvailableVersionsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Évalue un modèle sur un jeu de validation étiqueté et produit le rapport complet des métriques (Précision, Rappel, F1, Brier, FPR).
    /// </summary>
    Task<ModelEvaluationReport> EvaluateModelAsync(
        string modelVersion, 
        IReadOnlyList<(FileFeatureVector Features, ThreatVerdict TrueLabel)> testSet, 
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Rétablit immédiatement (rollback) une version antérieure certifiée en cas d'anomalie ou de régression détectée.
    /// </summary>
    Task<ModelRollbackResult> RollbackToVersionAsync(
        string targetVersion, 
        string reason, 
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Vérifie l'intégrité cryptographique (SHA-256 et signature) des modèles déployés.
    /// </summary>
    Task<bool> VerifyModelIntegrityAsync(string modelVersion, CancellationToken cancellationToken = default);
}
