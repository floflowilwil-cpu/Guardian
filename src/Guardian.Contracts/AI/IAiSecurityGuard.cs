using Guardian.Contracts.AI.Models;

namespace Guardian.Contracts.AI;

/// <summary>
/// Contrat du bouclier de sécurité protégeant les modèles d'IA contre les attaques adversariales :
/// prompt injection, empoisonnement des données (data poisoning), entrées adversariales (evasion),
/// extraction abusive (model theft/probing) et tentatives de contournement des garde-fous (jailbreak).
/// </summary>
public interface IAiSecurityGuard
{
    /// <summary>
    /// Inspecte un texte utilisateur ou une métadonnée textuelle pour détecter les injections de prompt et jailbreaks.
    /// </summary>
    Task<AiSecurityEvaluation> InspectTextAsync(
        string input, 
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Inspecte un vecteur de caractéristiques pour détecter des manipulations adversariales (padding artificiel, manipulation d'entropie).
    /// </summary>
    Task<AiSecurityEvaluation> InspectFeaturesAsync(
        FileFeatureVector features, 
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Détecte les tentatives d'extraction abusive du modèle (taux élevé de requêtes à la frontière de décision).
    /// </summary>
    Task<bool> TrackAndDetectExtractionAttemptAsync(
        string clientId, 
        double modelProbability, 
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Valide un échantillon soumis au pipeline d'apprentissage continu pour prévenir l'empoisonnement des modèles.
    /// </summary>
    Task<bool> ValidateTrainingSampleIntegrityAsync(
        FileFeatureVector sample, 
        ThreatVerdict declaredLabel, 
        CancellationToken cancellationToken = default);
}
