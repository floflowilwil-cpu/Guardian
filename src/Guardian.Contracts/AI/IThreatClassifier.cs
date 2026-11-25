using Guardian.Contracts.AI.Models;

namespace Guardian.Contracts.AI;

/// <summary>
/// Contrat principal de classification des menaces par apprentissage automatique et heuristiques statistiques.
/// </summary>
public interface IThreatClassifier
{
    /// <summary>
    /// Évalue un vecteur de caractéristiques extrait d'un fichier et retourne un verdict probabiliste calibré.
    /// </summary>
    /// <param name="features">Vecteur de caractéristiques normalisées du fichier.</param>
    /// <param name="cancellationToken">Jeton d'annulation de l'opération.</param>
    /// <returns>Résultat de classification avec probabilité, verdict et explicabilité.</returns>
    Task<ThreatClassificationResult> ClassifyFeaturesAsync(
        FileFeatureVector features, 
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Extrait les caractéristiques du fichier spécifié et exécute la classification en une passe.
    /// </summary>
    /// <param name="filePath">Chemin d'accès absolu au fichier à classifier.</param>
    /// <param name="cancellationToken">Jeton d'annulation de l'opération.</param>
    /// <returns>Résultat de classification complet.</returns>
    Task<ThreatClassificationResult> ClassifyFileAsync(
        string filePath, 
        CancellationToken cancellationToken = default);
}
