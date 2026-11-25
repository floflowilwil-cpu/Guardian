using Guardian.Contracts.AI.Models;

namespace Guardian.Contracts.AI;

/// <summary>
/// Contrat de corrélation multi-sources des signaux de sécurité (fichiers, processus, registre, réseau, mémoire).
/// Construit le graphe d'incident et la chronologie forensique.
/// </summary>
public interface ISignalCorrelator
{
    /// <summary>
    /// Corrèle un ensemble de signaux temporels pour construire le graphe de causalité de l'incident.
    /// </summary>
    /// <param name="signals">Signaux élémentaires collectés.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Graphe d'incident reliant les entités et identifiant la cause racine suspectée.</returns>
    Task<ThreatGraph> CorrelateSignalsAsync(
        IEnumerable<SecuritySignal> signals, 
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Génère une timeline ordonnée avec identification des jalons critiques de l'attaque.
    /// </summary>
    /// <param name="graph">Graphe d'incident généré.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Liste chronologique des événements jalons.</returns>
    Task<IReadOnlyList<ThreatTimelineEntry>> GenerateTimelineAsync(
        ThreatGraph graph, 
        CancellationToken cancellationToken = default);
}
