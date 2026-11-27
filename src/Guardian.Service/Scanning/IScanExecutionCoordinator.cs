using Guardian.Contracts.Ipc;
using Guardian.Contracts.Scanning;

namespace Guardian.Service.Scanning;

/// <summary>
/// Coordonne l'exécution asynchrone des analyses de fichiers (<c>Quick</c>, <c>Full</c>, <c>Custom</c>)
/// hébergées par le service Guardian avec suivi de progression et annulation contrôlée.
/// </summary>
public interface IScanExecutionCoordinator
{
    /// <summary>
    /// Démarre une nouvelle analyse si aucune autre n'est déjà active.
    /// </summary>
    /// <param name="scope">Portée d'analyse demandée (<c>Quick</c>, <c>Full</c> ou <c>Custom</c>).</param>
    /// <param name="customPath">Chemin cible obligatoire pour une analyse personnalisée.</param>
    /// <param name="serviceStoppingToken">Jeton d'arrêt du service hôte.</param>
    /// <returns>Résultat d'acceptation, message explicatif et instantané courant.</returns>
    Task<(bool Accepted, string Message, IpcScanStatusDto Status)> StartScanAsync(
        ScanScope scope,
        string? customPath,
        CancellationToken serviceStoppingToken = default);

    /// <summary>
    /// Retourne l'état courant et le dernier bilan d'analyse connu.
    /// </summary>
    /// <returns>Instantané typé de progression ou de dernier résultat.</returns>
    IpcScanStatusDto GetStatus();

    /// <summary>
    /// Demande l'annulation propre de l'analyse en cours.
    /// </summary>
    /// <returns><see langword="true"/> si une analyse active a reçu l'ordre d'annulation.</returns>
    bool CancelActiveScan();
}
