namespace Guardian.Contracts.Ipc;

/// <summary>
/// Contrat de validation, d'autorisation et de routage des requêtes IPC locales.
/// </summary>
/// <remarks>
/// <para><b>Sécurité :</b> valide la version du protocole, l'horodatage, l'anti-rejeu et les droits du client
/// avant d'exécuter une commande typée.</para>
/// </remarks>
public interface IIpcRequestDispatcher
{
    /// <summary>
    /// Valide et traite une requête IPC émise dans un contexte client authentifié.
    /// </summary>
    /// <param name="request">Requête typée reçue du client.</param>
    /// <param name="clientContext">Identité Windows vérifiée du client connecté.</param>
    /// <param name="cancellationToken">Jeton d'annulation et de timeout.</param>
    /// <returns>Réponse IPC structurée.</returns>
    Task<IpcResponse> DispatchAsync(
        IpcRequest request,
        IpcClientContext clientContext,
        CancellationToken cancellationToken = default);
}
