namespace Guardian.Contracts.Ipc;

/// <summary>
/// Codes d'erreur normalisés retournés par le canal IPC local Guardian.
/// </summary>
public enum IpcErrorCode
{
    /// <summary>
    /// Aucune erreur.
    /// </summary>
    None = 0,

    /// <summary>
    /// La version du protocole fournie par le client n'est pas prise en charge.
    /// </summary>
    InvalidProtocolVersion = 1,

    /// <summary>
    /// Le format ou le contenu de la requête est invalide.
    /// </summary>
    InvalidRequest = 2,

    /// <summary>
    /// La taille du message dépasse le plafond autorisé.
    /// </summary>
    PayloadTooLarge = 3,

    /// <summary>
    /// Le client authentifié ne dispose pas des autorisations requises pour cette commande.
    /// </summary>
    Unauthorized = 4,

    /// <summary>
    /// La commande demandée ne figure pas dans la liste blanche typée.
    /// </summary>
    UnknownCommand = 5,

    /// <summary>
    /// Une tentative de rejeu ou d'horodatage expiré a été détectée.
    /// </summary>
    ReplayDetected = 6,

    /// <summary>
    /// L'opération a expiré avant son achèvement.
    /// </summary>
    Timeout = 7,

    /// <summary>
    /// Le service ou un composant requis est actuellement en état dégradé.
    /// </summary>
    ServiceDegraded = 8,

    /// <summary>
    /// Erreur interne non sensible lors du traitement de la requête.
    /// </summary>
    InternalError = 9
}
