namespace Guardian.Contracts.Ipc;

/// <summary>
/// Réponse IPC versionnée et structurée retournée par le service Guardian.
/// </summary>
/// <param name="ProtocolVersion">Version du protocole IPC utilisée pour la réponse.</param>
/// <param name="RequestId">Identifiant corrélé à la requête initiale.</param>
/// <param name="Success">Indique si la commande a été exécutée avec succès.</param>
/// <param name="ErrorCode">Code d'erreur normalisé en cas d'échec.</param>
/// <param name="ErrorMessage">Message d'erreur non sensible destiné à l'appelant.</param>
/// <param name="TimestampUtc">Horodatage UTC de production de la réponse.</param>
/// <param name="PayloadJson">Résultat JSON typé en cas de succès, ou <see langword="null"/>.</param>
public sealed record IpcResponse(
    string ProtocolVersion,
    string RequestId,
    bool Success,
    IpcErrorCode ErrorCode,
    string? ErrorMessage,
    DateTimeOffset TimestampUtc,
    string? PayloadJson = null);
