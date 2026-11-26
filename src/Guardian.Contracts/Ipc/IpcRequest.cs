namespace Guardian.Contracts.Ipc;

/// <summary>
/// Requête IPC versionnée et typée envoyée par un client local autorisé.
/// </summary>
/// <param name="ProtocolVersion">Version de protocole attendue (voir <see cref="IpcProtocolConstants.ProtocolVersion"/>).</param>
/// <param name="RequestId">Identifiant unique de requête utilisé pour le suivi et l'anti-rejeu.</param>
/// <param name="Command">Commande typée appartenant à la liste blanche <see cref="IpcCommandType"/>.</param>
/// <param name="TimestampUtc">Horodatage UTC d'émission de la requête.</param>
/// <param name="Nonce">Jeton anti-rejeu optionnel associé à la requête.</param>
/// <param name="PayloadJson">Charge utile JSON typée optionnelle selon la commande.</param>
public sealed record IpcRequest(
    string ProtocolVersion,
    string RequestId,
    IpcCommandType Command,
    DateTimeOffset TimestampUtc,
    string? Nonce = null,
    string? PayloadJson = null);
