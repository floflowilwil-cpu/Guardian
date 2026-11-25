namespace Guardian.Contracts.Ipc;

/// <summary>
/// Contexte d'identité Windows vérifié côté serveur pour un client connecté au canal IPC.
/// </summary>
/// <param name="IdentityName">Nom du compte Windows authentifié (ex. <c>DOMAIN\User</c>).</param>
/// <param name="SecurityIdentifier">Identifiant de sécurité Windows (SID) du client, si résolu.</param>
/// <param name="ClientProcessId">Identifiant du processus client connecté, si résolu par le système.</param>
/// <param name="IsAdministrator">Indique si l'identité cliente possède les privilèges administrateur locaux.</param>
public sealed record IpcClientContext(
    string IdentityName,
    string? SecurityIdentifier,
    int? ClientProcessId,
    bool IsAdministrator);
