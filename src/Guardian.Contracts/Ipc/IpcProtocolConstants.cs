namespace Guardian.Contracts.Ipc;

/// <summary>
/// Constantes normatives du protocole IPC local authentifié entre l'interface et le service Guardian.
/// </summary>
public static class IpcProtocolConstants
{
    /// <summary>
    /// Version courante du protocole IPC typé.
    /// </summary>
    public const string ProtocolVersion = "1.0";

    /// <summary>
    /// Nom par défaut du Named Pipe local protégé par ACL.
    /// </summary>
    public const string DefaultPipeName = "Guardian.Service.Ipc.v1";

    /// <summary>
    /// Taille maximale par défaut d'un message IPC sérialisé en octets (256 Kio).
    /// </summary>
    public const int DefaultMaxMessageBytes = 256 * 1024;

    /// <summary>
    /// Délai maximal par défaut appliqué à une requête IPC.
    /// </summary>
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(10);
}
