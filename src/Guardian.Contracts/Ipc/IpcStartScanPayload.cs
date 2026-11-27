using Guardian.Contracts.Scanning;

namespace Guardian.Contracts.Ipc;

/// <summary>
/// Charge utile typée pour démarrer une analyse de fichiers via le canal IPC local.
/// </summary>
/// <param name="Scope">Portée demandée (<see cref="ScanScope.Quick"/>, <see cref="ScanScope.Full"/> ou <see cref="ScanScope.Custom"/>).</param>
/// <param name="CustomPath">Chemin du fichier ou dossier ciblé, obligatoire lorsque <see cref="Scope"/> vaut <see cref="ScanScope.Custom"/>.</param>
public sealed record IpcStartScanPayload(
    ScanScope Scope,
    string? CustomPath = null);
