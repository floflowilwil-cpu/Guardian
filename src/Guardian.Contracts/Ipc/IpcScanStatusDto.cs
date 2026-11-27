using Guardian.Contracts.Scanning;

namespace Guardian.Contracts.Ipc;

/// <summary>
/// État courant de progression et dernier bilan d'analyse exposés via IPC.
/// </summary>
/// <param name="ActiveScanId">Identifiant de l'analyse en cours ou dernière analyse lancée.</param>
/// <param name="IsRunning">Indique si une analyse est actuellement active.</param>
/// <param name="Scope">Portée de l'analyse courante ou récente.</param>
/// <param name="Percent">Pourcentage de progression (0 à 100).</param>
/// <param name="CurrentPath">Chemin en cours d'analyse, le cas échéant.</param>
/// <param name="FilesProcessed">Nombre de fichiers déjà traités.</param>
/// <param name="TotalFiles">Nombre total de fichiers recensés pour cette analyse.</param>
/// <param name="FindingsCount">Nombre de fichiers suspects ou malveillants détectés.</param>
/// <param name="StatusMessage">Message descriptif de l'état de l'analyse.</param>
/// <param name="LastCompletedSummary">Bilan de la dernière analyse terminée, s'il existe.</param>
public sealed record IpcScanStatusDto(
    Guid? ActiveScanId,
    bool IsRunning,
    ScanScope? Scope,
    int Percent,
    string CurrentPath,
    int FilesProcessed,
    int TotalFiles,
    int FindingsCount,
    string StatusMessage,
    ScanSummary? LastCompletedSummary = null);
