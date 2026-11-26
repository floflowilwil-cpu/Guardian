namespace Guardian.Contracts.System;

/// <summary>
/// Type de mécanisme de démarrage ou de persistance observé sous Windows.
/// </summary>
public enum PersistenceEntryKind
{
    /// <summary>
    /// Clé de registre <c>Run</c>.
    /// </summary>
    RegistryRun = 0,

    /// <summary>
    /// Clé de registre <c>RunOnce</c>.
    /// </summary>
    RegistryRunOnce = 1,

    /// <summary>
    /// Dossier de démarrage utilisateur ou commun.
    /// </summary>
    StartupFolder = 2,

    /// <summary>
    /// Valeur critique de démarrage <c>Winlogon</c>.
    /// </summary>
    Winlogon = 3,

    /// <summary>
    /// Entrée <c>Debugger</c> sous <c>Image File Execution Options</c>.
    /// </summary>
    ImageFileExecutionOptions = 4,

    /// <summary>
    /// Tâche planifiée Windows.
    /// </summary>
    ScheduledTask = 5,

    /// <summary>
    /// Service Windows à démarrage automatique ou système.
    /// </summary>
    WindowsService = 6
}
