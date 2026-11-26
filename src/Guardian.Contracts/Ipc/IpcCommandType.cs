namespace Guardian.Contracts.Ipc;

/// <summary>
/// Liste blanche stricte des commandes typées acceptées par le serveur IPC du service Guardian.
/// </summary>
/// <remarks>
/// Aucune commande shell générique ni exécution arbitraire n'est autorisée.
/// </remarks>
public enum IpcCommandType
{
    /// <summary>
    /// Commande non initialisée ou invalide, systématiquement rejetée.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// Vérification rapide de disponibilité du serveur IPC.
    /// </summary>
    Ping = 1,

    /// <summary>
    /// Récupère l'instantané global de santé du service et de ses composants.
    /// </summary>
    GetHealth = 2,

    /// <summary>
    /// Récupère l'état de santé d'un composant ciblé par son nom canonique.
    /// </summary>
    GetComponentHealth = 3,

    /// <summary>
    /// Récupère l'instantané courant du watchdog et de ses disjoncteurs.
    /// </summary>
    GetWatchdogStatus = 4,

    /// <summary>
    /// Récupère la posture de sécurité native Windows observée en lecture seule.
    /// </summary>
    GetSecurityPosture = 5,

    /// <summary>
    /// Récupère l'inventaire des processus actifs en lecture seule.
    /// </summary>
    GetProcesses = 6,

    /// <summary>
    /// Récupère l'inventaire des services Windows en lecture seule.
    /// </summary>
    GetServices = 7,

    /// <summary>
    /// Récupère les entrées de démarrage et persistance observables.
    /// </summary>
    GetStartupEntries = 8,

    /// <summary>
    /// Déclenche une vérification à la demande de l'auto-intégrité du service.
    /// </summary>
    RequestSelfIntegrityCheck = 9
}
