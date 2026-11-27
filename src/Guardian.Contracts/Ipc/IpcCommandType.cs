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
    RequestSelfIntegrityCheck = 9,

    /// <summary>
    /// Démarre une analyse antivirus (rapide, complète sur tout le disque ou personnalisée).
    /// </summary>
    StartScan = 10,

    /// <summary>
    /// Récupère la progression en cours et le dernier bilan d'analyse.
    /// </summary>
    GetScanStatus = 11,

    /// <summary>
    /// Demande l'annulation propre de l'analyse en cours.
    /// </summary>
    CancelScan = 12,

    /// <summary>
    /// Récupère les événements comportementaux et système récents collectés par le service.
    /// </summary>
    GetRecentSystemEvents = 13,

    /// <summary>
    /// Exécute une inspection défensive des métadonnées mémoire sans lecture de contenu privé.
    /// </summary>
    RunMemoryAnalysis = 14
}
