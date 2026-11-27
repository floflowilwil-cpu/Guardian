using Guardian.Contracts.Ipc;

namespace Guardian.Service.Configuration;

/// <summary>
/// Options typées de fonctionnement, surveillance, santé et IPC du service Windows Guardian.
/// </summary>
public sealed class GuardianServiceOptions
{
    /// <summary>
    /// Nom du service Windows enregistré auprès du SCM.
    /// </summary>
    public string ServiceName { get; set; } = GuardianServiceConstants.ServiceName;

    /// <summary>
    /// Délai maximal d'arrêt propre du service en secondes.
    /// </summary>
    public int ShutdownTimeoutSeconds { get; set; } = 15;

    /// <summary>
    /// Intervalle d'émission du heartbeat de l'hôte en secondes.
    /// </summary>
    public int HeartbeatIntervalSeconds { get; set; } = 5;

    /// <summary>
    /// Seuil d'expiration d'un heartbeat en secondes avant basculement vers l'état <c>Degraded</c>.
    /// </summary>
    public int HeartbeatStaleThresholdSeconds { get; set; } = 20;

    /// <summary>
    /// Intervalle de vérification périodique du watchdog en secondes.
    /// </summary>
    public int WatchdogCheckIntervalSeconds { get; set; } = 10;

    /// <summary>
    /// Nombre maximal de redémarrages automatiques autorisés dans la fenêtre glissante.
    /// </summary>
    public int WatchdogMaxRestartsInWindow { get; set; } = 3;

    /// <summary>
    /// Durée de la fenêtre glissante du disjoncteur watchdog en minutes.
    /// </summary>
    public int WatchdogRestartWindowMinutes { get; set; } = 10;

    /// <summary>
    /// Intervalle entre deux vérifications périodiques d'auto-intégrité en minutes.
    /// </summary>
    public int IntegrityCheckIntervalMinutes { get; set; } = 15;

    /// <summary>
    /// Exige que les binaires du service disposent d'une signature Authenticode valide.
    /// </summary>
    public bool RequireSignedBinaries { get; set; }

    /// <summary>
    /// Répertoire surveillé pour l'auto-intégrité (par défaut le dossier d'exécution du service).
    /// </summary>
    public string? IntegrityMonitoredDirectory { get; set; }

    /// <summary>
    /// Répertoire de données de remplacement (utile pour les tests d'intégration).
    /// </summary>
    public string? DataDirectoryOverride { get; set; }

    /// <summary>
    /// Nom du Named Pipe local utilisé par le serveur IPC.
    /// </summary>
    public string IpcPipeName { get; set; } = IpcProtocolConstants.DefaultPipeName;

    /// <summary>
    /// Nombre maximal de connexions IPC simultanées autorisées.
    /// </summary>
    public int IpcMaxConcurrentConnections { get; set; } = 8;

    /// <summary>
    /// Timeout de lecture et de traitement d'une requête IPC en secondes.
    /// </summary>
    public int IpcReadTimeoutSeconds { get; set; } = 10;

    /// <summary>
    /// Taille maximale autorisée d'un message IPC sérialisé en octets.
    /// </summary>
    public int IpcMaxMessageBytes { get; set; } = IpcProtocolConstants.DefaultMaxMessageBytes;

    /// <summary>
    /// Fenêtre de validité temporelle anti-rejeu des requêtes IPC en secondes.
    /// </summary>
    public int IpcReplayWindowSeconds { get; set; } = 60;

    /// <summary>
    /// Autorise l'interface utilisateur locale non élevée à interroger les commandes en lecture seule.
    /// </summary>
    public bool AllowNonAdminInteractiveIpc { get; set; } = true;

    /// <summary>
    /// Liste des composants requis pour que l'état global du service puisse être <c>Healthy</c>.
    /// </summary>
    public List<string> RequiredComponents { get; set; } =
    [
        GuardianServiceConstants.HostComponentName,
        GuardianServiceConstants.WatchdogComponentName,
        GuardianServiceConstants.SelfIntegrityComponentName
    ];
}
