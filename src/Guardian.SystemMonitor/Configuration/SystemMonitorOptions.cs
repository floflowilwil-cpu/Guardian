namespace Guardian.SystemMonitor.Configuration;

/// <summary>
/// Options typées régissant la surveillance système, la détection comportementale et le suivi mémoire défensif.
/// </summary>
public sealed class SystemMonitorOptions
{
    /// <summary>
    /// Nom de la section de configuration dans <c>appsettings.json</c>.
    /// </summary>
    public const string ConfigurationSectionName = "SystemMonitor";

    /// <summary>
    /// Intervalle entre deux cycles de collecte différentielle (processus, services, registre, posture) en secondes.
    /// </summary>
    public int PollingIntervalSeconds { get; set; } = 5;

    /// <summary>
    /// Intervalle entre deux balayages défensifs des métadonnées mémoire en secondes.
    /// </summary>
    public int MemoryScanIntervalSeconds { get; set; } = 60;

    /// <summary>
    /// Nombre maximal d'événements comportementaux conservés en mémoire bornée.
    /// </summary>
    public int MaxRetainedEvents { get; set; } = 500;

    /// <summary>
    /// Active la détection de rafales d'opérations fichiers sur les répertoires configurés.
    /// </summary>
    public bool EnableFileSystemWatch { get; set; } = true;

    /// <summary>
    /// Liste des répertoires surveillés pour les rafales d'écriture/renommage (aucun contenu de fichier n'est lu).
    /// </summary>
    public List<string> WatchedDirectories { get; set; } = [];

    /// <summary>
    /// Fenêtre glissante d'agrégation des rafales fichiers en secondes.
    /// </summary>
    public int FileBurstWindowSeconds { get; set; } = 10;

    /// <summary>
    /// Seuil d'opérations fichiers dans la fenêtre déclenchant une alerte <c>FileBurstAnomaly</c>.
    /// </summary>
    public int FileBurstThreshold { get; set; } = 25;

    /// <summary>
    /// Délai minimal entre deux alertes de rafale consécutives pour un même répertoire en secondes.
    /// </summary>
    public int FileBurstCooldownSeconds { get; set; } = 30;

    /// <summary>
    /// Active le balayage périodique défensif des métadonnées mémoire via <c>VirtualQueryEx</c>.
    /// </summary>
    public bool EnableMemorySweep { get; set; } = true;

    /// <summary>
    /// Active la surveillance différentielle de la posture de sécurité Windows.
    /// </summary>
    public bool EnablePostureWatch { get; set; } = true;

    /// <summary>
    /// Active la détection des branchements et débranchements de supports amovibles.
    /// </summary>
    public bool EnableRemovableDriveWatch { get; set; } = true;

    /// <summary>
    /// Délai de déduplication des signaux mémoire identiques pour un même processus en minutes.
    /// </summary>
    public int MemoryAlertCooldownMinutes { get; set; } = 5;
}
