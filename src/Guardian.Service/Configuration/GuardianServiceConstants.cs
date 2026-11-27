namespace Guardian.Service.Configuration;

/// <summary>
/// Noms canoniques des composants et paramètres du service Windows Guardian.
/// </summary>
public static class GuardianServiceConstants
{
    /// <summary>
    /// Nom enregistré du service dans le Service Control Manager Windows.
    /// </summary>
    public const string ServiceName = "GuardianService";

    /// <summary>
    /// Nom de la section de configuration dans <c>appsettings.json</c>.
    /// </summary>
    public const string ConfigurationSectionName = "GuardianService";

    /// <summary>
    /// Nom canonique du composant hôte principal du service.
    /// </summary>
    public const string HostComponentName = "Guardian.Service.Host";

    /// <summary>
    /// Nom canonique du composant watchdog du service.
    /// </summary>
    public const string WatchdogComponentName = "Guardian.Service.Watchdog";

    /// <summary>
    /// Nom canonique du serveur IPC Named Pipes local.
    /// </summary>
    public const string IpcComponentName = "Guardian.Service.Ipc";

    /// <summary>
    /// Nom canonique du moniteur d'auto-intégrité du service.
    /// </summary>
    public const string SelfIntegrityComponentName = "Guardian.Service.SelfIntegrity";

    /// <summary>
    /// Nom canonique du moteur d'analyse de fichiers hébergé par le service.
    /// </summary>
    public const string ScannerComponentName = "Guardian.Scanner";

    /// <summary>
    /// Nom canonique du sous-système d'intelligence artificielle hébergé par le service.
    /// </summary>
    public const string AiComponentName = "Guardian.AI";
}
