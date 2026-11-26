namespace Guardian.Contracts.System;

/// <summary>
/// Catégorie d'un événement système ou comportemental observé par Guardian.
/// </summary>
public enum SystemEventCategory
{
    /// <summary>
    /// Création ou arrêt de processus.
    /// </summary>
    ProcessLifecycle = 0,

    /// <summary>
    /// Modification observée sur une clé de registre surveillée.
    /// </summary>
    RegistryModification = 1,

    /// <summary>
    /// Changement sur un point de persistance ou de démarrage.
    /// </summary>
    PersistenceChange = 2,

    /// <summary>
    /// Rafale inhabituelle d'opérations sur des fichiers.
    /// </summary>
    FileBurstAnomaly = 3,

    /// <summary>
    /// Montage ou événement lié à un périphérique amovible USB.
    /// </summary>
    UsbDeviceEvent = 4,

    /// <summary>
    /// Signal défensif d'accès interprocessus ou d'injection suspecte.
    /// </summary>
    InterProcessAccess = 5,

    /// <summary>
    /// Changement détecté dans la posture de sécurité native Windows.
    /// </summary>
    SecurityPostureChange = 6,

    /// <summary>
    /// Événement lié à l'auto-intégrité des composants Guardian.
    /// </summary>
    SelfIntegrity = 7
}
