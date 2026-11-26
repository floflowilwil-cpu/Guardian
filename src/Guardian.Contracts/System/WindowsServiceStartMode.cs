namespace Guardian.Contracts.System;

/// <summary>
/// Mode de démarrage configuré pour un service Windows.
/// </summary>
public enum WindowsServiceStartMode
{
    /// <summary>
    /// Mode de démarrage inconnu ou inaccessible.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// Pilote chargé par le chargeur d'amorçage système.
    /// </summary>
    Boot = 1,

    /// <summary>
    /// Pilote initialisé au démarrage du noyau.
    /// </summary>
    System = 2,

    /// <summary>
    /// Service démarré automatiquement par le gestionnaire de services.
    /// </summary>
    Automatic = 3,

    /// <summary>
    /// Service démarré manuellement sur demande.
    /// </summary>
    Manual = 4,

    /// <summary>
    /// Service désactivé.
    /// </summary>
    Disabled = 5
}
