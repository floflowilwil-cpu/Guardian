namespace Guardian.Contracts.Common;

/// <summary>
/// Représente l'état de santé réel d'un composant ou du service Guardian.
/// </summary>
public enum GuardianHealthStatus
{
    /// <summary>
    /// État indéterminé ou non encore signalé.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// Composant opérationnel et conforme aux contrôles attendus.
    /// </summary>
    Healthy = 1,

    /// <summary>
    /// Composant partiellement disponible, en mode dégradé ou présentant un écart explicite.
    /// </summary>
    Degraded = 2,

    /// <summary>
    /// Composant arrêté ou non démarré.
    /// </summary>
    Stopped = 3,

    /// <summary>
    /// Composant actif mais nécessitant une mise à jour de définitions ou d'état.
    /// </summary>
    OutOfDate = 4
}
