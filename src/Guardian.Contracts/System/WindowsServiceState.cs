namespace Guardian.Contracts.System;

/// <summary>
/// État d'exécution courant d'un service Windows.
/// </summary>
public enum WindowsServiceState
{
    /// <summary>
    /// État inconnu ou inaccessible.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// Service arrêté.
    /// </summary>
    Stopped = 1,

    /// <summary>
    /// Service en cours de démarrage.
    /// </summary>
    StartPending = 2,

    /// <summary>
    /// Service en cours d'arrêt.
    /// </summary>
    StopPending = 3,

    /// <summary>
    /// Service en cours d'exécution.
    /// </summary>
    Running = 4,

    /// <summary>
    /// Reprise après pause en cours.
    /// </summary>
    ContinuePending = 5,

    /// <summary>
    /// Mise en pause en cours.
    /// </summary>
    PausePending = 6,

    /// <summary>
    /// Service en pause.
    /// </summary>
    Paused = 7
}
