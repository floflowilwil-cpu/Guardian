namespace Guardian.Contracts.Common;

/// <summary>
/// Indique la disponibilité vérifiable d'une capacité selon les privilèges, l'OS ou l'édition Windows.
/// </summary>
public enum FeatureAvailabilityStatus
{
    /// <summary>
    /// Capacité pleinement disponible sur l'environnement courant.
    /// </summary>
    Available = 0,

    /// <summary>
    /// Capacité disponible partiellement avec limitations explicites.
    /// </summary>
    Degraded = 1,

    /// <summary>
    /// Capacité nécessitant une élévation de privilèges ou un compte de service autorisé.
    /// </summary>
    RequiresElevation = 2,

    /// <summary>
    /// Capacité non prise en charge par l'édition Windows courante.
    /// </summary>
    UnsupportedEdition = 3,

    /// <summary>
    /// Capacité indisponible sur l'hôte ou dans le contexte actuel.
    /// </summary>
    Unavailable = 4
}
