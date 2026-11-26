namespace Guardian.Contracts.Common;

/// <summary>
/// Niveau de gravité normalisé d'un événement ou signal de sécurité Guardian.
/// </summary>
public enum EventSeverity
{
    /// <summary>
    /// Information opérationnelle sans anomalie suspecte.
    /// </summary>
    Info = 0,

    /// <summary>
    /// Signal faible à corréler avec d'autres indicateurs.
    /// </summary>
    Low = 1,

    /// <summary>
    /// Anomalie modérée justifiant une journalisation et un suivi.
    /// </summary>
    Medium = 2,

    /// <summary>
    /// Signal élevé indiquant un comportement potentiellement dangereux.
    /// </summary>
    High = 3,

    /// <summary>
    /// Signal critique nécessitant une action immédiate selon la politique.
    /// </summary>
    Critical = 4
}
