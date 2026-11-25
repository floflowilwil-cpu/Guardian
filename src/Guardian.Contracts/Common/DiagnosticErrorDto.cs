namespace Guardian.Contracts.Common;

/// <summary>
/// Représente une erreur de diagnostic structurée et non sensible.
/// </summary>
/// <param name="Code">Code d'erreur stable et exploitable par les journaux et l'interface.</param>
/// <param name="Message">Description lisible de l'anomalie rencontrée.</param>
/// <param name="TimestampUtc">Horodatage UTC de survenue de l'erreur.</param>
/// <param name="IsRecoverable">Indique si le composant peut tenter une reprise automatique.</param>
public sealed record DiagnosticErrorDto(
    string Code,
    string Message,
    DateTimeOffset TimestampUtc,
    bool IsRecoverable = true);
