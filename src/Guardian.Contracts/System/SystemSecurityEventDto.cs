using Guardian.Contracts.Common;

namespace Guardian.Contracts.System;

/// <summary>
/// Événement de sécurité système ou comportemental émis par la surveillance défensive.
/// </summary>
/// <remarks>
/// Aucune frappe clavier, aucun secret utilisateur ni contenu de session privé ne doit être collecté.
/// </remarks>
/// <param name="EventId">Identifiant unique de l'événement.</param>
/// <param name="TimestampUtc">Horodatage UTC de détection.</param>
/// <param name="Category">Catégorie de l'événement.</param>
/// <param name="Severity">Gravité associée à l'indicateur.</param>
/// <param name="Source">Module ou capteur émetteur.</param>
/// <param name="ProcessId">Identifiant du processus concerné, le cas échéant.</param>
/// <param name="ProcessName">Nom du processus concerné, le cas échéant.</param>
/// <param name="Target">Ressource cible (chemin, clé de registre, service).</param>
/// <param name="Summary">Explication lisible de l'événement observé.</param>
/// <param name="Metadata">Métadonnées contextuelles non sensibles.</param>
public sealed record SystemSecurityEventDto(
    Guid EventId,
    DateTimeOffset TimestampUtc,
    SystemEventCategory Category,
    EventSeverity Severity,
    string Source,
    int? ProcessId,
    string? ProcessName,
    string? Target,
    string Summary,
    IReadOnlyDictionary<string, string> Metadata);
