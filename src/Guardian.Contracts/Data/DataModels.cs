using Guardian.Contracts.AI.Models;
using Guardian.Contracts.Common;

namespace Guardian.Contracts.Data;

/// <summary>
/// État du cycle de vie d'une menace dans le référentiel.
/// </summary>
public enum ThreatStatus
{
    /// <summary>Menace détectée, aucune action finalisée.</summary>
    Detected = 0,

    /// <summary>Menace placée en quarantaine.</summary>
    Quarantined = 1,

    /// <summary>Élément restauré depuis la quarantaine.</summary>
    Restored = 2,

    /// <summary>Détection écartée (faux positif ou exclusion validée).</summary>
    Dismissed = 3,

    /// <summary>Menace traitée et close.</summary>
    Resolved = 4
}

/// <summary>
/// Page de résultats d'une requête paginée.
/// </summary>
/// <typeparam name="T">Type des éléments retournés.</typeparam>
/// <param name="Items">Éléments de la page demandée.</param>
/// <param name="TotalCount">Nombre total d'éléments correspondant au filtre.</param>
public sealed record PagedResult<T>(
    IReadOnlyList<T> Items,
    int TotalCount);

/// <summary>
/// Élément de preuve rattaché à une menace.
/// </summary>
/// <remarks>
/// Ne contient jamais de contenu privé : uniquement des indicateurs techniques et des métadonnées non sensibles.
/// </remarks>
/// <param name="EvidenceId">Identifiant unique de la preuve.</param>
/// <param name="ObservedAtUtc">Horodatage UTC de l'observation.</param>
/// <param name="Kind">Nature de la preuve (ex. <c>Signature</c>, <c>Heuristic</c>, <c>Behavior</c>, <c>Network</c>).</param>
/// <param name="Description">Description lisible et non sensible.</param>
/// <param name="Metadata">Métadonnées contextuelles non sensibles.</param>
public sealed record ThreatEvidenceDto(
    Guid EvidenceId,
    DateTimeOffset ObservedAtUtc,
    string Kind,
    string Description,
    IReadOnlyDictionary<string, string> Metadata);

/// <summary>
/// Menace enregistrée dans le référentiel local.
/// </summary>
/// <param name="ThreatId">Identifiant unique de la menace.</param>
/// <param name="DetectedAtUtc">Horodatage UTC de première détection.</param>
/// <param name="UpdatedAtUtc">Horodatage UTC de dernière mise à jour.</param>
/// <param name="DisplayName">Nom lisible de la menace.</param>
/// <param name="Verdict">Verdict de classification.</param>
/// <param name="RiskScore">Score de risque de 0 à 100.</param>
/// <param name="Status">État dans le cycle de vie.</param>
/// <param name="DetectionSource">Moteur ou module à l'origine de la détection.</param>
/// <param name="FilePath">Chemin du fichier concerné, le cas échéant.</param>
/// <param name="Sha256">Empreinte SHA-256 du fichier, en hexadécimal, le cas échéant.</param>
/// <param name="Evidence">Preuves associées.</param>
public sealed record ThreatRecordDto(
    Guid ThreatId,
    DateTimeOffset DetectedAtUtc,
    DateTimeOffset UpdatedAtUtc,
    string DisplayName,
    ThreatVerdict Verdict,
    int RiskScore,
    ThreatStatus Status,
    string DetectionSource,
    string? FilePath,
    string? Sha256,
    IReadOnlyList<ThreatEvidenceDto> Evidence);

/// <summary>
/// Filtre de recherche de menaces. Les bornes de pagination sont plafonnées par l'implémentation.
/// </summary>
/// <param name="FromUtc">Borne inférieure de détection (incluse), le cas échéant.</param>
/// <param name="ToUtc">Borne supérieure de détection (exclue), le cas échéant.</param>
/// <param name="Status">Filtre sur l'état, le cas échéant.</param>
/// <param name="Verdict">Filtre sur le verdict, le cas échéant.</param>
/// <param name="Skip">Nombre d'éléments à ignorer.</param>
/// <param name="Take">Nombre maximal d'éléments à retourner.</param>
public sealed record ThreatQuery(
    DateTimeOffset? FromUtc = null,
    DateTimeOffset? ToUtc = null,
    ThreatStatus? Status = null,
    ThreatVerdict? Verdict = null,
    int Skip = 0,
    int Take = 100);

/// <summary>
/// Filtre de recherche d'événements (système, réseau ou audit).
/// </summary>
/// <param name="FromUtc">Borne inférieure (incluse), le cas échéant.</param>
/// <param name="ToUtc">Borne supérieure (exclue), le cas échéant.</param>
/// <param name="MinimumSeverity">Gravité minimale, le cas échéant (ignorée pour l'audit).</param>
/// <param name="Skip">Nombre d'éléments à ignorer.</param>
/// <param name="Take">Nombre maximal d'éléments à retourner.</param>
public sealed record EventQuery(
    DateTimeOffset? FromUtc = null,
    DateTimeOffset? ToUtc = null,
    EventSeverity? MinimumSeverity = null,
    int Skip = 0,
    int Take = 100);

/// <summary>
/// Bilan d'une purge de rétention.
/// </summary>
/// <param name="SystemEventsDeleted">Nombre d'événements système supprimés.</param>
/// <param name="NetworkEventsDeleted">Nombre d'événements réseau supprimés.</param>
/// <param name="AuditEventsDeleted">Nombre d'événements d'audit supprimés.</param>
public sealed record RetentionPurgeResult(
    int SystemEventsDeleted,
    int NetworkEventsDeleted,
    int AuditEventsDeleted);
