namespace Guardian.Contracts.Common;

/// <summary>
/// Représente un événement d'audit traçant une opération contrôlée dans Guardian.
/// </summary>
/// <remarks>
/// Conformément aux règles de confidentialité Guardian, aucun mot de passe, secret, clé privée
/// ni donnée de frappe clavier ne doit jamais être inclus dans les propriétés de cet enregistrement.
/// </remarks>
/// <param name="EventId">Identifiant unique de l'événement d'audit.</param>
/// <param name="TimestampUtc">Horodatage UTC de l'opération.</param>
/// <param name="Category">Catégorie fonctionnelle (ex. <c>Service</c>, <c>IPC</c>, <c>Integrity</c>).</param>
/// <param name="Action">Action typée exécutée.</param>
/// <param name="Actor">Identité ou composant ayant déclenché l'action.</param>
/// <param name="Target">Cible logique de l'opération.</param>
/// <param name="Succeeded">Indique si l'opération a réussi.</param>
/// <param name="Details">Complément d'information non sensible, le cas échéant.</param>
public sealed record AuditEventDto(
    Guid EventId,
    DateTimeOffset TimestampUtc,
    string Category,
    string Action,
    string Actor,
    string Target,
    bool Succeeded,
    string? Details = null);
