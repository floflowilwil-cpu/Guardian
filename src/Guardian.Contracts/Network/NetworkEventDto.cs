using Guardian.Contracts.Common;

namespace Guardian.Contracts.Network;

/// <summary>
/// Événement réseau normalisé : connexion, DNS, TLS, réputation, décision et règle appliquée.
/// </summary>
/// <remarks>
/// Aucune donnée de contenu, aucun mot de passe, aucune clé privée et aucune frappe clavier ne doit être transporté ici.
/// Aucune détection C2 n'est garantie sur la seule base d'un domaine ou d'une adresse : la gravité reflète un faisceau d'indicateurs.
/// </remarks>
/// <param name="EventId">Identifiant unique de l'événement.</param>
/// <param name="TimestampUtc">Horodatage UTC de l'événement.</param>
/// <param name="Kind">Nature de l'événement.</param>
/// <param name="Severity">Gravité normalisée.</param>
/// <param name="Connection">Connexion concernée, le cas échéant.</param>
/// <param name="Dns">Observation DNS associée, le cas échéant.</param>
/// <param name="Tls">Métadonnées TLS associées, le cas échéant.</param>
/// <param name="Reputation">Réputation associée, le cas échéant.</param>
/// <param name="Decision">Décision appliquée après arbitrage de la politique.</param>
/// <param name="AppliedRuleId">Identifiant de la règle de pare-feu appliquée, le cas échéant.</param>
/// <param name="Summary">Explication lisible et non sensible de l'événement.</param>
/// <param name="Metadata">Métadonnées contextuelles non sensibles.</param>
public sealed record NetworkEventDto(
    Guid EventId,
    DateTimeOffset TimestampUtc,
    NetworkEventKind Kind,
    EventSeverity Severity,
    NetworkConnectionDto? Connection,
    DnsObservationDto? Dns,
    TlsMetadataDto? Tls,
    NetworkReputationDto? Reputation,
    NetworkDecision Decision,
    Guid? AppliedRuleId,
    string Summary,
    IReadOnlyDictionary<string, string> Metadata);
