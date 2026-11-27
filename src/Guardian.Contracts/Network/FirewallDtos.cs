using Guardian.Contracts.Common;

namespace Guardian.Contracts.Network;

/// <summary>
/// État d'un profil du pare-feu Windows (domaine, privé, public).
/// </summary>
/// <param name="ProfileName">Nom du profil.</param>
/// <param name="IsEnabled">Indique si le pare-feu est actif sur ce profil.</param>
public sealed record FirewallProfileStateDto(
    string ProfileName,
    bool IsEnabled);

/// <summary>
/// Instantané en lecture seule de l'état du pare-feu Windows.
/// </summary>
/// <param name="ObservedAtUtc">Horodatage UTC de la lecture.</param>
/// <param name="Availability">Disponibilité de l'information (peut exiger une élévation).</param>
/// <param name="Profiles">État de chaque profil.</param>
/// <param name="Recommendations">Recommandations de restauration si une configuration est affaiblie.</param>
public sealed record FirewallStatusDto(
    DateTimeOffset ObservedAtUtc,
    FeatureAvailabilityStatus Availability,
    IReadOnlyList<FirewallProfileStateDto> Profiles,
    IReadOnlyList<string> Recommendations);

/// <summary>
/// Règle de pare-feu gérée par Guardian.
/// </summary>
/// <param name="RuleId">Identifiant unique de la règle.</param>
/// <param name="Name">Nom lisible de la règle.</param>
/// <param name="CreatedAtUtc">Horodatage UTC de création.</param>
/// <param name="ExpiresAtUtc">Horodatage UTC d'expiration ; toute règle temporaire doit en porter un.</param>
/// <param name="Direction">Sens concerné.</param>
/// <param name="Protocol">Protocole concerné.</param>
/// <param name="RemoteAddress">Adresse distante visée, le cas échéant.</param>
/// <param name="RemotePort">Port distant visé, le cas échéant.</param>
/// <param name="ApplicationPath">Chemin de l'application visée, le cas échéant.</param>
public sealed record FirewallRuleDto(
    Guid RuleId,
    string Name,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    NetworkDirection Direction,
    NetworkProtocol Protocol,
    string? RemoteAddress,
    int? RemotePort,
    string? ApplicationPath);

/// <summary>
/// Demande de blocage temporaire. Elle n'est recevable qu'après une décision de politique.
/// </summary>
/// <param name="PolicyDecisionId">Identifiant de la décision de politique qui autorise le blocage (obligatoire).</param>
/// <param name="Direction">Sens à bloquer.</param>
/// <param name="Protocol">Protocole à bloquer.</param>
/// <param name="RemoteAddress">Adresse distante à bloquer, le cas échéant.</param>
/// <param name="RemotePort">Port distant à bloquer, le cas échéant.</param>
/// <param name="ApplicationPath">Application à bloquer, le cas échéant.</param>
/// <param name="Duration">Durée de vie de la règle, strictement positive et bornée par la configuration.</param>
/// <param name="Reason">Motif lisible et non sensible, journalisé avec la règle.</param>
public sealed record TemporaryBlockRequest(
    Guid PolicyDecisionId,
    NetworkDirection Direction,
    NetworkProtocol Protocol,
    string? RemoteAddress,
    int? RemotePort,
    string? ApplicationPath,
    TimeSpan Duration,
    string Reason);

/// <summary>
/// Résultat d'une création ou d'une suppression de règle de pare-feu.
/// </summary>
/// <param name="Succeeded">Indique si l'opération a réussi.</param>
/// <param name="Rule">Règle créée ou supprimée, le cas échéant.</param>
/// <param name="Error">Erreur de diagnostic en cas d'échec ou de refus.</param>
public sealed record FirewallRuleResultDto(
    bool Succeeded,
    FirewallRuleDto? Rule,
    DiagnosticErrorDto? Error);
