using Guardian.Contracts.Common;

namespace Guardian.Contracts.Network;

/// <summary>
/// Connexion réseau observée, associée autant que possible à son processus.
/// </summary>
/// <remarks>
/// Métadonnées uniquement : aucun contenu de communication n'est collecté.
/// </remarks>
/// <param name="ConnectionId">Identifiant unique de l'observation.</param>
/// <param name="ObservedAtUtc">Horodatage UTC de l'observation.</param>
/// <param name="Protocol">Protocole de transport.</param>
/// <param name="Direction">Sens de la connexion.</param>
/// <param name="LocalAddress">Adresse locale sous forme de texte.</param>
/// <param name="LocalPort">Port local.</param>
/// <param name="RemoteAddress">Adresse distante, le cas échéant.</param>
/// <param name="RemotePort">Port distant, le cas échéant.</param>
/// <param name="State">État de la connexion (ex. <c>Established</c>, <c>Listen</c>).</param>
/// <param name="ProcessId">Identifiant du processus propriétaire, si disponible.</param>
/// <param name="ProcessName">Nom du processus propriétaire, si disponible.</param>
/// <param name="ImagePath">Chemin du binaire du processus, si disponible.</param>
/// <param name="IsImageSigned">Indique si le binaire porte une signature valide, ou <see langword="null"/> si non vérifié.</param>
/// <param name="AssociatedDomain">Domaine DNS associé à l'adresse distante, si corrélé.</param>
/// <param name="ProcessAttribution">Disponibilité de l'association connexion-processus (peut exiger une élévation).</param>
public sealed record NetworkConnectionDto(
    Guid ConnectionId,
    DateTimeOffset ObservedAtUtc,
    NetworkProtocol Protocol,
    NetworkDirection Direction,
    string LocalAddress,
    int LocalPort,
    string? RemoteAddress,
    int? RemotePort,
    string State,
    int? ProcessId,
    string? ProcessName,
    string? ImagePath,
    bool? IsImageSigned,
    string? AssociatedDomain,
    FeatureAvailabilityStatus ProcessAttribution);
