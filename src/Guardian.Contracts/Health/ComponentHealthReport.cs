using Guardian.Contracts.Common;

namespace Guardian.Contracts.Health;

/// <summary>
/// Décrit l'état de santé vérifiable d'un composant individuel de Guardian.
/// </summary>
/// <param name="ComponentName">Nom canonique du composant (ex. <c>Guardian.Service.Host</c>).</param>
/// <param name="Status">État de santé courant du composant.</param>
/// <param name="Summary">Résumé lisible de l'état constaté.</param>
/// <param name="LastUpdatedUtc">Horodatage UTC de la dernière mise à jour d'état.</param>
/// <param name="LastHeartbeatUtc">Horodatage UTC du dernier heartbeat émis par le composant, si applicable.</param>
/// <param name="Availability">Niveau de disponibilité réel selon l'environnement et les privilèges.</param>
/// <param name="Reasons">Liste explicite des raisons expliquant un état dégradé, arrêté ou obsolète.</param>
/// <param name="RequiredPrivilege">Privilège minimal requis lorsque la disponibilité est restreinte.</param>
public sealed record ComponentHealthReport(
    string ComponentName,
    GuardianHealthStatus Status,
    string Summary,
    DateTimeOffset LastUpdatedUtc,
    DateTimeOffset? LastHeartbeatUtc,
    FeatureAvailabilityStatus Availability,
    IReadOnlyList<string> Reasons,
    string? RequiredPrivilege = null);
