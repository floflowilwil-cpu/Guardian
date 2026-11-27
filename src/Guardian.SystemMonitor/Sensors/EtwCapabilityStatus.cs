using Guardian.Contracts.Common;

namespace Guardian.SystemMonitor.Sensors;

/// <summary>
/// État vérifiable de disponibilité de la collecte ETW user-mode selon la plateforme et les privilèges.
/// </summary>
/// <param name="Availability">Statut global de disponibilité ETW (<c>Available</c>, <c>RequiresElevation</c>, <c>Unavailable</c>).</param>
/// <param name="CanSubscribeUserModeProviders">Indique si les sessions ETW standard accessibles en user-mode sont autorisées.</param>
/// <param name="RequiresElevationForFullEtw">Indique si l'élévation administrateur ou LocalSystem est requise pour la collecte ETW complète.</param>
/// <param name="Summary">Explication transparente du mode de fonctionnement et des capteurs de repli actifs.</param>
public sealed record EtwCapabilityStatus(
    FeatureAvailabilityStatus Availability,
    bool CanSubscribeUserModeProviders,
    bool RequiresElevationForFullEtw,
    string Summary);
