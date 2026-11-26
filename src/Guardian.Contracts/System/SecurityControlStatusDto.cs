using Guardian.Contracts.Common;

namespace Guardian.Contracts.System;

/// <summary>
/// État en lecture seule d'un contrôle de sécurité natif Windows.
/// </summary>
/// <param name="ControlName">Nom du contrôle Windows observé (ex. <c>Microsoft Defender</c>, <c>UAC</c>).</param>
/// <param name="IsEnabled">Indique si le contrôle est actif, ou <see langword="null"/> si indéterminable.</param>
/// <param name="Availability">Statut de disponibilité de l'observation.</param>
/// <param name="Summary">Résumé factuel de l'état observé.</param>
/// <param name="RequiredPrivilege">Privilège requis si la lecture complète est restreinte.</param>
/// <param name="Recommendation">Recommandation de durcissement lorsque le contrôle est affaibli.</param>
public sealed record SecurityControlStatusDto(
    string ControlName,
    bool? IsEnabled,
    FeatureAvailabilityStatus Availability,
    string Summary,
    string? RequiredPrivilege = null,
    string? Recommendation = null);
