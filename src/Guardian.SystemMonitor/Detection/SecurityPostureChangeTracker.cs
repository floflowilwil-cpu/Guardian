using Guardian.Contracts.Common;
using Guardian.Contracts.System;

namespace Guardian.SystemMonitor.Detection;

/// <summary>
/// Détecteur différentiel des affaiblissements ou restaurations de la posture de sécurité Windows
/// (Defender, Pare-feu, UAC, Secure Boot, TPM, VBS, Credential Guard, protection LSASS).
/// </summary>
public sealed class SecurityPostureChangeTracker
{
    private readonly TimeProvider _timeProvider;
    private readonly object _gate = new();
    private WindowsSecurityPostureDto? _baselinePosture;

    /// <summary>
    /// Initialise le traceur de posture sécurité Windows.
    /// </summary>
    /// <param name="timeProvider">Horloge injectée.</param>
    public SecurityPostureChangeTracker(TimeProvider timeProvider)
    {
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    /// <summary>
    /// Compare l'instantané de posture courant à la référence précédente.
    /// </summary>
    /// <param name="current">Posture courante observée en lecture seule.</param>
    /// <returns>Événements générés (vide lors du premier appel).</returns>
    public IReadOnlyList<SystemSecurityEventDto> EvaluatePosture(WindowsSecurityPostureDto current)
    {
        ArgumentNullException.ThrowIfNull(current);

        var now = _timeProvider.GetUtcNow();

        lock (_gate)
        {
            if (_baselinePosture is null)
            {
                _baselinePosture = current;
                return [];
            }

            var prev = _baselinePosture;
            var events = new List<SystemSecurityEventDto>();

            CompareControl("Defender", isCritical: true, prev.Defender, current.Defender, now, events);
            CompareControl("Firewall", isCritical: true, prev.Firewall, current.Firewall, now, events);
            CompareControl("Uac", isCritical: true, prev.Uac, current.Uac, now, events);
            CompareControl("LsassProtection", isCritical: true, prev.LsassProtection, current.LsassProtection, now, events);
            CompareControl("SecureBoot", isCritical: false, prev.SecureBoot, current.SecureBoot, now, events);
            CompareControl("Tpm", isCritical: false, prev.Tpm, current.Tpm, now, events);
            CompareControl("VirtualizationBasedSecurity", isCritical: false, prev.VirtualizationBasedSecurity, current.VirtualizationBasedSecurity, now, events);
            CompareControl("CredentialGuard", isCritical: false, prev.CredentialGuard, current.CredentialGuard, now, events);

            _baselinePosture = current;
            return events;
        }
    }

    private static void CompareControl(
        string key,
        bool isCritical,
        SecurityControlStatusDto previous,
        SecurityControlStatusDto current,
        DateTimeOffset now,
        List<SystemSecurityEventDto> events)
    {
        var wasEnabled = previous.IsEnabled == true;
        var isEnabled = current.IsEnabled == true;
        var availabilityDegraded = previous.Availability == FeatureAvailabilityStatus.Available
            && current.Availability != FeatureAvailabilityStatus.Available
            && !isEnabled;

        if ((wasEnabled && !isEnabled) || availabilityDegraded)
        {
            events.Add(new SystemSecurityEventDto(
                EventId: Guid.NewGuid(),
                TimestampUtc: now,
                Category: SystemEventCategory.SecurityPostureChange,
                Severity: isCritical ? EventSeverity.High : EventSeverity.Medium,
                Source: "Guardian.SystemMonitor.PostureTracker",
                ProcessId: null,
                ProcessName: null,
                Target: current.ControlName,
                Summary: $"Dégradation ou désactivation détectée pour '{current.ControlName}' : {current.Summary}",
                Metadata: new Dictionary<string, string>
                {
                    ["controlKey"] = key,
                    ["previousEnabled"] = previous.IsEnabled?.ToString() ?? "Unknown",
                    ["currentEnabled"] = current.IsEnabled?.ToString() ?? "Unknown",
                    ["availability"] = current.Availability.ToString()
                }));
        }
        else if (!wasEnabled && isEnabled)
        {
            events.Add(new SystemSecurityEventDto(
                EventId: Guid.NewGuid(),
                TimestampUtc: now,
                Category: SystemEventCategory.SecurityPostureChange,
                Severity: EventSeverity.Info,
                Source: "Guardian.SystemMonitor.PostureTracker",
                ProcessId: null,
                ProcessName: null,
                Target: current.ControlName,
                Summary: $"Contrôle de sécurité Windows réactivé : '{current.ControlName}'.",
                Metadata: new Dictionary<string, string>
                {
                    ["controlKey"] = key,
                    ["currentEnabled"] = "True"
                }));
        }
    }
}
