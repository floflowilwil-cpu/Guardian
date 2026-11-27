using Guardian.Contracts.Common;
using Guardian.Windows.Environment;

namespace Guardian.SystemMonitor.Sensors;

/// <summary>
/// Évalue de façon honnête la disponibilité ETW sur l'hôte courant afin d'exposer le niveau de couverture réel.
/// </summary>
public sealed class WindowsEtwCapabilityProbe
{
    private readonly IWindowsPrivilegeInspector _privilegeInspector;

    /// <summary>
    /// Initialise la sonde de capacité ETW.
    /// </summary>
    /// <param name="privilegeInspector">Inspecteur de privilèges et d'OS.</param>
    public WindowsEtwCapabilityProbe(IWindowsPrivilegeInspector privilegeInspector)
    {
        _privilegeInspector = privilegeInspector ?? throw new ArgumentNullException(nameof(privilegeInspector));
    }

    /// <summary>
    /// Inspecte la plateforme et le niveau d'élévation pour déterminer l'accès ETW disponible.
    /// </summary>
    /// <returns>Statut vérifiable de disponibilité ETW.</returns>
    public EtwCapabilityStatus Probe()
    {
        var env = _privilegeInspector.GetEnvironmentInfo();
        if (!env.IsWindows)
        {
            return new EtwCapabilityStatus(
                Availability: FeatureAvailabilityStatus.Unavailable,
                CanSubscribeUserModeProviders: false,
                RequiresElevationForFullEtw: false,
                Summary: "ETW is unavailable on non-Windows platforms.");
        }

        if (env.IsElevated)
        {
            return new EtwCapabilityStatus(
                Availability: FeatureAvailabilityStatus.Available,
                CanSubscribeUserModeProviders: true,
                RequiresElevationForFullEtw: false,
                Summary: "Standard user-mode ETW providers are accessible; Threat-Intelligence ETW remains PPL/ELAM-restricted; Win32 differential polling and FileSystemWatcher sensors are active.");
        }

        return new EtwCapabilityStatus(
            Availability: FeatureAvailabilityStatus.RequiresElevation,
            CanSubscribeUserModeProviders: false,
            RequiresElevationForFullEtw: true,
            Summary: "Full ETW trace sessions require Administrator or LocalSystem privileges; falling back transparently to Win32 differential polling and FileSystemWatcher sensors.");
    }
}
