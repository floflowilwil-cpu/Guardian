using System.Runtime.Versioning;
using Guardian.Contracts.Common;
using Guardian.Contracts.System;
using Guardian.Windows.Environment;
using Guardian.Windows.Registry;
using Guardian.Windows.Services;
using Microsoft.Win32;

namespace Guardian.Windows.Security;

/// <summary>
/// Évalue de façon strictement passive la posture de sécurité native du système Windows.
/// </summary>
public sealed class WindowsSecurityPostureReader : IWindowsSecurityPostureReader
{
    private readonly IWindowsPrivilegeInspector _privilegeInspector;
    private readonly IWindowsRegistryAdapter _registryAdapter;
    private readonly IWindowsServiceAdapter _serviceAdapter;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initialise le lecteur de posture de sécurité Windows.
    /// </summary>
    /// <param name="privilegeInspector">Inspecteur d'environnement et de privilèges Windows.</param>
    /// <param name="registryAdapter">Adaptateur registre en lecture seule.</param>
    /// <param name="serviceAdapter">Adaptateur d'état des services Windows en lecture seule.</param>
    /// <param name="timeProvider">Fournisseur d'horloge optionnel (par défaut <see cref="TimeProvider.System"/>).</param>
    public WindowsSecurityPostureReader(
        IWindowsPrivilegeInspector privilegeInspector,
        IWindowsRegistryAdapter registryAdapter,
        IWindowsServiceAdapter serviceAdapter,
        TimeProvider? timeProvider = null)
    {
        _privilegeInspector = privilegeInspector ?? throw new ArgumentNullException(nameof(privilegeInspector));
        _registryAdapter = registryAdapter ?? throw new ArgumentNullException(nameof(registryAdapter));
        _serviceAdapter = serviceAdapter ?? throw new ArgumentNullException(nameof(serviceAdapter));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public async Task<WindowsSecurityPostureDto> ReadPostureAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var env = _privilegeInspector.GetEnvironmentInfo();
        var now = _timeProvider.GetUtcNow();

        if (!env.IsWindows || !OperatingSystem.IsWindows())
        {
            var unavailable = static (string name) => new SecurityControlStatusDto(
                ControlName: name,
                IsEnabled: null,
                Availability: FeatureAvailabilityStatus.Unavailable,
                Summary: "Windows security control inspection requires Windows.");

            return new WindowsSecurityPostureDto(
                CapturedAtUtc: now,
                OsVersion: env.OsVersion,
                WindowsEdition: env.WindowsEdition,
                CurrentPrivilege: env.CurrentPrivilege,
                Defender: unavailable("Microsoft Defender"),
                Firewall: unavailable("Windows Firewall"),
                Uac: unavailable("UAC"),
                SecureBoot: unavailable("Secure Boot"),
                Tpm: unavailable("TPM"),
                VirtualizationBasedSecurity: unavailable("VBS"),
                CredentialGuard: unavailable("Credential Guard"),
                LsassProtection: unavailable("LSASS Protection"),
                Recommendations: []);
        }

        return await ReadWindowsPostureAsync(env, now, cancellationToken).ConfigureAwait(false);
    }

    [SupportedOSPlatform("windows")]
    private async Task<WindowsSecurityPostureDto> ReadWindowsPostureAsync(
        WindowsEnvironmentInfo env,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        var recommendations = new List<string>();

        var defender = await ReadDefenderStatusAsync(cancellationToken).ConfigureAwait(false);
        var firewall = await ReadFirewallStatusAsync(cancellationToken).ConfigureAwait(false);
        var uac = ReadUacStatus();
        var secureBoot = ReadSecureBootStatus();
        var tpm = await ReadTpmStatusAsync(cancellationToken).ConfigureAwait(false);
        var vbs = ReadVbsStatus();
        var credentialGuard = ReadCredentialGuardStatus();
        var lsass = ReadLsassProtectionStatus();

        foreach (var control in new[] { defender, firewall, uac, secureBoot, tpm, vbs, credentialGuard, lsass })
        {
            if (!string.IsNullOrWhiteSpace(control.Recommendation))
            {
                recommendations.Add(control.Recommendation);
            }
        }

        return new WindowsSecurityPostureDto(
            CapturedAtUtc: now,
            OsVersion: env.OsVersion,
            WindowsEdition: env.WindowsEdition,
            CurrentPrivilege: env.CurrentPrivilege,
            Defender: defender,
            Firewall: firewall,
            Uac: uac,
            SecureBoot: secureBoot,
            Tpm: tpm,
            VirtualizationBasedSecurity: vbs,
            CredentialGuard: credentialGuard,
            LsassProtection: lsass,
            Recommendations: recommendations);
    }

    [SupportedOSPlatform("windows")]
    private async Task<SecurityControlStatusDto> ReadDefenderStatusAsync(CancellationToken cancellationToken)
    {
        var winDefendService = await _serviceAdapter.GetServiceByNameAsync("WinDefend", cancellationToken).ConfigureAwait(false);
        var disableRtp = _registryAdapter.TryReadDword(
            RegistryHive.LocalMachine,
            @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
            "DisableRealtimeMonitoring");
        var policyDisableAntiSpyware = _registryAdapter.TryReadDword(
            RegistryHive.LocalMachine,
            @"SOFTWARE\Policies\Microsoft\Windows Defender",
            "DisableAntiSpyware");
        var policyDisableRtp = _registryAdapter.TryReadDword(
            RegistryHive.LocalMachine,
            @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
            "DisableRealtimeMonitoring");

        if ((disableRtp.Found && disableRtp.Value == 1) ||
            (policyDisableAntiSpyware.Found && policyDisableAntiSpyware.Value == 1) ||
            (policyDisableRtp.Found && policyDisableRtp.Value == 1))
        {
            return new SecurityControlStatusDto(
                ControlName: "Microsoft Defender",
                IsEnabled: false,
                Availability: FeatureAvailabilityStatus.Available,
                Summary: "Microsoft Defender real-time protection or anti-spyware policy is disabled.",
                Recommendation: "Re-enable Microsoft Defender Real-Time Protection via Windows Security.");
        }

        if (winDefendService is { State: WindowsServiceState.Running })
        {
            return new SecurityControlStatusDto(
                ControlName: "Microsoft Defender",
                IsEnabled: true,
                Availability: FeatureAvailabilityStatus.Available,
                Summary: "Microsoft Defender service (WinDefend) is running and no disablement flag was observed.");
        }

        if (winDefendService is not null)
        {
            return new SecurityControlStatusDto(
                ControlName: "Microsoft Defender",
                IsEnabled: false,
                Availability: FeatureAvailabilityStatus.Available,
                Summary: $"Microsoft Defender service (WinDefend) state is {winDefendService.State}.",
                Recommendation: "Verify Microsoft Defender service health in Windows Security.");
        }

        var requiresElevation = disableRtp.Availability == FeatureAvailabilityStatus.RequiresElevation
            || policyDisableAntiSpyware.Availability == FeatureAvailabilityStatus.RequiresElevation;

        return new SecurityControlStatusDto(
            ControlName: "Microsoft Defender",
            IsEnabled: null,
            Availability: requiresElevation ? FeatureAvailabilityStatus.RequiresElevation : FeatureAvailabilityStatus.Unavailable,
            Summary: requiresElevation
                ? "Microsoft Defender status could not be confirmed without elevated registry/service permissions."
                : "Microsoft Defender service (WinDefend) was not found.",
            RequiredPrivilege: requiresElevation ? "Administrator" : null);
    }

    [SupportedOSPlatform("windows")]
    private async Task<SecurityControlStatusDto> ReadFirewallStatusAsync(CancellationToken cancellationToken)
    {
        var mpssvc = await _serviceAdapter.GetServiceByNameAsync("mpssvc", cancellationToken).ConfigureAwait(false);
        if (mpssvc is not null && mpssvc.State != WindowsServiceState.Running && mpssvc.State != WindowsServiceState.Unknown)
        {
            return new SecurityControlStatusDto(
                ControlName: "Windows Firewall",
                IsEnabled: false,
                Availability: FeatureAvailabilityStatus.Available,
                Summary: $"Windows Defender Firewall service (mpssvc) is {mpssvc.State}.",
                Recommendation: "Enable Windows Defender Firewall service (mpssvc) via Windows Security.");
        }

        var profiles = new (string Name, string SubKey)[]
        {
            ("Domain", @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile"),
            ("Private", @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"),
            ("Public", @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile")
        };

        var disabledProfiles = new List<string>();
        var requiresElevation = false;
        var foundAny = false;

        foreach (var profile in profiles)
        {
            var result = _registryAdapter.TryReadDword(RegistryHive.LocalMachine, profile.SubKey, "EnableFirewall");
            if (result.Availability == FeatureAvailabilityStatus.RequiresElevation)
            {
                requiresElevation = true;
            }
            else if (result.Found)
            {
                foundAny = true;
                if (result.Value == 0)
                {
                    disabledProfiles.Add(profile.Name);
                }
            }
        }

        if (disabledProfiles.Count > 0)
        {
            var list = string.Join(", ", disabledProfiles);
            return new SecurityControlStatusDto(
                ControlName: "Windows Firewall",
                IsEnabled: false,
                Availability: FeatureAvailabilityStatus.Available,
                Summary: $"Windows Firewall is disabled on profile(s): {list}.",
                Recommendation: $"Re-enable Windows Defender Firewall on {list} profile(s).");
        }

        if (foundAny)
        {
            return new SecurityControlStatusDto(
                ControlName: "Windows Firewall",
                IsEnabled: true,
                Availability: FeatureAvailabilityStatus.Available,
                Summary: "Windows Defender Firewall profiles are enabled.");
        }

        if (requiresElevation)
        {
            return new SecurityControlStatusDto(
                ControlName: "Windows Firewall",
                IsEnabled: mpssvc?.State == WindowsServiceState.Running ? true : null,
                Availability: FeatureAvailabilityStatus.RequiresElevation,
                Summary: "Firewall profile registry settings require elevation to inspect completely.",
                RequiredPrivilege: "Administrator");
        }

        return new SecurityControlStatusDto(
            ControlName: "Windows Firewall",
            IsEnabled: mpssvc?.State == WindowsServiceState.Running ? true : null,
            Availability: mpssvc is { State: WindowsServiceState.Running }
                ? FeatureAvailabilityStatus.Degraded
                : FeatureAvailabilityStatus.Unavailable,
            Summary: mpssvc is { State: WindowsServiceState.Running }
                ? "Firewall service is running; profile keys were not found."
                : "Windows Firewall status could not be determined.");
    }

    [SupportedOSPlatform("windows")]
    private SecurityControlStatusDto ReadUacStatus()
    {
        const string uacSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        var enableLua = _registryAdapter.TryReadDword(RegistryHive.LocalMachine, uacSubKey, "EnableLUA");
        var promptBehavior = _registryAdapter.TryReadDword(RegistryHive.LocalMachine, uacSubKey, "ConsentPromptBehaviorAdmin");

        if (enableLua.Availability == FeatureAvailabilityStatus.RequiresElevation)
        {
            return new SecurityControlStatusDto(
                ControlName: "UAC",
                IsEnabled: null,
                Availability: FeatureAvailabilityStatus.RequiresElevation,
                Summary: "UAC configuration requires elevated permissions to inspect.",
                RequiredPrivilege: "Administrator");
        }

        if (!enableLua.Found)
        {
            return new SecurityControlStatusDto(
                ControlName: "UAC",
                IsEnabled: null,
                Availability: FeatureAvailabilityStatus.Unavailable,
                Summary: "EnableLUA registry value was not found.");
        }

        if (enableLua.Value == 0)
        {
            return new SecurityControlStatusDto(
                ControlName: "UAC",
                IsEnabled: false,
                Availability: FeatureAvailabilityStatus.Available,
                Summary: "User Account Control (EnableLUA) is disabled.",
                Recommendation: "Enable User Account Control (UAC) in Windows Security settings.");
        }

        if (promptBehavior.Found && promptBehavior.Value == 0)
        {
            return new SecurityControlStatusDto(
                ControlName: "UAC",
                IsEnabled: true,
                Availability: FeatureAvailabilityStatus.Degraded,
                Summary: "UAC is enabled, but ConsentPromptBehaviorAdmin is set to elevate without prompting.",
                Recommendation: "Configure UAC ConsentPromptBehaviorAdmin to prompt administrators for consent or credentials.");
        }

        return new SecurityControlStatusDto(
            ControlName: "UAC",
            IsEnabled: true,
            Availability: FeatureAvailabilityStatus.Available,
            Summary: "User Account Control (UAC) is enabled with administrator prompting.");
    }

    [SupportedOSPlatform("windows")]
    private SecurityControlStatusDto ReadSecureBootStatus()
    {
        var result = _registryAdapter.TryReadDword(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
            "UEFISecureBootEnabled");

        if (result.Availability == FeatureAvailabilityStatus.RequiresElevation)
        {
            return new SecurityControlStatusDto(
                ControlName: "Secure Boot",
                IsEnabled: null,
                Availability: FeatureAvailabilityStatus.RequiresElevation,
                Summary: "Secure Boot registry state requires elevated access.",
                RequiredPrivilege: "Administrator");
        }

        if (!result.Found)
        {
            return new SecurityControlStatusDto(
                ControlName: "Secure Boot",
                IsEnabled: null,
                Availability: FeatureAvailabilityStatus.Unavailable,
                Summary: "UEFISecureBootEnabled key not present (legacy BIOS or unsupported firmware).");
        }

        if (result.Value == 1)
        {
            return new SecurityControlStatusDto(
                ControlName: "Secure Boot",
                IsEnabled: true,
                Availability: FeatureAvailabilityStatus.Available,
                Summary: "UEFI Secure Boot is enabled.");
        }

        return new SecurityControlStatusDto(
            ControlName: "Secure Boot",
            IsEnabled: false,
            Availability: FeatureAvailabilityStatus.Available,
            Summary: "UEFI Secure Boot is disabled.",
            Recommendation: "Enable UEFI Secure Boot in system firmware settings if supported by hardware.");
    }

    [SupportedOSPlatform("windows")]
    private async Task<SecurityControlStatusDto> ReadTpmStatusAsync(CancellationToken cancellationToken)
    {
        var tbsService = await _serviceAdapter.GetServiceByNameAsync("TBS", cancellationToken).ConfigureAwait(false);
        if (tbsService is null)
        {
            return new SecurityControlStatusDto(
                ControlName: "TPM",
                IsEnabled: null,
                Availability: FeatureAvailabilityStatus.Unavailable,
                Summary: "TPM Base Services (TBS) service was not detected.");
        }

        if (tbsService.State == WindowsServiceState.Running)
        {
            return new SecurityControlStatusDto(
                ControlName: "TPM",
                IsEnabled: true,
                Availability: FeatureAvailabilityStatus.Available,
                Summary: "TPM Base Services (TBS) is running.");
        }

        if (tbsService.StartMode == WindowsServiceStartMode.Disabled)
        {
            return new SecurityControlStatusDto(
                ControlName: "TPM",
                IsEnabled: false,
                Availability: FeatureAvailabilityStatus.Available,
                Summary: "TPM Base Services (TBS) is disabled.",
                Recommendation: "Enable TPM in firmware and ensure TBS service is not disabled.");
        }

        return new SecurityControlStatusDto(
            ControlName: "TPM",
            IsEnabled: true,
            Availability: FeatureAvailabilityStatus.Degraded,
            Summary: $"TPM Base Services (TBS) is configured ({tbsService.StartMode}) and currently {tbsService.State}.");
    }

    [SupportedOSPlatform("windows")]
    private SecurityControlStatusDto ReadVbsStatus()
    {
        var vbs = _registryAdapter.TryReadDword(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\DeviceGuard",
            "EnableVirtualizationBasedSecurity");

        if (vbs.Availability == FeatureAvailabilityStatus.RequiresElevation)
        {
            return new SecurityControlStatusDto(
                ControlName: "VBS",
                IsEnabled: null,
                Availability: FeatureAvailabilityStatus.RequiresElevation,
                Summary: "Virtualization-Based Security configuration requires elevation to inspect.",
                RequiredPrivilege: "Administrator");
        }

        if (vbs.Found && vbs.Value == 1)
        {
            return new SecurityControlStatusDto(
                ControlName: "VBS",
                IsEnabled: true,
                Availability: FeatureAvailabilityStatus.Available,
                Summary: "Virtualization-Based Security (VBS) is configured as enabled.");
        }

        return new SecurityControlStatusDto(
            ControlName: "VBS",
            IsEnabled: false,
            Availability: FeatureAvailabilityStatus.Available,
            Summary: "Virtualization-Based Security (VBS) is not enabled in DeviceGuard configuration.",
            Recommendation: "Consider enabling Virtualization-Based Security / Core Isolation if supported.");
    }

    [SupportedOSPlatform("windows")]
    private SecurityControlStatusDto ReadCredentialGuardStatus()
    {
        var deviceGuardFlag = _registryAdapter.TryReadDword(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\DeviceGuard",
            "LsaCfgFlags");
        var lsaFlag = _registryAdapter.TryReadDword(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Lsa",
            "LsaCfgFlags");

        if (deviceGuardFlag.Availability == FeatureAvailabilityStatus.RequiresElevation &&
            lsaFlag.Availability == FeatureAvailabilityStatus.RequiresElevation)
        {
            return new SecurityControlStatusDto(
                ControlName: "Credential Guard",
                IsEnabled: null,
                Availability: FeatureAvailabilityStatus.RequiresElevation,
                Summary: "Credential Guard settings require elevation to inspect.",
                RequiredPrivilege: "Administrator");
        }

        var flagValue = deviceGuardFlag.Found ? deviceGuardFlag.Value : lsaFlag.Found ? lsaFlag.Value : 0;
        if (flagValue is 1 or 2)
        {
            return new SecurityControlStatusDto(
                ControlName: "Credential Guard",
                IsEnabled: true,
                Availability: FeatureAvailabilityStatus.Available,
                Summary: $"Windows Defender Credential Guard is enabled (LsaCfgFlags={flagValue}).");
        }

        return new SecurityControlStatusDto(
            ControlName: "Credential Guard",
            IsEnabled: false,
            Availability: FeatureAvailabilityStatus.Available,
            Summary: "Windows Defender Credential Guard is not enabled.",
            Recommendation: "Enable Windows Defender Credential Guard on supported Windows editions.");
    }

    [SupportedOSPlatform("windows")]
    private SecurityControlStatusDto ReadLsassProtectionStatus()
    {
        var runAsPpl = _registryAdapter.TryReadDword(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Lsa",
            "RunAsPPL");
        var runAsPplBoot = _registryAdapter.TryReadDword(
            RegistryHive.LocalMachine,
            @"SYSTEM\CurrentControlSet\Control\Lsa",
            "RunAsPPLBoot");

        if (runAsPpl.Availability == FeatureAvailabilityStatus.RequiresElevation &&
            runAsPplBoot.Availability == FeatureAvailabilityStatus.RequiresElevation)
        {
            return new SecurityControlStatusDto(
                ControlName: "LSASS Protection",
                IsEnabled: null,
                Availability: FeatureAvailabilityStatus.RequiresElevation,
                Summary: "LSASS RunAsPPL configuration requires elevation to inspect.",
                RequiredPrivilege: "Administrator");
        }

        if ((runAsPpl.Found && runAsPpl.Value is 1 or 2) ||
            (runAsPplBoot.Found && runAsPplBoot.Value is 1 or 2))
        {
            return new SecurityControlStatusDto(
                ControlName: "LSASS Protection",
                IsEnabled: true,
                Availability: FeatureAvailabilityStatus.Available,
                Summary: "LSASS Protected Process Light (RunAsPPL) is enabled.");
        }

        return new SecurityControlStatusDto(
            ControlName: "LSASS Protection",
            IsEnabled: false,
            Availability: FeatureAvailabilityStatus.Available,
            Summary: "LSASS RunAsPPL protection is not enabled.",
            Recommendation: "Enable Local Security Authority (LSASS) RunAsPPL protection.");
    }
}
