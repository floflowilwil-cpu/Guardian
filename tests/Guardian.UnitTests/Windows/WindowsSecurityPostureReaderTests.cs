using System.Runtime.Versioning;
using Guardian.Contracts.Common;
using Guardian.Contracts.System;
using Guardian.Windows.Environment;
using Guardian.Windows.Registry;
using Guardian.Windows.Security;
using Guardian.Windows.Services;
using Microsoft.Win32;

namespace Guardian.UnitTests.Windows;

public class WindowsSecurityPostureReaderTests
{
    [Fact]
    public async Task ReadPostureAsync_WhenDefensesWeakened_ShouldDetectAllGapsAndEmitRecommendations()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var registry = new FakeRegistryAdapter();
        registry.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", 1);
        registry.SetDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "EnableFirewall", 1);
        registry.SetDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", "EnableFirewall", 0);
        registry.SetDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "EnableFirewall", 1);
        registry.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 0);
        registry.SetDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 0);

        var services = new FakeServiceAdapter(
            new WindowsServiceInfoDto("WinDefend", "Microsoft Defender Antivirus Service", WindowsServiceState.Stopped, WindowsServiceStartMode.Manual, null, null, null),
            new WindowsServiceInfoDto("mpssvc", "Windows Defender Firewall", WindowsServiceState.Running, WindowsServiceStartMode.Automatic, null, null, 1200),
            new WindowsServiceInfoDto("TBS", "TPM Base Services", WindowsServiceState.Running, WindowsServiceStartMode.Automatic, null, null, 1400));

        var reader = new WindowsSecurityPostureReader(new FakePrivilegeInspector(isWindows: true), registry, services);

        var posture = await reader.ReadPostureAsync();

        Assert.False(posture.Defender.IsEnabled);
        Assert.False(posture.Firewall.IsEnabled);
        Assert.Contains("Private", posture.Firewall.Summary, StringComparison.Ordinal);
        Assert.False(posture.Uac.IsEnabled);
        Assert.Null(posture.SecureBoot.IsEnabled);
        Assert.Equal(FeatureAvailabilityStatus.Unavailable, posture.SecureBoot.Availability);
        Assert.True(posture.Tpm.IsEnabled);
        Assert.False(posture.LsassProtection.IsEnabled);
        Assert.True(posture.Recommendations.Count >= 4);
    }

    [Fact]
    public async Task ReadPostureAsync_WhenAllControlsEnabled_ShouldReportHealthyPostureWithZeroRecommendations()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var registry = new FakeRegistryAdapter();
        registry.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", 0);
        registry.SetDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "EnableFirewall", 1);
        registry.SetDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", "EnableFirewall", 1);
        registry.SetDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile", "EnableFirewall", 1);
        registry.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", 1);
        registry.SetDword(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin", 5);
        registry.SetDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled", 1);
        registry.SetDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity", 1);
        registry.SetDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\DeviceGuard", "LsaCfgFlags", 1);
        registry.SetDword(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 1);

        var services = new FakeServiceAdapter(
            new WindowsServiceInfoDto("WinDefend", "Microsoft Defender Antivirus Service", WindowsServiceState.Running, WindowsServiceStartMode.Automatic, null, null, 1100),
            new WindowsServiceInfoDto("mpssvc", "Windows Defender Firewall", WindowsServiceState.Running, WindowsServiceStartMode.Automatic, null, null, 1200),
            new WindowsServiceInfoDto("TBS", "TPM Base Services", WindowsServiceState.Running, WindowsServiceStartMode.Automatic, null, null, 1400));

        var reader = new WindowsSecurityPostureReader(new FakePrivilegeInspector(isWindows: true), registry, services);

        var posture = await reader.ReadPostureAsync();

        Assert.True(posture.Defender.IsEnabled);
        Assert.True(posture.Firewall.IsEnabled);
        Assert.True(posture.Uac.IsEnabled);
        Assert.True(posture.SecureBoot.IsEnabled);
        Assert.True(posture.Tpm.IsEnabled);
        Assert.True(posture.VirtualizationBasedSecurity.IsEnabled);
        Assert.True(posture.CredentialGuard.IsEnabled);
        Assert.True(posture.LsassProtection.IsEnabled);
        Assert.Empty(posture.Recommendations);
    }

    [Fact]
    public async Task ReadPostureAsync_WhenEnvironmentIsNotWindows_ShouldReportUnavailableHonestly()
    {
        var reader = new WindowsSecurityPostureReader(
            new FakePrivilegeInspector(isWindows: false),
            new FakeRegistryAdapter(),
            new FakeServiceAdapter());

        var posture = await reader.ReadPostureAsync();

        Assert.Equal(FeatureAvailabilityStatus.Unavailable, posture.Defender.Availability);
        Assert.Equal(FeatureAvailabilityStatus.Unavailable, posture.Firewall.Availability);
        Assert.Equal(FeatureAvailabilityStatus.Unavailable, posture.Uac.Availability);
        Assert.Null(posture.Defender.IsEnabled);
    }

    private sealed class FakePrivilegeInspector(bool isWindows) : IWindowsPrivilegeInspector
    {
        public WindowsEnvironmentInfo GetEnvironmentInfo() => new(
            IsWindows: isWindows,
            OsVersion: "Microsoft Windows NT 10.0.26100.0",
            WindowsEdition: "Windows 11 Pro",
            BuildNumber: "26100",
            Is64BitOperatingSystem: true,
            CurrentPrivilege: isWindows ? PrivilegeLevel.StandardUser : PrivilegeLevel.Unknown,
            IsElevated: false,
            CurrentIdentityName: @"TEST\John");

        public GuardianPaths GetStandardPaths(string? programDataRootOverride = null, string? programFilesRootOverride = null, string? localAppDataRootOverride = null)
            => new WindowsPrivilegeInspector().GetStandardPaths(programDataRootOverride, programFilesRootOverride, localAppDataRootOverride);
    }

    private sealed class FakeRegistryAdapter : IWindowsRegistryAdapter
    {
        private readonly Dictionary<(int Hive, string SubKey, string ValueName), int> _dwords = new();

        [SupportedOSPlatform("windows")]
        public void SetDword(RegistryHive hive, string subKey, string valueName, int value)
            => _dwords[((int)hive, subKey.ToUpperInvariant(), valueName.ToUpperInvariant())] = value;

        public RegistryReadResult<int> TryReadDword(RegistryHive hive, string subKeyPath, string valueName)
        {
            if (!OperatingSystem.IsWindows())
            {
                return new RegistryReadResult<int>(false, default, FeatureAvailabilityStatus.Unavailable);
            }

            return TryReadDwordWindows(hive, subKeyPath, valueName);
        }

        [SupportedOSPlatform("windows")]
        private RegistryReadResult<int> TryReadDwordWindows(RegistryHive hive, string subKeyPath, string valueName)
        {
            if (_dwords.TryGetValue(((int)hive, subKeyPath.ToUpperInvariant(), valueName.ToUpperInvariant()), out var value))
            {
                return new RegistryReadResult<int>(true, value, FeatureAvailabilityStatus.Available);
            }

            return new RegistryReadResult<int>(false, default, FeatureAvailabilityStatus.Available);
        }

        public RegistryReadResult<string> TryReadString(RegistryHive hive, string subKeyPath, string valueName)
            => new(false, null, FeatureAvailabilityStatus.Available);

        public (FeatureAvailabilityStatus Availability, IReadOnlyDictionary<string, string> Values, string? ErrorMessage) EnumerateValuePairs(RegistryHive hive, string subKeyPath)
            => (FeatureAvailabilityStatus.Available, new Dictionary<string, string>(), null);

        public Task<IReadOnlyList<StartupEntryDto>> GetStartupEntriesAsync(CancellationToken cancellationToken = default)
            => Task.FromResult<IReadOnlyList<StartupEntryDto>>([]);
    }

    private sealed class FakeServiceAdapter(params WindowsServiceInfoDto[] services) : IWindowsServiceAdapter
    {
        private readonly IReadOnlyList<WindowsServiceInfoDto> _services = services;

        public Task<IReadOnlyList<WindowsServiceInfoDto>> GetServicesAsync(CancellationToken cancellationToken = default)
            => Task.FromResult(_services);

        public Task<WindowsServiceInfoDto?> GetServiceByNameAsync(string serviceName, CancellationToken cancellationToken = default)
            => Task.FromResult(_services.FirstOrDefault(s => string.Equals(s.ServiceName, serviceName, StringComparison.OrdinalIgnoreCase)));
    }
}
