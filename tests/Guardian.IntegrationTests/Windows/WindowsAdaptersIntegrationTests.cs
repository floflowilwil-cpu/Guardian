using Guardian.Contracts.Common;
using Guardian.Windows.Environment;
using Guardian.Windows.Processes;
using Guardian.Windows.Registry;
using Guardian.Windows.Security;
using Guardian.Windows.Services;

namespace Guardian.IntegrationTests.Windows;

public class WindowsAdaptersIntegrationTests
{
    [Fact]
    public void PrivilegeInspector_ShouldInspectCurrentWindowsEnvironment()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var inspector = new WindowsPrivilegeInspector();
        var env = inspector.GetEnvironmentInfo();

        Assert.True(env.IsWindows);
        Assert.False(string.IsNullOrWhiteSpace(env.OsVersion));
        Assert.False(string.IsNullOrWhiteSpace(env.WindowsEdition));
        Assert.False(string.IsNullOrWhiteSpace(env.CurrentIdentityName));
        Assert.NotEqual(PrivilegeLevel.Unknown, env.CurrentPrivilege);
    }

    [Fact]
    public async Task SecurityPostureReader_ShouldReadNativeWindowsControlsWithoutThrowing()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var reader = new WindowsSecurityPostureReader(
            new WindowsPrivilegeInspector(),
            new WindowsRegistryAdapter(),
            new WindowsServiceAdapter());

        var posture = await reader.ReadPostureAsync();

        Assert.Equal("Microsoft Defender", posture.Defender.ControlName);
        Assert.Equal("Windows Firewall", posture.Firewall.ControlName);
        Assert.Equal("UAC", posture.Uac.ControlName);
        Assert.Equal("Secure Boot", posture.SecureBoot.ControlName);
        Assert.Equal("TPM", posture.Tpm.ControlName);
        Assert.Equal("VBS", posture.VirtualizationBasedSecurity.ControlName);
        Assert.Equal("Credential Guard", posture.CredentialGuard.ControlName);
        Assert.Equal("LSASS Protection", posture.LsassProtection.ControlName);
    }

    [Fact]
    public async Task ProcessAdapter_ShouldFindCurrentProcessWithExecutablePath()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var adapter = new WindowsProcessAdapter();
        var processes = await adapter.GetProcessesAsync(includeModules: false);

        var current = processes.FirstOrDefault(p => p.ProcessId == Environment.ProcessId);
        Assert.NotNull(current);
        Assert.False(string.IsNullOrWhiteSpace(current.ProcessName));
        Assert.False(string.IsNullOrWhiteSpace(current.ExecutablePath));
        Assert.Equal(FeatureAvailabilityStatus.Available, current.AccessStatus);
    }

    [Fact]
    public async Task ServiceAdapter_ShouldEnumerateWindowsServices()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var adapter = new WindowsServiceAdapter();
        var services = await adapter.GetServicesAsync();

        Assert.NotEmpty(services);
        Assert.Contains(services, s => !string.IsNullOrWhiteSpace(s.ServiceName));
    }

    [Fact]
    public async Task RegistryAdapter_ShouldEnumerateStartupEntriesWithoutThrowing()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var adapter = new WindowsRegistryAdapter();
        var entries = await adapter.GetStartupEntriesAsync();

        Assert.NotNull(entries);
    }

    [Fact]
    public async Task AuthenticodeVerifier_ShouldVerifySignedSystemKernel32Dll()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var kernel32Path = Path.Combine(Environment.SystemDirectory, "kernel32.dll");
        Assert.True(File.Exists(kernel32Path));

        var verifier = new WindowsAuthenticodeVerifier();
        var validResult = await verifier.VerifyFileAsync(kernel32Path);

        Assert.True(validResult.Exists);
        Assert.NotNull(validResult.Sha256);
        Assert.Equal(64, validResult.Sha256.Length);
        Assert.True(validResult.IsAuthenticodeSigned);
        Assert.True(validResult.IsSignatureValid);
        Assert.Equal(FeatureAvailabilityStatus.Available, validResult.Availability);

        var mismatchResult = await verifier.VerifyFileAsync(kernel32Path, expectedSha256: new string('0', 64));
        Assert.False(mismatchResult.ExpectedHashMatched);
    }
}
