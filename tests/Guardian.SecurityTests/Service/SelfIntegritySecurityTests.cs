using System.Security.AccessControl;
using System.Security.Principal;
using Guardian.Contracts.Common;
using Guardian.Service.Configuration;
using Guardian.Service.Health;
using Guardian.Service.Security;
using Guardian.Windows.Environment;
using Guardian.Windows.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Guardian.SecurityTests.Service;

public class SelfIntegritySecurityTests
{
    [Fact]
    public async Task SelfIntegrityMonitor_ShouldFlagPermissiveDataDirectoryAclAndPassOnceHardened()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var tempRoot = Path.Combine(Path.GetTempPath(), $"guardian-acl-svc-{Guid.NewGuid():N}");
        var binDir = Path.Combine(tempRoot, "bin");
        var dataDir = Path.Combine(tempRoot, "data");
        Directory.CreateDirectory(binDir);
        Directory.CreateDirectory(dataDir);

        try
        {
            await File.WriteAllTextAsync(Path.Combine(binDir, "CoreComponent.dll"), "valid-component-bytes");

            var dirInfo = new DirectoryInfo(dataDir);
            var security = dirInfo.GetAccessControl(AccessControlSections.Access);
            var usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            security.AddAccessRule(new FileSystemAccessRule(
                usersSid,
                FileSystemRights.Modify,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
            dirInfo.SetAccessControl(security);

            var options = Options.Create(new GuardianServiceOptions
            {
                IntegrityMonitoredDirectory = binDir,
                DataDirectoryOverride = dataDir,
                RequireSignedBinaries = false,
                RequiredComponents = [GuardianServiceConstants.SelfIntegrityComponentName]
            });

            var aclInspector = new WindowsAclInspector();
            var healthService = new GuardianHealthService(options, TimeProvider.System);
            var monitor = new SelfIntegrityMonitor(
                new WindowsAuthenticodeVerifier(),
                aclInspector,
                new WindowsPrivilegeInspector(),
                healthService,
                options,
                TimeProvider.System,
                NullLogger<SelfIntegrityMonitor>.Instance);

            var permissiveReport = await monitor.InitializeBaselineAsync();
            Assert.Equal(GuardianHealthStatus.Degraded, permissiveReport.Status);
            Assert.NotNull(permissiveReport.DataDirectoryAclAudit);
            Assert.False(permissiveReport.DataDirectoryAclAudit.IsRestrictive);
            Assert.NotEmpty(permissiveReport.Anomalies);

            aclInspector.ApplyRestrictiveDirectoryAcl(dataDir, includeCurrentUser: true);

            var hardenedReport = await monitor.VerifyIntegrityAsync();
            Assert.Equal(GuardianHealthStatus.Healthy, hardenedReport.Status);
            Assert.Empty(hardenedReport.Anomalies);
            Assert.NotNull(hardenedReport.DataDirectoryAclAudit);
            Assert.True(hardenedReport.DataDirectoryAclAudit.IsRestrictive);
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, recursive: true);
            }
        }
    }
}
