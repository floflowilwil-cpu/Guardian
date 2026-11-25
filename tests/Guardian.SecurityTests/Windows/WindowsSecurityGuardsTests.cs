using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using Guardian.Contracts.Common;
using Guardian.Contracts.Memory;
using Guardian.Windows.Memory;
using Guardian.Windows.Security;

namespace Guardian.SecurityTests.Windows;

public class WindowsSecurityGuardsTests
{
    [Fact]
    public async Task MemoryAdapter_ShouldNeverInspectLsassOrSystemCredentialProcesses()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var adapter = new WindowsMemoryAdapter();

        var systemReport = await adapter.AnalyzeProcessAsync(4);
        Assert.Equal(FeatureAvailabilityStatus.Unavailable, systemReport.Availability);
        Assert.Contains(systemReport.Signals, s => s.Kind == MemorySignalKind.ProtectedProcessSkipped);

        var lsassProcesses = Process.GetProcessesByName("lsass");
        try
        {
            foreach (var lsass in lsassProcesses)
            {
                var report = await adapter.AnalyzeProcessAsync(lsass.Id);
                Assert.Equal(FeatureAvailabilityStatus.Unavailable, report.Availability);
                Assert.Single(report.Signals);
                Assert.Equal(MemorySignalKind.ProtectedProcessSkipped, report.Signals[0].Kind);
            }
        }
        finally
        {
            foreach (var p in lsassProcesses)
            {
                p.Dispose();
            }
        }
    }

    [Fact]
    public void AclInspector_ShouldDetectBroadWritePermissionsAndHardenDirectory()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var tempDir = Path.Combine(Path.GetTempPath(), $"guardian-acl-sec-{Guid.NewGuid():N}");
        var inspector = new WindowsAclInspector();

        try
        {
            Directory.CreateDirectory(tempDir);

            var dirInfo = new DirectoryInfo(tempDir);
            var security = dirInfo.GetAccessControl(AccessControlSections.Access);
            var usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
            security.AddAccessRule(new FileSystemAccessRule(
                usersSid,
                FileSystemRights.Modify,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
            dirInfo.SetAccessControl(security);

            var permissiveAudit = inspector.AuditPathAcl(tempDir);
            Assert.True(permissiveAudit.Exists);
            Assert.False(permissiveAudit.IsRestrictive);
            Assert.NotEmpty(permissiveAudit.Findings);

            inspector.ApplyRestrictiveDirectoryAcl(tempDir, includeCurrentUser: true);

            var hardenedAudit = inspector.AuditPathAcl(tempDir);
            Assert.True(hardenedAudit.Exists);
            Assert.True(hardenedAudit.IsRestrictive);
            Assert.Empty(hardenedAudit.Findings);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Fact]
    public void AclInspector_ShouldRefuseCriticalSystemAndRootPaths()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var inspector = new WindowsAclInspector();
        var windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var system32Dir = Environment.SystemDirectory;
        var rootDrive = Path.GetPathRoot(system32Dir)!;

        Assert.Throws<InvalidOperationException>(() => inspector.ApplyRestrictiveDirectoryAcl(windowsDir));
        Assert.Throws<InvalidOperationException>(() => inspector.ApplyRestrictiveDirectoryAcl(system32Dir));
        Assert.Throws<InvalidOperationException>(() => inspector.ApplyRestrictiveDirectoryAcl(rootDrive));
    }
}
