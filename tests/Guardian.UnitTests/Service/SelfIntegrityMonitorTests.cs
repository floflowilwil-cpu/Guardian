using Guardian.Contracts.Common;
using Guardian.Contracts.Health;
using Guardian.Service.Configuration;
using Guardian.Service.Health;
using Guardian.Service.Security;
using Guardian.Windows.Environment;
using Guardian.Windows.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Guardian.UnitTests.Service;

public class SelfIntegrityMonitorTests
{
    [Fact]
    public async Task SelfIntegrityMonitor_ShouldDetectBinaryTamperingUnexpectedFilesAndUnsignedRequirements()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"guardian-integrity-ut-{Guid.NewGuid():N}");
        var binDir = Path.Combine(tempRoot, "bin");
        var missingDataDir = Path.Combine(tempRoot, "data-none");
        Directory.CreateDirectory(binDir);

        try
        {
            var modulePath = Path.Combine(binDir, "ModuleA.dll");
            await File.WriteAllTextAsync(modulePath, "original-binary-payload-v1");

            var timeProvider = new TestTimeProvider();
            var options = Options.Create(new GuardianServiceOptions
            {
                IntegrityMonitoredDirectory = binDir,
                DataDirectoryOverride = missingDataDir,
                RequireSignedBinaries = false,
                RequiredComponents = [GuardianServiceConstants.SelfIntegrityComponentName]
            });

            var healthService = new GuardianHealthService(options, timeProvider);
            var monitor = new SelfIntegrityMonitor(
                new WindowsAuthenticodeVerifier(),
                new WindowsAclInspector(),
                new WindowsPrivilegeInspector(),
                healthService,
                options,
                timeProvider,
                NullLogger<SelfIntegrityMonitor>.Instance);

            var baselineReport = await monitor.InitializeBaselineAsync();
            Assert.Equal(GuardianHealthStatus.Healthy, baselineReport.Status);
            Assert.Equal(1, baselineReport.BaselineFileCount);
            Assert.Empty(baselineReport.Anomalies);

            await File.WriteAllTextAsync(modulePath, "tampered-binary-payload!");
            var tamperedReport = await monitor.VerifyIntegrityAsync();
            Assert.Equal(GuardianHealthStatus.Degraded, tamperedReport.Status);
            Assert.Contains(tamperedReport.Anomalies, a => a.Contains("SHA-256 mismatch", StringComparison.Ordinal));

            var overallHealth = await healthService.GetOverallHealthAsync();
            Assert.Equal(GuardianHealthStatus.Degraded, overallHealth.OverallStatus);

            await File.WriteAllTextAsync(modulePath, "original-binary-payload-v1");
            await File.WriteAllTextAsync(Path.Combine(binDir, "Rogue.dll"), "unexpected");
            var rogueReport = await monitor.VerifyIntegrityAsync();
            Assert.Equal(GuardianHealthStatus.Degraded, rogueReport.Status);
            Assert.Contains(rogueReport.Anomalies, a => a.Contains("Rogue.dll", StringComparison.Ordinal));

            File.Delete(Path.Combine(binDir, "Rogue.dll"));
            var strictOptions = Options.Create(new GuardianServiceOptions
            {
                IntegrityMonitoredDirectory = binDir,
                DataDirectoryOverride = missingDataDir,
                RequireSignedBinaries = true,
                RequiredComponents = [GuardianServiceConstants.SelfIntegrityComponentName]
            });

            var strictMonitor = new SelfIntegrityMonitor(
                new WindowsAuthenticodeVerifier(),
                new WindowsAclInspector(),
                new WindowsPrivilegeInspector(),
                healthService,
                strictOptions,
                timeProvider,
                NullLogger<SelfIntegrityMonitor>.Instance);

            var unsignedReport = await strictMonitor.InitializeBaselineAsync();
            Assert.Equal(GuardianHealthStatus.Degraded, unsignedReport.Status);
            Assert.Contains(unsignedReport.Anomalies, a => a.Contains("Authenticode", StringComparison.Ordinal));
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
