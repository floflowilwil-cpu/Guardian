using Guardian.Contracts.Common;
using Guardian.Contracts.Health;
using Guardian.Service.Configuration;
using Guardian.Service.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Guardian.IntegrationTests.Service;

public class GuardianServiceHostLifecycleTests
{
    [Fact]
    public async Task ServiceHost_StartsWithoutUi_ReportsHealthyAndTransitionsToStoppedOnShutdown()
    {
        var builder = Host.CreateApplicationBuilder();
        var missingDataDir = Path.Combine(Path.GetTempPath(), $"guardian-nonexistent-{Guid.NewGuid():N}");
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["GuardianService:HeartbeatIntervalSeconds"] = "1",
            ["GuardianService:HeartbeatStaleThresholdSeconds"] = "10",
            ["GuardianService:ShutdownTimeoutSeconds"] = "5",
            ["GuardianService:DataDirectoryOverride"] = missingDataDir,
            ["GuardianService:IpcPipeName"] = $"Guardian.Test.Ipc.{Guid.NewGuid():N}"
        });
        builder.Services.AddGuardianServiceCore(builder.Configuration);

        using var host = builder.Build();
        var healthService = host.Services.GetRequiredService<IGuardianHealthService>();

        await host.StartAsync();

        var runningSnapshot = await healthService.GetOverallHealthAsync();
        var expectedRunningStatus = OperatingSystem.IsWindows()
            ? GuardianHealthStatus.Healthy
            : GuardianHealthStatus.Degraded;

        Assert.Equal(expectedRunningStatus, runningSnapshot.OverallStatus);
        var hostReport = Assert.Single(
            runningSnapshot.Components,
            c => c.ComponentName == GuardianServiceConstants.HostComponentName);
        Assert.NotNull(hostReport.LastHeartbeatUtc);

        await host.StopAsync();

        var stoppedSnapshot = await healthService.GetOverallHealthAsync();
        Assert.Equal(GuardianHealthStatus.Stopped, stoppedSnapshot.OverallStatus);
    }
}
