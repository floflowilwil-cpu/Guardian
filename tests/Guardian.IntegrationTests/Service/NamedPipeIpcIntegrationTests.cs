using System.Text.Json;
using Guardian.Contracts.Common;
using Guardian.Contracts.Ipc;
using Guardian.Contracts.Scanning;
using Guardian.Service.Configuration;
using Guardian.Service.Hosting;
using Guardian.Service.Ipc;
using Guardian.Service.Security;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace Guardian.IntegrationTests.Service;

public class NamedPipeIpcIntegrationTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task NamedPipeServer_EndToEnd_ShouldServeHealthIntegrityAndRealCustomScan()
    {
        var pipeName = $"Guardian.Test.Ipc.{Guid.NewGuid():N}";
        var tempRoot = Path.Combine(Path.GetTempPath(), $"guardian-ipc-int-{Guid.NewGuid():N}");
        var scanDir = Path.Combine(tempRoot, "targets");
        var missingDataDir = Path.Combine(tempRoot, "data-none");
        Directory.CreateDirectory(scanDir);

        try
        {
            await File.WriteAllTextAsync(Path.Combine(scanDir, "doc1.txt"), "benign document 1");
            await File.WriteAllTextAsync(Path.Combine(scanDir, "doc2.txt"), "benign document 2");

            var builder = Host.CreateApplicationBuilder();
            builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["GuardianService:IpcPipeName"] = pipeName,
                ["GuardianService:HeartbeatIntervalSeconds"] = "1",
                ["GuardianService:HeartbeatStaleThresholdSeconds"] = "15",
                ["GuardianService:ShutdownTimeoutSeconds"] = "5",
                ["GuardianService:DataDirectoryOverride"] = missingDataDir
            });
            builder.Services.AddGuardianServiceCore(builder.Configuration);

            using var host = builder.Build();
            await host.StartAsync();

            try
            {
                var client = new NamedPipeIpcClient(pipeName, timeout: TimeSpan.FromSeconds(5));

                var ping = await client.PingAsync();
                Assert.True(ping.Success);
                Assert.Contains("pong", ping.PayloadJson, StringComparison.Ordinal);

                var health = await client.GetHealthAsync();
                Assert.NotNull(health);
                var expectedStatus = OperatingSystem.IsWindows()
                    ? GuardianHealthStatus.Healthy
                    : GuardianHealthStatus.Degraded;
                Assert.Equal(expectedStatus, health.OverallStatus);
                Assert.Contains(health.Components, c => c.ComponentName == GuardianServiceConstants.HostComponentName);
                Assert.Contains(health.Components, c => c.ComponentName == GuardianServiceConstants.WatchdogComponentName);
                Assert.Contains(health.Components, c => c.ComponentName == GuardianServiceConstants.SelfIntegrityComponentName);
                Assert.Contains(health.Components, c => c.ComponentName == GuardianServiceConstants.IpcComponentName);

                var integrityResp = await client.SendAsync(new IpcRequest(
                    IpcProtocolConstants.ProtocolVersion,
                    Guid.NewGuid().ToString("N"),
                    IpcCommandType.RequestSelfIntegrityCheck,
                    DateTimeOffset.UtcNow,
                    Guid.NewGuid().ToString("N")));
                Assert.True(integrityResp.Success);
                var integrityReport = JsonSerializer.Deserialize<SelfIntegrityReportDto>(integrityResp.PayloadJson!, JsonOptions);
                Assert.NotNull(integrityReport);
                Assert.Equal(GuardianHealthStatus.Healthy, integrityReport.Status);

                var (startResp, initialScanStatus) = await client.StartScanAsync(ScanScope.Custom, scanDir);
                Assert.True(startResp.Success);
                Assert.NotNull(initialScanStatus);

                IpcScanStatusDto? completedStatus = null;
                for (var attempt = 0; attempt < 60; attempt++)
                {
                    completedStatus = await client.GetScanStatusAsync();
                    if (completedStatus is { IsRunning: false, LastCompletedSummary: not null })
                    {
                        break;
                    }

                    await Task.Delay(50);
                }

                Assert.NotNull(completedStatus?.LastCompletedSummary);
                Assert.Equal(ScanScope.Custom, completedStatus.LastCompletedSummary.Scope);
                Assert.Equal(2, completedStatus.LastCompletedSummary.FilesScanned);
                Assert.Empty(completedStatus.LastCompletedSummary.Findings);
            }
            finally
            {
                await host.StopAsync();
            }
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
