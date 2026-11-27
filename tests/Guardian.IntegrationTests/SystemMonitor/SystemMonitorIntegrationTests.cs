using Guardian.Contracts.Common;
using Guardian.Contracts.System;
using Guardian.SystemMonitor;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Guardian.IntegrationTests.SystemMonitor;

public class SystemMonitorIntegrationTests
{
    [Fact]
    public async Task SystemMonitor_WithRealDirectoryBurstSensorAndWindowsAdapters_ShouldDetectBurstAndServeInventory()
    {
        var watchedDir = Path.Combine(Path.GetTempPath(), $"guardian-burst-{Guid.NewGuid():N}");
        Directory.CreateDirectory(watchedDir);

        try
        {
            var configuration = new ConfigurationBuilder()
                .AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["SystemMonitor:PollingIntervalSeconds"] = "60",
                    ["SystemMonitor:MemoryScanIntervalSeconds"] = "120",
                    ["SystemMonitor:EnableFileSystemWatch"] = "true",
                    ["SystemMonitor:WatchedDirectories:0"] = watchedDir,
                    ["SystemMonitor:FileBurstWindowSeconds"] = "10",
                    ["SystemMonitor:FileBurstThreshold"] = "5",
                    ["SystemMonitor:FileBurstCooldownSeconds"] = "30",
                    ["SystemMonitor:EnableMemorySweep"] = "false"
                })
                .Build();

            var services = new ServiceCollection();
            services.AddLogging();
            services.AddGuardianSystemMonitor(configuration);

            await using var provider = services.BuildServiceProvider();
            var systemMonitor = provider.GetRequiredService<ISystemMonitor>();
            var behaviorMonitor = provider.GetRequiredService<IBehaviorMonitor>();

            var burstObserved = new TaskCompletionSource<SystemSecurityEventDto>(TaskCreationOptions.RunContinuationsAsynchronously);
            behaviorMonitor.EventDetected += (_, e) =>
            {
                if (e.Category == SystemEventCategory.FileBurstAnomaly)
                {
                    burstObserved.TrySetResult(e);
                }
            };

            await systemMonitor.StartAsync();

            try
            {
                // Laisse le temps aux capteurs de démarrer puis génère une rafale de fichiers sans lecture de contenu.
                for (var i = 0; i < 10; i++)
                {
                    await File.WriteAllTextAsync(Path.Combine(watchedDir, $"item-{i}.tmp"), $"tick-{i}");
                }

                var burstEvent = await burstObserved.Task.WaitAsync(TimeSpan.FromSeconds(5));
                Assert.Equal(SystemEventCategory.FileBurstAnomaly, burstEvent.Category);
                Assert.Equal(EventSeverity.High, burstEvent.Severity);

                var recent = await behaviorMonitor.GetRecentEventsAsync(20);
                Assert.Contains(recent, e => e.Category == SystemEventCategory.FileBurstAnomaly);

                var processes = await systemMonitor.GetProcessesAsync(includeModules: false);
                var startupEntries = await systemMonitor.GetStartupEntriesAsync();

                if (OperatingSystem.IsWindows())
                {
                    Assert.NotEmpty(processes);
                    Assert.NotNull(startupEntries);
                }
            }
            finally
            {
                await systemMonitor.StopAsync();
            }
        }
        finally
        {
            if (Directory.Exists(watchedDir))
            {
                Directory.Delete(watchedDir, recursive: true);
            }
        }
    }
}
