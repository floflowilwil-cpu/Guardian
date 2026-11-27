using Guardian.Contracts.Common;
using Guardian.Contracts.Health;
using Guardian.Service.Configuration;
using Guardian.Service.Hosting;
using Guardian.Service.Watchdog;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Guardian.IntegrationTests.Service;

public class WatchdogRecoveryIntegrationTests
{
    [Fact]
    public async Task WatchdogService_ShouldRecoverTransientFailureAndOpenBreakerOnPersistentFailure()
    {
        var fakeComponent = new FakeMonitoredComponent("Guardian.Test.Worker");
        var missingDataDir = Path.Combine(Path.GetTempPath(), $"guardian-wd-none-{Guid.NewGuid():N}");

        var builder = Host.CreateApplicationBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["GuardianService:HeartbeatIntervalSeconds"] = "5",
            ["GuardianService:HeartbeatStaleThresholdSeconds"] = "20",
            ["GuardianService:WatchdogCheckIntervalSeconds"] = "60",
            ["GuardianService:WatchdogMaxRestartsInWindow"] = "2",
            ["GuardianService:WatchdogRestartWindowMinutes"] = "10",
            ["GuardianService:ShutdownTimeoutSeconds"] = "5",
            ["GuardianService:DataDirectoryOverride"] = missingDataDir
        });
        builder.Services.AddGuardianServiceCore(builder.Configuration);
        builder.Services.AddSingleton<IMonitoredComponent>(fakeComponent);

        using var host = builder.Build();
        var watchdog = host.Services.GetRequiredService<GuardianWatchdogService>();
        var healthService = host.Services.GetRequiredService<IGuardianHealthService>();

        await host.StartAsync();

        try
        {
            fakeComponent.SimulateTransientFailure();
            await watchdog.RunCheckCycleAsync();

            Assert.Equal(1, fakeComponent.RestartAttempts);
            Assert.True(fakeComponent.IsHealthy);

            var recoveredHealth = await healthService.GetOverallHealthAsync();
            var expectedHealthy = OperatingSystem.IsWindows()
                ? GuardianHealthStatus.Healthy
                : GuardianHealthStatus.Degraded;
            Assert.Equal(expectedHealthy, recoveredHealth.OverallStatus);

            fakeComponent.SimulatePersistentFailure();
            await watchdog.RunCheckCycleAsync();
            await watchdog.RunCheckCycleAsync();

            Assert.Equal(2, fakeComponent.RestartAttempts);

            var afterBreakerHealth = await healthService.GetOverallHealthAsync();
            Assert.Equal(GuardianHealthStatus.Degraded, afterBreakerHealth.OverallStatus);
            Assert.NotNull(afterBreakerHealth.Watchdog);
            var tracked = Assert.Single(afterBreakerHealth.Watchdog.Components);
            Assert.True(tracked.CircuitBreakerOpen);
            Assert.Equal(2, tracked.RestartsInCurrentWindow);

            await watchdog.RunCheckCycleAsync();
            Assert.Equal(2, fakeComponent.RestartAttempts);
        }
        finally
        {
            await host.StopAsync();
        }
    }

    private sealed class FakeMonitoredComponent(string componentName) : IMonitoredComponent
    {
        private bool _recoverOnRestart = true;

        public string ComponentName { get; } = componentName;
        public bool IsHealthy { get; private set; } = true;
        public DateTimeOffset? LastHeartbeatUtc { get; private set; } = DateTimeOffset.UtcNow;
        public int RestartAttempts { get; private set; }

        public void SimulateTransientFailure()
        {
            _recoverOnRestart = true;
            IsHealthy = false;
        }

        public void SimulatePersistentFailure()
        {
            _recoverOnRestart = false;
            IsHealthy = false;
        }

        public Task RestartAsync(CancellationToken cancellationToken = default)
        {
            RestartAttempts++;
            if (_recoverOnRestart)
            {
                IsHealthy = true;
                LastHeartbeatUtc = DateTimeOffset.UtcNow;
            }

            return Task.CompletedTask;
        }
    }
}
