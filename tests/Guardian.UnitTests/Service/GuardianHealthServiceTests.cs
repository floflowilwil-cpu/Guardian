using Guardian.Contracts.Common;
using Guardian.Contracts.Health;
using Guardian.Service.Configuration;
using Guardian.Service.Health;
using Microsoft.Extensions.Options;

namespace Guardian.UnitTests.Service;

public class GuardianHealthServiceTests
{
    [Fact]
    public async Task GetOverallHealthAsync_WhenNoComponentReported_ShouldReturnUnknown()
    {
        var timeProvider = new TestTimeProvider();
        var service = CreateHealthService(timeProvider, GuardianServiceConstants.HostComponentName);

        var snapshot = await service.GetOverallHealthAsync();

        Assert.Equal(GuardianHealthStatus.Unknown, snapshot.OverallStatus);
        Assert.NotEmpty(snapshot.DegradedReasons);
    }

    [Fact]
    public async Task GetOverallHealthAsync_WhenAllRequiredComponentsHealthyWithFreshHeartbeat_ShouldReturnHealthy()
    {
        var timeProvider = new TestTimeProvider();
        var service = CreateHealthService(
            timeProvider,
            GuardianServiceConstants.HostComponentName,
            GuardianServiceConstants.IpcComponentName);

        var now = timeProvider.GetUtcNow();
        await service.ReportComponentHealthAsync(HealthyReport(GuardianServiceConstants.HostComponentName, now));
        await service.ReportComponentHealthAsync(HealthyReport(GuardianServiceConstants.IpcComponentName, now));

        var snapshot = await service.GetOverallHealthAsync();

        Assert.Equal(GuardianHealthStatus.Healthy, snapshot.OverallStatus);
        Assert.Empty(snapshot.DegradedReasons);
        Assert.Equal(2, snapshot.Components.Count);
    }

    [Fact]
    public async Task GetOverallHealthAsync_WhenRequiredComponentMissing_ShouldNeverReportHealthy()
    {
        var timeProvider = new TestTimeProvider();
        var service = CreateHealthService(
            timeProvider,
            GuardianServiceConstants.HostComponentName,
            GuardianServiceConstants.WatchdogComponentName);

        await service.ReportComponentHealthAsync(
            HealthyReport(GuardianServiceConstants.HostComponentName, timeProvider.GetUtcNow()));

        var snapshot = await service.GetOverallHealthAsync();

        Assert.Equal(GuardianHealthStatus.Degraded, snapshot.OverallStatus);
        Assert.Contains(snapshot.DegradedReasons, r => r.Contains(GuardianServiceConstants.WatchdogComponentName, StringComparison.Ordinal));
    }

    [Fact]
    public async Task GetOverallHealthAsync_WhenComponentOutOfDate_ShouldReturnOutOfDate()
    {
        var timeProvider = new TestTimeProvider();
        var service = CreateHealthService(
            timeProvider,
            GuardianServiceConstants.HostComponentName,
            GuardianServiceConstants.ScannerComponentName);

        var now = timeProvider.GetUtcNow();
        await service.ReportComponentHealthAsync(HealthyReport(GuardianServiceConstants.HostComponentName, now));
        await service.ReportComponentHealthAsync(new ComponentHealthReport(
            ComponentName: GuardianServiceConstants.ScannerComponentName,
            Status: GuardianHealthStatus.OutOfDate,
            Summary: "Signature definitions are outdated.",
            LastUpdatedUtc: now,
            LastHeartbeatUtc: now,
            Availability: FeatureAvailabilityStatus.Available,
            Reasons: ["Signatures are older than threshold."]));

        var snapshot = await service.GetOverallHealthAsync();

        Assert.Equal(GuardianHealthStatus.OutOfDate, snapshot.OverallStatus);
        Assert.Contains(snapshot.DegradedReasons, r => r.Contains("Signatures", StringComparison.Ordinal));
    }

    [Fact]
    public async Task GetOverallHealthAsync_WhenHeartbeatBecomesStale_ShouldTransitionToDegraded()
    {
        var timeProvider = new TestTimeProvider();
        var service = CreateHealthService(timeProvider, GuardianServiceConstants.HostComponentName);

        await service.ReportComponentHealthAsync(
            HealthyReport(GuardianServiceConstants.HostComponentName, timeProvider.GetUtcNow()));

        var initial = await service.GetOverallHealthAsync();
        Assert.Equal(GuardianHealthStatus.Healthy, initial.OverallStatus);

        timeProvider.Advance(TimeSpan.FromSeconds(25));

        var afterTimeout = await service.GetOverallHealthAsync();
        Assert.Equal(GuardianHealthStatus.Degraded, afterTimeout.OverallStatus);
        Assert.Contains(afterTimeout.DegradedReasons, r => r.Contains("stale", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task GetOverallHealthAsync_WhenHostStopped_ShouldReturnStopped()
    {
        var timeProvider = new TestTimeProvider();
        var service = CreateHealthService(timeProvider, GuardianServiceConstants.HostComponentName);
        var now = timeProvider.GetUtcNow();

        await service.ReportComponentHealthAsync(new ComponentHealthReport(
            ComponentName: GuardianServiceConstants.HostComponentName,
            Status: GuardianHealthStatus.Stopped,
            Summary: "Service stopped cleanly.",
            LastUpdatedUtc: now,
            LastHeartbeatUtc: now,
            Availability: FeatureAvailabilityStatus.Unavailable,
            Reasons: ["Service host stopped."]));

        var snapshot = await service.GetOverallHealthAsync();

        Assert.Equal(GuardianHealthStatus.Stopped, snapshot.OverallStatus);
    }

    private static GuardianHealthService CreateHealthService(TimeProvider timeProvider, params string[] requiredComponents)
    {
        var options = Options.Create(new GuardianServiceOptions
        {
            HeartbeatIntervalSeconds = 5,
            HeartbeatStaleThresholdSeconds = 20,
            RequiredComponents = [.. requiredComponents]
        });

        return new GuardianHealthService(options, timeProvider);
    }

    private static ComponentHealthReport HealthyReport(string name, DateTimeOffset timestamp) =>
        new(
            ComponentName: name,
            Status: GuardianHealthStatus.Healthy,
            Summary: $"{name} operational.",
            LastUpdatedUtc: timestamp,
            LastHeartbeatUtc: timestamp,
            Availability: FeatureAvailabilityStatus.Available,
            Reasons: []);
}
