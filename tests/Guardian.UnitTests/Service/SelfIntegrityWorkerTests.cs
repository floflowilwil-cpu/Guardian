using Guardian.Contracts.Common;
using Guardian.Contracts.Health;
using Guardian.Service.Configuration;
using Guardian.Service.Health;
using Guardian.Service.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Guardian.UnitTests.Service;

public class SelfIntegrityWorkerTests
{
    [Fact]
    public async Task ExecuteAsync_ShouldRefreshHeartbeatWithoutTurningStaleAndPreserveDegradedStatus()
    {
        var timeProvider = new TestTimeProvider();
        var options = Options.Create(new GuardianServiceOptions
        {
            HeartbeatIntervalSeconds = 5,
            HeartbeatStaleThresholdSeconds = 20,
            IntegrityCheckIntervalMinutes = 15,
            RequiredComponents = [GuardianServiceConstants.SelfIntegrityComponentName]
        });

        var healthService = new GuardianHealthService(options, timeProvider);
        var monitor = new FakeSelfIntegrityMonitor(healthService, timeProvider);
        using var worker = new SelfIntegrityWorker(
            monitor,
            healthService,
            options,
            timeProvider,
            NullLogger<SelfIntegrityWorker>.Instance);

        await worker.StartAsync(CancellationToken.None);

        try
        {
            Assert.Equal(1, monitor.InitializeCalls);
            Assert.Equal(0, monitor.VerifyCalls);

            await WaitUntilTimerArmedAsync(timeProvider);

            // Avance 6 fois de 5 s (30 s > seuil de péremption de 20 s) sans attendre 15 min.
            for (var tick = 0; tick < 6; tick++)
            {
                timeProvider.Advance(TimeSpan.FromSeconds(5));
                await WaitUntilHeartbeatReachedAsync(healthService, timeProvider.GetUtcNow());
            }

            Assert.Equal(0, monitor.VerifyCalls);

            var healthySnapshot = await healthService.GetOverallHealthAsync();
            Assert.Equal(GuardianHealthStatus.Healthy, healthySnapshot.OverallStatus);

            // Simule une altération détectée lors d'un contrôle à la demande -> le statut Degraded doit être préservé.
            monitor.ReportDegraded = true;
            await monitor.VerifyIntegrityAsync();

            timeProvider.Advance(TimeSpan.FromSeconds(5));
            await WaitUntilHeartbeatReachedAsync(healthService, timeProvider.GetUtcNow());

            var degradedSnapshot = await healthService.GetOverallHealthAsync();
            Assert.Equal(GuardianHealthStatus.Degraded, degradedSnapshot.OverallStatus);
            Assert.Contains(degradedSnapshot.DegradedReasons, r => r.Contains("tampered", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            await worker.StopAsync(CancellationToken.None);
        }
    }

    private static async Task WaitUntilTimerArmedAsync(TestTimeProvider timeProvider)
    {
        for (var attempt = 0; attempt < 200; attempt++)
        {
            if (timeProvider.ActiveTimerCount > 0)
            {
                return;
            }

            await Task.Delay(5);
        }

        throw new TimeoutException("Timed out waiting for SelfIntegrityWorker PeriodicTimer registration.");
    }

    private static async Task WaitUntilHeartbeatReachedAsync(
        IGuardianHealthService healthService,
        DateTimeOffset expectedTimestamp)
    {
        for (var attempt = 0; attempt < 100; attempt++)
        {
            var report = await healthService.GetComponentHealthAsync(GuardianServiceConstants.SelfIntegrityComponentName);
            if (report?.LastHeartbeatUtc >= expectedTimestamp)
            {
                return;
            }

            await Task.Delay(10);
        }

        throw new TimeoutException($"Timed out waiting for SelfIntegrity heartbeat >= {expectedTimestamp:O}.");
    }

    private sealed class FakeSelfIntegrityMonitor(
        IGuardianHealthService healthService,
        TimeProvider timeProvider) : ISelfIntegrityMonitor
    {
        public int InitializeCalls { get; private set; }
        public int VerifyCalls { get; private set; }
        public bool ReportDegraded { get; set; }

        public async Task<SelfIntegrityReportDto> InitializeBaselineAsync(CancellationToken cancellationToken = default)
        {
            InitializeCalls++;
            return await PublishAsync(cancellationToken);
        }

        public async Task<SelfIntegrityReportDto> VerifyIntegrityAsync(CancellationToken cancellationToken = default)
        {
            VerifyCalls++;
            return await PublishAsync(cancellationToken);
        }

        private async Task<SelfIntegrityReportDto> PublishAsync(CancellationToken cancellationToken)
        {
            var now = timeProvider.GetUtcNow();
            var status = ReportDegraded ? GuardianHealthStatus.Degraded : GuardianHealthStatus.Healthy;
            IReadOnlyList<string> anomalies = ReportDegraded ? ["Binary tampered"] : [];

            await healthService.ReportComponentHealthAsync(
                new ComponentHealthReport(
                    GuardianServiceConstants.SelfIntegrityComponentName,
                    status,
                    ReportDegraded ? "Anomaly detected." : "Baseline integrity verified.",
                    now,
                    now,
                    FeatureAvailabilityStatus.Available,
                    anomalies),
                cancellationToken);

            return new SelfIntegrityReportDto(now, status, 9, 9, anomalies, null);
        }
    }
}
