using System.Text.Json;
using Guardian.Contracts.Common;
using Guardian.Contracts.Health;
using Guardian.Contracts.Ipc;
using Guardian.Contracts.Memory;
using Guardian.Contracts.Scanning;
using Guardian.Contracts.System;
using Guardian.Scanner;
using Guardian.Service.Configuration;
using Guardian.Service.Health;
using Guardian.Service.Ipc;
using Guardian.Service.Scanning;
using Guardian.Service.Security;
using Guardian.Service.Watchdog;
using Guardian.Signatures;
using Guardian.SystemMonitor;
using Guardian.SystemMonitor.Configuration;
using Guardian.SystemMonitor.Detection;
using Guardian.SystemMonitor.Events;
using Guardian.SystemMonitor.Sensors;
using Guardian.Windows.Environment;
using Guardian.Windows.Memory;
using Guardian.Windows.Processes;
using Guardian.Windows.Registry;
using Guardian.Windows.Security;
using Guardian.Windows.Services;
using Guardian.Windows.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Guardian.UnitTests.Service;

public class IpcRequestDispatcherTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task DispatchAsync_ShouldValidateVersionCommandAuthorizationAndExecuteScan()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"guardian-disp-{Guid.NewGuid():N}");
        var scanDir = Path.Combine(tempRoot, "scan");
        var binDir = Path.Combine(tempRoot, "bin");
        var missingDataDir = Path.Combine(tempRoot, "data-none");
        Directory.CreateDirectory(scanDir);
        Directory.CreateDirectory(binDir);

        try
        {
            await File.WriteAllTextAsync(Path.Combine(scanDir, "sample.txt"), "safe-content");
            await File.WriteAllTextAsync(Path.Combine(binDir, "App.dll"), "binary-bytes");

            var timeProvider = new TestTimeProvider();
            var options = Options.Create(new GuardianServiceOptions
            {
                IntegrityMonitoredDirectory = binDir,
                DataDirectoryOverride = missingDataDir,
                AllowNonAdminInteractiveIpc = false,
                RequiredComponents = [GuardianServiceConstants.HostComponentName]
            });

            var healthService = new GuardianHealthService(options, timeProvider);
            await healthService.ReportComponentHealthAsync(new ComponentHealthReport(
                GuardianServiceConstants.HostComponentName,
                GuardianHealthStatus.Healthy,
                "Healthy",
                timeProvider.GetUtcNow(),
                timeProvider.GetUtcNow(),
                FeatureAvailabilityStatus.Available,
                []));

            var tracker = new WatchdogTracker(options, timeProvider);
            var privilegeInspector = new WindowsPrivilegeInspector();
            var registryAdapter = new WindowsRegistryAdapter();
            var serviceAdapter = new WindowsServiceAdapter();
            var postureReader = new WindowsSecurityPostureReader(privilegeInspector, registryAdapter, serviceAdapter, timeProvider);
            var integrityMonitor = new SelfIntegrityMonitor(
                new WindowsAuthenticodeVerifier(),
                new WindowsAclInspector(),
                privilegeInspector,
                healthService,
                options,
                timeProvider,
                NullLogger<SelfIntegrityMonitor>.Instance);

            var scanner = new FileScanner(new InMemorySignatureProvider([]));
            var orchestrator = new ScanOrchestrator(scanner, new DefaultScanTargetResolver());
            using var scanCoordinator = new ScanExecutionCoordinator(orchestrator, NullLogger<ScanExecutionCoordinator>.Instance);

            var sysMonOptions = Options.Create(new SystemMonitorOptions
            {
                EnableFileSystemWatch = false,
                EnableMemorySweep = false
            });
            var memoryAdapter = new WindowsMemoryAdapter();
            var eventStore = new BoundedSystemEventStore(sysMonOptions);
            using var systemMonitor = new SystemMonitorService(
                new WindowsProcessAdapter(),
                serviceAdapter,
                registryAdapter,
                new WindowsScheduledTaskAdapter(tasksRootOverride: Path.Combine(tempRoot, "no-tasks")),
                postureReader,
                new WindowsAuthenticodeVerifier(),
                memoryAdapter,
                new WindowsRemovableDriveProvider(),
                eventStore,
                new WindowsEtwCapabilityProbe(privilegeInspector),
                sysMonOptions,
                timeProvider,
                NullLogger<SystemMonitorService>.Instance);

            eventStore.Publish(new SystemSecurityEventDto(
                Guid.NewGuid(),
                timeProvider.GetUtcNow(),
                SystemEventCategory.ProcessLifecycle,
                EventSeverity.Info,
                "TestSource",
                Environment.ProcessId,
                "testhost",
                null,
                "Test system event recorded",
                new Dictionary<string, string>()));

            var dispatcher = new IpcRequestDispatcher(
                healthService,
                tracker,
                systemMonitor,
                systemMonitor,
                memoryAdapter,
                integrityMonitor,
                scanCoordinator,
                new IpcReplayGuard(options, timeProvider),
                options,
                timeProvider,
                NullLogger<IpcRequestDispatcher>.Instance);

            var adminClient = new IpcClientContext(@"TEST\Admin", "S-1-5-21-1000", 1234, IsAdministrator: true);
            var standardClient = new IpcClientContext(@"TEST\User", "S-1-5-21-1001", 1235, IsAdministrator: false);

            var badVersion = await dispatcher.DispatchAsync(
                new IpcRequest("9.9", "req-ver", IpcCommandType.Ping, timeProvider.GetUtcNow()),
                adminClient);
            Assert.False(badVersion.Success);
            Assert.Equal(IpcErrorCode.InvalidProtocolVersion, badVersion.ErrorCode);

            var unknownCmd = await dispatcher.DispatchAsync(
                new IpcRequest(IpcProtocolConstants.ProtocolVersion, "req-unk", IpcCommandType.Unknown, timeProvider.GetUtcNow()),
                adminClient);
            Assert.False(unknownCmd.Success);
            Assert.Equal(IpcErrorCode.UnknownCommand, unknownCmd.ErrorCode);

            var unauthorized = await dispatcher.DispatchAsync(
                new IpcRequest(IpcProtocolConstants.ProtocolVersion, "req-unauth", IpcCommandType.Ping, timeProvider.GetUtcNow()),
                standardClient);
            Assert.False(unauthorized.Success);
            Assert.Equal(IpcErrorCode.Unauthorized, unauthorized.ErrorCode);

            var ping = await dispatcher.DispatchAsync(
                new IpcRequest(IpcProtocolConstants.ProtocolVersion, "req-ping", IpcCommandType.Ping, timeProvider.GetUtcNow()),
                adminClient);
            Assert.True(ping.Success);
            Assert.Contains("pong", ping.PayloadJson, StringComparison.Ordinal);

            var health = await dispatcher.DispatchAsync(
                new IpcRequest(IpcProtocolConstants.ProtocolVersion, "req-health", IpcCommandType.GetHealth, timeProvider.GetUtcNow()),
                adminClient);
            Assert.True(health.Success);
            var healthSnapshot = JsonSerializer.Deserialize<GuardianHealthSnapshot>(health.PayloadJson!, JsonOptions);
            Assert.NotNull(healthSnapshot);
            Assert.Equal(GuardianHealthStatus.Healthy, healthSnapshot.OverallStatus);

            var startScan = await dispatcher.DispatchAsync(
                new IpcRequest(
                    IpcProtocolConstants.ProtocolVersion,
                    "req-scan",
                    IpcCommandType.StartScan,
                    timeProvider.GetUtcNow(),
                    PayloadJson: JsonSerializer.Serialize(new IpcStartScanPayload(ScanScope.Custom, scanDir), JsonOptions)),
                adminClient);
            Assert.True(startScan.Success);

            IpcScanStatusDto? finalStatus = null;
            for (var attempt = 0; attempt < 50; attempt++)
            {
                var statusResp = await dispatcher.DispatchAsync(
                    new IpcRequest(IpcProtocolConstants.ProtocolVersion, $"req-stat-{attempt}", IpcCommandType.GetScanStatus, timeProvider.GetUtcNow()),
                    adminClient);
                Assert.True(statusResp.Success);
                finalStatus = JsonSerializer.Deserialize<IpcScanStatusDto>(statusResp.PayloadJson!, JsonOptions);
                if (finalStatus is { IsRunning: false, LastCompletedSummary: not null })
                {
                    break;
                }

                await Task.Delay(30);
            }

            Assert.NotNull(finalStatus?.LastCompletedSummary);
            Assert.Equal(1, finalStatus.LastCompletedSummary.FilesScanned);

            var eventsResp = await dispatcher.DispatchAsync(
                new IpcRequest(
                    IpcProtocolConstants.ProtocolVersion,
                    "req-sysevents",
                    IpcCommandType.GetRecentSystemEvents,
                    timeProvider.GetUtcNow(),
                    PayloadJson: JsonSerializer.Serialize(10, JsonOptions)),
                adminClient);
            Assert.True(eventsResp.Success);
            var recentEvents = JsonSerializer.Deserialize<IReadOnlyList<SystemSecurityEventDto>>(eventsResp.PayloadJson!, JsonOptions);
            Assert.NotNull(recentEvents);
            Assert.Contains(recentEvents, e => e.Summary == "Test system event recorded");

            var memResp = await dispatcher.DispatchAsync(
                new IpcRequest(
                    IpcProtocolConstants.ProtocolVersion,
                    "req-mem",
                    IpcCommandType.RunMemoryAnalysis,
                    timeProvider.GetUtcNow(),
                    PayloadJson: JsonSerializer.Serialize(Environment.ProcessId, JsonOptions)),
                adminClient);
            Assert.True(memResp.Success);
            var memReports = JsonSerializer.Deserialize<IReadOnlyList<MemoryAnalysisReportDto>>(memResp.PayloadJson!, JsonOptions);
            Assert.NotNull(memReports);
            Assert.Single(memReports);
            Assert.Equal(Environment.ProcessId, memReports[0].ProcessId);
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
