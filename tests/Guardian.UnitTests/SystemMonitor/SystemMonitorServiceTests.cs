using Guardian.Contracts.Common;
using Guardian.Contracts.Memory;
using Guardian.Contracts.System;
using Guardian.SystemMonitor;
using Guardian.SystemMonitor.Configuration;
using Guardian.SystemMonitor.Detection;
using Guardian.SystemMonitor.Events;
using Guardian.SystemMonitor.Sensors;
using Guardian.UnitTests.Service;
using Guardian.Windows.Environment;
using Guardian.Windows.Memory;
using Guardian.Windows.Processes;
using Guardian.Windows.Registry;
using Guardian.Windows.Security;
using Guardian.Windows.Services;
using Guardian.Windows.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Win32;

namespace Guardian.UnitTests.SystemMonitor;

public class SystemMonitorServiceTests
{
    [Fact]
    public async Task RunSingleObservationCycleAsync_ShouldDetectProcessServiceTaskAndPostureDeltas()
    {
        var tempRoot = Path.Combine(Path.GetTempPath(), $"guardian-sysmon-{Guid.NewGuid():N}");
        var taskDir = Path.Combine(tempRoot, "tasks");
        Directory.CreateDirectory(taskDir);

        try
        {
            var time = new TestTimeProvider();
            var processAdapter = new FakeProcessAdapter
            {
                Processes =
                [
                    new ProcessInfoDto(100, 4, "explorer.exe", @"C:\Windows\explorer.exe", 1, time.GetUtcNow(), FeatureAvailabilityStatus.Available, null, [])
                ]
            };
            var serviceAdapter = new FakeServiceAdapter
            {
                Services =
                [
                    new WindowsServiceInfoDto("BaseSvc", "Base Service", WindowsServiceState.Running, WindowsServiceStartMode.Automatic, @"C:\Windows\System32\base.exe", "LocalSystem", 100)
                ]
            };
            var registryAdapter = new FakeRegistryAdapter
            {
                Entries =
                [
                    new StartupEntryDto("SafeRun", PersistenceEntryKind.RegistryRun, @"HKCU\...\Run", @"C:\Program Files\Safe\app.exe", "User", FeatureAvailabilityStatus.Available)
                ]
            };
            var postureReader = new FakePostureReader(defenderEnabled: true);
            var options = Options.Create(new SystemMonitorOptions
            {
                PollingIntervalSeconds = 5,
                MemoryScanIntervalSeconds = 60,
                EnableFileSystemWatch = false
            });

            var eventStore = new BoundedSystemEventStore(options);
            using var monitor = new SystemMonitorService(
                processAdapter,
                serviceAdapter,
                registryAdapter,
                new WindowsScheduledTaskAdapter(tasksRootOverride: taskDir),
                postureReader,
                new FakeAuthenticodeVerifier(),
                new FakeMemoryAdapter(),
                new FakeRemovableDriveProvider(),
                eventStore,
                new WindowsEtwCapabilityProbe(new WindowsPrivilegeInspector()),
                options,
                time,
                NullLogger<SystemMonitorService>.Instance);

            var raisedEvents = new List<SystemSecurityEventDto>();
            monitor.EventDetected += (_, e) => raisedEvents.Add(e);

            // Cycle 1 : capture silencieuse de référence.
            var firstCycle = await monitor.RunSingleObservationCycleAsync();
            Assert.Empty(firstCycle);
            Assert.NotNull(monitor.LastObservationUtc);

            // Injecte une nouvelle tâche planifiée, un processus enfant suspect et un affaiblissement Defender.
            const string taskXml = """
                <Task version="1.2">
                  <Actions>
                    <Exec>
                      <Command>C:\Users\Public\runner.exe</Command>
                    </Exec>
                  </Actions>
                </Task>
                """;
            await File.WriteAllTextAsync(Path.Combine(taskDir, "NewScheduledTask"), taskXml);

            time.Advance(TimeSpan.FromSeconds(5));
            processAdapter.Processes =
            [
                processAdapter.Processes[0],
                new ProcessInfoDto(500, 100, "winword.exe", @"C:\Office\winword.exe", 1, time.GetUtcNow(), FeatureAvailabilityStatus.Available, null, []),
                new ProcessInfoDto(501, 500, "powershell.exe", @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", 1, time.GetUtcNow(), FeatureAvailabilityStatus.Available, null, [])
            ];
            postureReader.DefenderEnabled = false;

            var secondCycle = await monitor.RunSingleObservationCycleAsync();

            Assert.Contains(secondCycle, e => e.Category == SystemEventCategory.ProcessLifecycle && e.Severity == EventSeverity.High);
            Assert.Contains(secondCycle, e => e.Category == SystemEventCategory.PersistenceChange && e.Target == @"\NewScheduledTask\NewScheduledTask");
            Assert.Contains(secondCycle, e => e.Category == SystemEventCategory.SecurityPostureChange && e.Severity == EventSeverity.High);

            var startupEntries = await monitor.GetStartupEntriesAsync();
            Assert.Contains(startupEntries, e => e.Kind == PersistenceEntryKind.RegistryRun);
            Assert.Contains(startupEntries, e => e.Kind == PersistenceEntryKind.ScheduledTask && e.Name == "NewScheduledTask");

            var recent = await monitor.GetRecentEventsAsync(10);
            Assert.Equal(secondCycle.Count, recent.Count);
            Assert.Equal(secondCycle.Count, raisedEvents.Count);
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, recursive: true);
            }
        }
    }

    [Fact]
    public async Task StartStopLifecycle_ShouldTransitionIsRunningCleanly()
    {
        var time = new TestTimeProvider();
        var options = Options.Create(new SystemMonitorOptions
        {
            PollingIntervalSeconds = 60,
            MemoryScanIntervalSeconds = 120,
            EnableFileSystemWatch = false
        });

        using var monitor = new SystemMonitorService(
            new FakeProcessAdapter(),
            new FakeServiceAdapter(),
            new FakeRegistryAdapter(),
            new WindowsScheduledTaskAdapter(tasksRootOverride: Path.Combine(Path.GetTempPath(), $"none-{Guid.NewGuid():N}")),
            new FakePostureReader(defenderEnabled: true),
            new FakeAuthenticodeVerifier(),
            new FakeMemoryAdapter(),
            new FakeRemovableDriveProvider(),
            new BoundedSystemEventStore(options),
            new WindowsEtwCapabilityProbe(new WindowsPrivilegeInspector()),
            options,
            time,
            NullLogger<SystemMonitorService>.Instance);

        Assert.False(monitor.IsRunning);
        await monitor.StartAsync();
        Assert.True(monitor.IsRunning);

        await monitor.StopAsync();
        Assert.False(monitor.IsRunning);
    }

    private sealed class FakeProcessAdapter : IWindowsProcessAdapter
    {
        public IReadOnlyList<ProcessInfoDto> Processes { get; set; } = [];
        public Task<IReadOnlyList<ProcessInfoDto>> GetProcessesAsync(bool includeModules = false, CancellationToken cancellationToken = default) =>
            Task.FromResult(Processes);
    }

    private sealed class FakeServiceAdapter : IWindowsServiceAdapter
    {
        public IReadOnlyList<WindowsServiceInfoDto> Services { get; set; } = [];
        public Task<IReadOnlyList<WindowsServiceInfoDto>> GetServicesAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(Services);
        public Task<WindowsServiceInfoDto?> GetServiceByNameAsync(string serviceName, CancellationToken cancellationToken = default) =>
            Task.FromResult(Services.FirstOrDefault(s => string.Equals(s.ServiceName, serviceName, StringComparison.OrdinalIgnoreCase)));
    }

    private sealed class FakeRegistryAdapter : IWindowsRegistryAdapter
    {
        public IReadOnlyList<StartupEntryDto> Entries { get; set; } = [];
        public RegistryReadResult<int> TryReadDword(RegistryHive hive, string subKeyPath, string valueName) =>
            new(false, default, FeatureAvailabilityStatus.Available);
        public RegistryReadResult<string> TryReadString(RegistryHive hive, string subKeyPath, string valueName) =>
            new(false, null, FeatureAvailabilityStatus.Available);
        public (FeatureAvailabilityStatus Availability, IReadOnlyDictionary<string, string> Values, string? ErrorMessage) EnumerateValuePairs(RegistryHive hive, string subKeyPath) =>
            (FeatureAvailabilityStatus.Available, new Dictionary<string, string>(), null);
        public Task<IReadOnlyList<StartupEntryDto>> GetStartupEntriesAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(Entries);
    }

    private sealed class FakePostureReader(bool defenderEnabled) : IWindowsSecurityPostureReader
    {
        public bool DefenderEnabled { get; set; } = defenderEnabled;

        public Task<WindowsSecurityPostureDto> ReadPostureAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new WindowsSecurityPostureDto(
                DateTimeOffset.UtcNow,
                "Windows 11",
                "Professional",
                PrivilegeLevel.StandardUser,
                new SecurityControlStatusDto("Microsoft Defender", DefenderEnabled, FeatureAvailabilityStatus.Available, DefenderEnabled ? "Active" : "Disabled"),
                new SecurityControlStatusDto("Windows Firewall", true, FeatureAvailabilityStatus.Available, "Active"),
                new SecurityControlStatusDto("UAC", true, FeatureAvailabilityStatus.Available, "Active"),
                new SecurityControlStatusDto("Secure Boot", true, FeatureAvailabilityStatus.Available, "Active"),
                new SecurityControlStatusDto("TPM", true, FeatureAvailabilityStatus.Available, "Active"),
                new SecurityControlStatusDto("VBS", true, FeatureAvailabilityStatus.Available, "Active"),
                new SecurityControlStatusDto("Credential Guard", false, FeatureAvailabilityStatus.Available, "Not configured"),
                new SecurityControlStatusDto("LSASS Protection", true, FeatureAvailabilityStatus.Available, "RunAsPPL"),
                []));
    }

    private sealed class FakeAuthenticodeVerifier : IWindowsAuthenticodeVerifier
    {
        public Task<FileIntegrityResultDto> VerifyFileAsync(string filePath, string? expectedSha256 = null, CancellationToken cancellationToken = default) =>
            Task.FromResult(new FileIntegrityResultDto(filePath, true, "0000", true, true, true, "Test", 0, FeatureAvailabilityStatus.Available, "Valid"));
    }

    private sealed class FakeMemoryAdapter : IWindowsMemoryAdapter
    {
        public Task<MemoryAnalysisReportDto> AnalyzeProcessAsync(int processId, CancellationToken cancellationToken = default) =>
            Task.FromResult(new MemoryAnalysisReportDto(processId, "proc", DateTimeOffset.UtcNow, FeatureAvailabilityStatus.Available, "Clean", []));
        public Task<IReadOnlyList<MemoryAnalysisReportDto>> ScanAllAccessibleProcessesAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<MemoryAnalysisReportDto>>([]);
    }

    private sealed class FakeRemovableDriveProvider : IRemovableDriveProvider
    {
        public IReadOnlyList<RemovableDriveSnapshot> GetRemovableDrives() => [];
    }
}
