using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using Guardian.Contracts.Common;
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

namespace Guardian.SecurityTests.SystemMonitor;

public class SystemMonitorSecurityTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private static readonly string[] ForbiddenInputCaptureApis =
    [
        "SetWindowsHookEx",
        "SetWindowsHookExA",
        "SetWindowsHookExW",
        "GetAsyncKeyState",
        "GetKeyState",
        "RegisterRawInputDevices"
    ];

    [Fact]
    public void SystemMonitorAndWindowsAssemblies_ShouldNeverImportKeyloggingOrInputCaptureApis()
    {
        var assemblies = new[]
        {
            typeof(SystemMonitorService).Assembly,
            typeof(GuardianPaths).Assembly
        };

        foreach (var assembly in assemblies)
        {
            foreach (var type in assembly.GetTypes())
            {
                const BindingFlags flags = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance | BindingFlags.DeclaredOnly;
                foreach (var method in type.GetMethods(flags))
                {
                    var dllImport = method.GetCustomAttribute<DllImportAttribute>();
                    var entryPoint = dllImport?.EntryPoint ?? method.Name;

                    foreach (var forbidden in ForbiddenInputCaptureApis)
                    {
                        Assert.False(
                            method.Name.Contains(forbidden, StringComparison.OrdinalIgnoreCase) ||
                            entryPoint.Contains(forbidden, StringComparison.OrdinalIgnoreCase),
                            $"Forbidden input-capture API '{forbidden}' found on {type.FullName}.{method.Name}.");
                    }
                }
            }
        }
    }

    [Fact]
    public void EventStore_ShouldStripForbiddenPrivacyMetadataKeys()
    {
        var store = new BoundedSystemEventStore(capacity: 10);
        var evt = store.Publish(new SystemSecurityEventDto(
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            SystemEventCategory.ProcessLifecycle,
            EventSeverity.Medium,
            "SecurityTest",
            1234,
            "app.exe",
            @"C:\app.exe",
            "Suspicious behavior",
            new Dictionary<string, string>
            {
                ["PasswordHash"] = "secret-value",
                ["SessionSecret"] = "secret-value",
                ["PrivateKeyMaterial"] = "secret-value",
                ["CapturedKeystrokes"] = "secret-value",
                ["AccessToken"] = "secret-value",
                ["CommandLineCategory"] = "benign-summary"
            }));

        Assert.Single(evt.Metadata);
        Assert.True(evt.Metadata.ContainsKey("CommandLineCategory"));
        Assert.DoesNotContain(evt.Metadata.Keys, k =>
            k.Contains("password", StringComparison.OrdinalIgnoreCase) ||
            k.Contains("secret", StringComparison.OrdinalIgnoreCase) ||
            k.Contains("privatekey", StringComparison.OrdinalIgnoreCase) ||
            k.Contains("keystroke", StringComparison.OrdinalIgnoreCase) ||
            k.Contains("token", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ScheduledTaskAdapter_ShouldBlockXxeDtdPayloads()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"guardian-xxe-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);

        try
        {
            const string xxePayload = """
                <?xml version="1.0" encoding="utf-8"?>
                <!DOCTYPE foo [
                  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
                ]>
                <Task version="1.2">
                  <Actions>
                    <Exec>
                      <Command>&xxe;</Command>
                    </Exec>
                  </Actions>
                </Task>
                """;
            await File.WriteAllTextAsync(Path.Combine(tempDir, "XxeTask"), xxePayload);

            var adapter = new WindowsScheduledTaskAdapter(tasksRootOverride: tempDir);
            var tasks = await adapter.GetScheduledTasksAsync();

            Assert.Empty(tasks);
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
    public async Task IpcRunMemoryAnalysis_ShouldNeverInspectLsassAndRejectInvalidPid()
    {
        var missingDataDir = Path.Combine(Path.GetTempPath(), $"guardian-sec-disp-{Guid.NewGuid():N}");
        var options = Options.Create(new GuardianServiceOptions
        {
            DataDirectoryOverride = missingDataDir,
            AllowNonAdminInteractiveIpc = true,
            RequiredComponents = []
        });
        var timeProvider = TimeProvider.System;
        var healthService = new GuardianHealthService(options, timeProvider);
        var tracker = new WatchdogTracker(options, timeProvider);
        var privilegeInspector = new WindowsPrivilegeInspector();
        var registryAdapter = new WindowsRegistryAdapter();
        var serviceAdapter = new WindowsServiceAdapter();
        var taskAdapter = new WindowsScheduledTaskAdapter(tasksRootOverride: Path.Combine(Path.GetTempPath(), $"none-{Guid.NewGuid():N}"));
        var postureReader = new WindowsSecurityPostureReader(privilegeInspector, registryAdapter, serviceAdapter, timeProvider);
        var integrityMonitor = new SelfIntegrityMonitor(
            new WindowsAuthenticodeVerifier(),
            new WindowsAclInspector(),
            privilegeInspector,
            healthService,
            options,
            timeProvider,
            NullLogger<SelfIntegrityMonitor>.Instance);
        var memoryAdapter = new WindowsMemoryAdapter();
        var sysMonOptions = Options.Create(new SystemMonitorOptions { EnableFileSystemWatch = false, EnableMemorySweep = false });
        using var sysMon = new SystemMonitorService(
            new WindowsProcessAdapter(),
            serviceAdapter,
            registryAdapter,
            taskAdapter,
            postureReader,
            new WindowsAuthenticodeVerifier(),
            memoryAdapter,
            new WindowsRemovableDriveProvider(),
            new BoundedSystemEventStore(sysMonOptions),
            new WindowsEtwCapabilityProbe(privilegeInspector),
            sysMonOptions,
            timeProvider,
            NullLogger<SystemMonitorService>.Instance);
        using var scanCoordinator = new ScanExecutionCoordinator(
            new ScanOrchestrator(new FileScanner(new InMemorySignatureProvider([])), new DefaultScanTargetResolver()),
            NullLogger<ScanExecutionCoordinator>.Instance);

        var dispatcher = new IpcRequestDispatcher(
            healthService,
            tracker,
            sysMon,
            sysMon,
            memoryAdapter,
            integrityMonitor,
            scanCoordinator,
            new IpcReplayGuard(options, timeProvider),
            options,
            timeProvider,
            NullLogger<IpcRequestDispatcher>.Instance);

        var admin = new IpcClientContext(@"TEST\Admin", "S-1-5-21-1000", 100, IsAdministrator: true);

        var invalidPidResp = await dispatcher.DispatchAsync(
            new IpcRequest(
                IpcProtocolConstants.ProtocolVersion,
                Guid.NewGuid().ToString("N"),
                IpcCommandType.RunMemoryAnalysis,
                DateTimeOffset.UtcNow,
                Nonce: Guid.NewGuid().ToString("N"),
                PayloadJson: JsonSerializer.Serialize(-42, JsonOptions)),
            admin);
        Assert.False(invalidPidResp.Success);
        Assert.Equal(IpcErrorCode.InvalidRequest, invalidPidResp.ErrorCode);

        if (OperatingSystem.IsWindows())
        {
            var lsass = Process.GetProcessesByName("lsass");
            try
            {
                if (lsass.Length > 0)
                {
                    var lsassResp = await dispatcher.DispatchAsync(
                        new IpcRequest(
                            IpcProtocolConstants.ProtocolVersion,
                            Guid.NewGuid().ToString("N"),
                            IpcCommandType.RunMemoryAnalysis,
                            DateTimeOffset.UtcNow,
                            Nonce: Guid.NewGuid().ToString("N"),
                            PayloadJson: JsonSerializer.Serialize(lsass[0].Id, JsonOptions)),
                        admin);
                    Assert.True(lsassResp.Success);
                    var reports = JsonSerializer.Deserialize<IReadOnlyList<MemoryAnalysisReportDto>>(lsassResp.PayloadJson!, JsonOptions);
                    var lsassReport = Assert.Single(reports!);
                    Assert.Equal(FeatureAvailabilityStatus.Unavailable, lsassReport.Availability);
                    Assert.Contains(lsassReport.Signals, s => s.Kind == MemorySignalKind.ProtectedProcessSkipped);
                }
            }
            finally
            {
                foreach (var p in lsass)
                {
                    p.Dispose();
                }
            }
        }
    }
}
