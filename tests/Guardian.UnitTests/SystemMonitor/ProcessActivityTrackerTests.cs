using Guardian.Contracts.Common;
using Guardian.Contracts.Memory;
using Guardian.Contracts.System;
using Guardian.SystemMonitor.Detection;
using Guardian.UnitTests.Service;

namespace Guardian.UnitTests.SystemMonitor;

public class ProcessActivityTrackerTests
{
    [Fact]
    public void EvaluateProcessSnapshot_ShouldSuppressBaselineThenFlagSuspiciousSpawnAndTempModule()
    {
        var time = new TestTimeProvider();
        var tracker = new ProcessActivityTracker(time, memoryAlertCooldownMinutes: 5);

        var parentProcess = new ProcessInfoDto(
            ProcessId: 1000,
            ParentProcessId: 500,
            ProcessName: "winword.exe",
            ExecutablePath: @"C:\Program Files\Microsoft Office\WINWORD.EXE",
            SessionId: 1,
            StartTimeUtc: time.GetUtcNow(),
            AccessStatus: FeatureAvailabilityStatus.Available,
            AccessNotes: null,
            Modules: []);

        // Premier instantané -> référence silencieuse.
        Assert.Empty(tracker.EvaluateProcessSnapshot([parentProcess]));

        time.Advance(TimeSpan.FromSeconds(5));

        var childPowerShell = new ProcessInfoDto(
            ProcessId: 2000,
            ParentProcessId: 1000,
            ProcessName: "powershell.exe",
            ExecutablePath: @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            SessionId: 1,
            StartTimeUtc: time.GetUtcNow(),
            AccessStatus: FeatureAvailabilityStatus.Available,
            AccessNotes: null,
            Modules:
            [
                new LoadedModuleDto(
                    "hooker.dll",
                    @"C:\Users\john\AppData\Local\Temp\hooker.dll",
                    BaseAddress: 0x10000,
                    MemorySizeBytes: 4096,
                    IsSigned: false)
            ]);

        var events = tracker.EvaluateProcessSnapshot([parentProcess, childPowerShell]);

        Assert.Contains(events, e =>
            e.Category == SystemEventCategory.ProcessLifecycle &&
            e.Severity == EventSeverity.High &&
            e.ProcessId == 2000 &&
            e.Metadata["parentProcess"] == "winword.exe");

        Assert.Contains(events, e =>
            e.Category == SystemEventCategory.InterProcessAccess &&
            e.Severity == EventSeverity.High &&
            e.ProcessId == 2000 &&
            e.Metadata["moduleName"] == "hooker.dll");
    }

    [Fact]
    public void EvaluateMemoryReports_ShouldIgnoreProtectedProcessesAndDeduplicateWithinCooldown()
    {
        var time = new TestTimeProvider();
        var tracker = new ProcessActivityTracker(time, memoryAlertCooldownMinutes: 5);

        var reports = new[]
        {
            new MemoryAnalysisReportDto(
                ProcessId: 668,
                ProcessName: "lsass.exe",
                AnalyzedAtUtc: time.GetUtcNow(),
                Availability: FeatureAvailabilityStatus.Unavailable,
                Summary: "Skipped",
                Signals:
                [
                    new MemoryRegionSignalDto(0, 0, MemorySignalKind.ProtectedProcessSkipped, EventSeverity.Info, "LSASS skipped")
                ]),
            new MemoryAnalysisReportDto(
                ProcessId: 4242,
                ProcessName: "suspicious.exe",
                AnalyzedAtUtc: time.GetUtcNow(),
                Availability: FeatureAvailabilityStatus.Available,
                Summary: "RWX region observed",
                Signals:
                [
                    new MemoryRegionSignalDto(0x200000, 4096, MemorySignalKind.ReadWriteExecuteRegion, EventSeverity.High, "Private RWX page")
                ])
        };

        var firstPass = tracker.EvaluateMemoryReports(reports);
        var singleAlert = Assert.Single(firstPass);
        Assert.Equal(4242, singleAlert.ProcessId);
        Assert.Equal(SystemEventCategory.InterProcessAccess, singleAlert.Category);
        Assert.Equal(EventSeverity.High, singleAlert.Severity);

        // Même signal 1 minute plus tard -> dédupliqué pendant les 5 minutes de cooldown.
        time.Advance(TimeSpan.FromMinutes(1));
        Assert.Empty(tracker.EvaluateMemoryReports(reports));

        // Après expiration du cooldown -> signal émis de nouveau.
        time.Advance(TimeSpan.FromMinutes(5));
        Assert.Single(tracker.EvaluateMemoryReports(reports));
    }
}
