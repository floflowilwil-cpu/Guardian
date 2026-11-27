using Guardian.Contracts.Common;
using Guardian.Contracts.System;
using Guardian.SystemMonitor.Detection;
using Guardian.UnitTests.Service;

namespace Guardian.UnitTests.SystemMonitor;

public class PersistenceChangeTrackerTests
{
    [Fact]
    public void EvaluateStartupEntries_ShouldDetectRegistryAdditionScheduledTaskAndCriticalWinlogon()
    {
        var time = new TestTimeProvider();
        var tracker = new PersistenceChangeTracker(time);

        var baseline = new[]
        {
            new StartupEntryDto("OneDrive", PersistenceEntryKind.RegistryRun, @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", @"C:\OneDrive.exe", "User", FeatureAvailabilityStatus.Available)
        };

        Assert.Empty(tracker.EvaluateStartupEntries(baseline));

        var updated = new[]
        {
            baseline[0],
            new StartupEntryDto("UpdaterTask", PersistenceEntryKind.ScheduledTask, @"\Custom\UpdaterTask", @"C:\Temp\up.exe", "Machine", FeatureAvailabilityStatus.Available),
            new StartupEntryDto("Shell", PersistenceEntryKind.Winlogon, @"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", @"explorer.exe, evil.exe", "Machine", FeatureAvailabilityStatus.Available)
        };

        var events = tracker.EvaluateStartupEntries(updated);

        Assert.Equal(2, events.Count);
        Assert.Contains(events, e =>
            e.Category == SystemEventCategory.PersistenceChange &&
            e.Severity == EventSeverity.Medium &&
            e.Metadata["kind"] == nameof(PersistenceEntryKind.ScheduledTask));
        Assert.Contains(events, e =>
            e.Category == SystemEventCategory.RegistryModification &&
            e.Severity == EventSeverity.High &&
            e.Metadata["kind"] == nameof(PersistenceEntryKind.Winlogon));
    }

    [Fact]
    public void EvaluateServices_ShouldFlagNewTempServiceAndModifiedBinaryPath()
    {
        var time = new TestTimeProvider();
        var tracker = new PersistenceChangeTracker(time);

        var initial = new[]
        {
            new WindowsServiceInfoDto("AppSvc", "App Service", WindowsServiceState.Running, WindowsServiceStartMode.Automatic, @"C:\Program Files\App\svc.exe", "LocalSystem", 1200)
        };

        Assert.Empty(tracker.EvaluateServices(initial));

        var next = new[]
        {
            new WindowsServiceInfoDto("AppSvc", "App Service", WindowsServiceState.Running, WindowsServiceStartMode.Automatic, @"C:\Program Files\App\hijacked.exe", "LocalSystem", 1200),
            new WindowsServiceInfoDto("TempDropSvc", "Temp Drop", WindowsServiceState.Stopped, WindowsServiceStartMode.Manual, @"C:\Users\Public\drop.exe", "LocalSystem", null)
        };

        var events = tracker.EvaluateServices(next);
        Assert.Equal(2, events.Count);
        Assert.All(events, e =>
        {
            Assert.Equal(SystemEventCategory.PersistenceChange, e.Category);
            Assert.Equal(EventSeverity.High, e.Severity);
        });
    }
}
