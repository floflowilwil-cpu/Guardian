using Guardian.Contracts.Common;
using Guardian.Contracts.System;
using Guardian.SystemMonitor.Detection;
using Guardian.UnitTests.Service;

namespace Guardian.UnitTests.SystemMonitor;

public class FileBurstDetectorTests
{
    [Fact]
    public void RecordFileOperation_ShouldTriggerOnWindowThresholdRespectCooldownAndExpireWindow()
    {
        var time = new TestTimeProvider();
        var detector = new FileBurstDetector(time, windowSeconds: 10, threshold: 4, cooldownSeconds: 30);

        Assert.Null(detector.RecordFileOperation(@"C:\Temp\Work", "Created"));
        Assert.Null(detector.RecordFileOperation(@"C:\Temp\Work", "Changed"));
        Assert.Null(detector.RecordFileOperation(@"C:\Temp\Work", "Renamed"));

        var triggered = detector.RecordFileOperation(@"C:\Temp\Work", "Changed");
        Assert.NotNull(triggered);
        Assert.Equal(SystemEventCategory.FileBurstAnomaly, triggered.Category);
        Assert.Equal(EventSeverity.High, triggered.Severity);

        // Pendant les 30 s de refroidissement -> supprimé.
        Assert.Null(detector.RecordFileOperation(@"C:\Temp\Work", "Changed"));

        // Après expiration du cooldown et de la fenêtre (40 s) -> le compteur repart à 1, donc pas d'alerte immédiate.
        time.Advance(TimeSpan.FromSeconds(40));
        Assert.Null(detector.RecordFileOperation(@"C:\Temp\Work", "Created"));
    }
}
