using Guardian.Contracts.Common;
using Guardian.Contracts.System;
using Guardian.SystemMonitor.Detection;
using Guardian.UnitTests.Service;

namespace Guardian.UnitTests.SystemMonitor;

public class SecurityPostureChangeTrackerTests
{
    [Fact]
    public void EvaluatePosture_ShouldFlagCriticalWeakeningAndRecovery()
    {
        var time = new TestTimeProvider();
        var tracker = new SecurityPostureChangeTracker(time);

        var securePosture = BuildPosture(time.GetUtcNow(), defenderEnabled: true, uacEnabled: true);
        Assert.Empty(tracker.EvaluatePosture(securePosture));

        // Posture inchangée -> aucun bruit.
        Assert.Empty(tracker.EvaluatePosture(securePosture));

        time.Advance(TimeSpan.FromSeconds(10));
        var weakened = BuildPosture(time.GetUtcNow(), defenderEnabled: false, uacEnabled: true);
        var weakEvents = tracker.EvaluatePosture(weakened);

        var alert = Assert.Single(weakEvents);
        Assert.Equal(SystemEventCategory.SecurityPostureChange, alert.Category);
        Assert.Equal(EventSeverity.High, alert.Severity);
        Assert.Equal("Microsoft Defender", alert.Target);

        time.Advance(TimeSpan.FromSeconds(10));
        var restored = BuildPosture(time.GetUtcNow(), defenderEnabled: true, uacEnabled: true);
        var recoveredEvents = tracker.EvaluatePosture(restored);

        var recovery = Assert.Single(recoveredEvents);
        Assert.Equal(EventSeverity.Info, recovery.Severity);
    }

    private static WindowsSecurityPostureDto BuildPosture(DateTimeOffset now, bool defenderEnabled, bool uacEnabled) =>
        new(
            now,
            "Windows 11",
            "Professional",
            PrivilegeLevel.StandardUser,
            new SecurityControlStatusDto("Microsoft Defender", defenderEnabled, FeatureAvailabilityStatus.Available, defenderEnabled ? "Active" : "Disabled"),
            new SecurityControlStatusDto("Windows Firewall", true, FeatureAvailabilityStatus.Available, "Active"),
            new SecurityControlStatusDto("UAC", uacEnabled, FeatureAvailabilityStatus.Available, uacEnabled ? "Enabled" : "Disabled"),
            new SecurityControlStatusDto("Secure Boot", true, FeatureAvailabilityStatus.Available, "Enabled"),
            new SecurityControlStatusDto("TPM", true, FeatureAvailabilityStatus.Available, "Ready"),
            new SecurityControlStatusDto("VBS", true, FeatureAvailabilityStatus.Available, "Enabled"),
            new SecurityControlStatusDto("Credential Guard", false, FeatureAvailabilityStatus.Available, "Not configured"),
            new SecurityControlStatusDto("LSASS Protection", true, FeatureAvailabilityStatus.Available, "RunAsPPL"),
            []);
}
