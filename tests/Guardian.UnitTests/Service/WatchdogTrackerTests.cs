using Guardian.Contracts.Common;
using Guardian.Service.Configuration;
using Guardian.Service.Watchdog;
using Microsoft.Extensions.Options;

namespace Guardian.UnitTests.Service;

public class WatchdogTrackerTests
{
    [Fact]
    public void TryReserveRestart_ShouldAllowBoundedRestartsThenOpenCircuitBreakerAndRecoverAfterWindow()
    {
        var timeProvider = new TestTimeProvider();
        var options = Options.Create(new GuardianServiceOptions
        {
            WatchdogMaxRestartsInWindow = 2,
            WatchdogRestartWindowMinutes = 10
        });
        var tracker = new WatchdogTracker(options, timeProvider);
        tracker.RegisterComponent("TestComponent");

        Assert.True(tracker.TryReserveRestart("TestComponent", "Crash #1", out var firstState));
        Assert.Equal(1, firstState.RestartsInCurrentWindow);
        Assert.False(firstState.CircuitBreakerOpen);

        timeProvider.Advance(TimeSpan.FromMinutes(1));
        Assert.True(tracker.TryReserveRestart("TestComponent", "Crash #2", out var secondState));
        Assert.Equal(2, secondState.RestartsInCurrentWindow);
        Assert.False(secondState.CircuitBreakerOpen);

        timeProvider.Advance(TimeSpan.FromMinutes(1));
        Assert.False(tracker.TryReserveRestart("TestComponent", "Crash #3", out var breakerState));
        Assert.True(breakerState.CircuitBreakerOpen);
        Assert.Equal(GuardianHealthStatus.Degraded, breakerState.Status);

        var snapshotWhileOpen = tracker.CaptureSnapshot();
        Assert.Equal(GuardianHealthStatus.Degraded, snapshotWhileOpen.OverallStatus);

        timeProvider.Advance(TimeSpan.FromMinutes(11));
        Assert.True(tracker.TryReserveRestart("TestComponent", "Crash after window", out var recoveredReservation));
        Assert.False(recoveredReservation.CircuitBreakerOpen);
        Assert.Equal(1, recoveredReservation.RestartsInCurrentWindow);

        tracker.UpdateComponentObservation("TestComponent", isHealthy: true, timeProvider.GetUtcNow());
        var healthySnapshot = tracker.CaptureSnapshot();
        Assert.Equal(GuardianHealthStatus.Healthy, healthySnapshot.OverallStatus);
    }
}
