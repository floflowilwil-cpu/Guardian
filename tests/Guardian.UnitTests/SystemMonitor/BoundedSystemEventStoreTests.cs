using Guardian.Contracts.Common;
using Guardian.Contracts.System;
using Guardian.SystemMonitor.Events;

namespace Guardian.UnitTests.SystemMonitor;

public class BoundedSystemEventStoreTests
{
    [Fact]
    public void Publish_ShouldEnforceCapacityRingBufferAndReturnNewestFirst()
    {
        var store = new BoundedSystemEventStore(capacity: 3);

        for (var i = 1; i <= 5; i++)
        {
            store.Publish(CreateEvent($"Event {i}"));
        }

        Assert.Equal(3, store.Count);
        var recent = store.GetRecent(10);
        Assert.Equal(3, recent.Count);
        Assert.Equal("Event 5", recent[0].Summary);
        Assert.Equal("Event 4", recent[1].Summary);
        Assert.Equal("Event 3", recent[2].Summary);
    }

    [Fact]
    public void Publish_ShouldStripSensitiveMetadataKeysAndIsolateFaultySubscribers()
    {
        var store = new BoundedSystemEventStore(capacity: 10);
        SystemSecurityEventDto? secondSubscriberReceived = null;

        store.EventDetected += (_, _) => throw new InvalidOperationException("Simulated UI error");
        store.EventDetected += (_, e) => secondSubscriberReceived = e;

        var published = store.Publish(new SystemSecurityEventDto(
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            SystemEventCategory.ProcessLifecycle,
            EventSeverity.Info,
            "UnitTest",
            42,
            "test.exe",
            @"C:\app\test.exe",
            "Safe event",
            new Dictionary<string, string>
            {
                ["safeField"] = "value-ok",
                ["userPassword"] = "do-not-store",
                ["apiToken"] = "do-not-store",
                ["keystrokeBuffer"] = "do-not-store",
                ["privateKeyHex"] = "do-not-store"
            }));

        Assert.Single(published.Metadata);
        Assert.Equal("value-ok", published.Metadata["safeField"]);
        Assert.NotNull(secondSubscriberReceived);
        Assert.Single(secondSubscriberReceived.Metadata);
    }

    private static SystemSecurityEventDto CreateEvent(string summary) =>
        new(
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            SystemEventCategory.ProcessLifecycle,
            EventSeverity.Info,
            "UnitTest",
            100,
            "proc.exe",
            null,
            summary,
            new Dictionary<string, string>());
}
