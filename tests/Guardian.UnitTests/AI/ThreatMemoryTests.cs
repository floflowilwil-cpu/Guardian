using Guardian.AI.Correlation;
using Guardian.Contracts.AI.Models;

namespace Guardian.UnitTests.AI;

public class ThreatMemoryTests
{
    [Fact]
    public async Task ThreatMemoryService_SanitizesSensitiveMetadataKeys()
    {
        var memory = new ThreatMemoryService();
        var signalWithSensitiveData = new SecuritySignal
        {
            SignalId = "sig-123",
            Source = SignalSource.Process,
            Severity = SignalSeverity.High,
            Category = "ProcessAccess",
            EntityId = "test_proc",
            Description = "Test memory signal",
            TimestampUtc = DateTime.UtcNow,
            Metadata = new Dictionary<string, string>
            {
                ["PublicInfo"] = "legitimate_info",
                ["UserPassword"] = "SecretPassword123!",
                ["AuthToken"] = "Bearer eyJhbGciOi...",
                ["KeystrokeData"] = "typing_log"
            }
        };

        await memory.RecordSignalAsync(signalWithSensitiveData);

        var retrieved = await memory.GetSignalsForEntityAsync("test_proc", TimeSpan.FromMinutes(10));
        Assert.Single(retrieved);

        var storedMetadata = retrieved[0].Metadata;
        Assert.True(storedMetadata.ContainsKey("PublicInfo"));
        Assert.False(storedMetadata.ContainsKey("UserPassword"));
        Assert.False(storedMetadata.ContainsKey("AuthToken"));
        Assert.False(storedMetadata.ContainsKey("KeystrokeData"));
    }

    [Fact]
    public async Task ThreatMemoryService_PurgesExpiredSignals()
    {
        var memory = new ThreatMemoryService();
        var oldSignal = new SecuritySignal
        {
            SignalId = "old-sig",
            Source = SignalSource.Network,
            Severity = SignalSeverity.Low,
            Category = "DnsQuery",
            EntityId = "expired_entity",
            Description = "Old DNS query",
            TimestampUtc = DateTime.UtcNow.AddHours(-48)
        };

        await memory.RecordSignalAsync(oldSignal);
        await memory.PurgeExpiredSignalsAsync(TimeSpan.FromHours(24));

        var retrieved = await memory.GetSignalsForEntityAsync("expired_entity", TimeSpan.FromDays(7));
        Assert.Empty(retrieved);
    }
}
