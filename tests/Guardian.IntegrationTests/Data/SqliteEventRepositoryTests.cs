using Guardian.Contracts.Common;
using Guardian.Contracts.Data;
using Guardian.Contracts.Network;
using Guardian.Contracts.System;
using Guardian.Data;
using Microsoft.Data.Sqlite;

namespace Guardian.IntegrationTests.Data;

public class SqliteEventRepositoryTests
{
    private static readonly DateTimeOffset BaseTime = new(2026, 11, 1, 10, 0, 0, TimeSpan.Zero);

    private static SystemSecurityEventDto MakeSystemEvent(EventSeverity severity, DateTimeOffset at) =>
        new(
            Guid.NewGuid(),
            at,
            SystemEventCategory.ProcessLifecycle,
            severity,
            "TestSensor",
            1234,
            "proc.exe",
            null,
            "Événement de test",
            new Dictionary<string, string> { ["k"] = "v" });

    private static NetworkEventDto MakeNetworkEvent(EventSeverity severity, DateTimeOffset at) =>
        new(
            Guid.NewGuid(),
            at,
            NetworkEventKind.DnsQuery,
            severity,
            null,
            new DnsObservationDto(Guid.NewGuid(), at, "exemple.test", "A", true, ["192.0.2.10"], 4321, "browser.exe"),
            null,
            new NetworkReputationDto(NetworkReputation.Neutral, 10, "liste-locale"),
            NetworkDecision.None,
            null,
            "Requête DNS observée",
            new Dictionary<string, string>());

    private static AuditEventDto MakeAudit(DateTimeOffset at) =>
        new(Guid.NewGuid(), at, "Network", "ApplyTemporaryBlock", "Guardian.Service", "203.0.113.5", true, null);

    [Fact]
    public async Task SystemEvents_ShouldRoundTripAndFilterBySeverity()
    {
        using var db = new TestDatabase();
        var repository = new SqliteEventRepository(db.Connections);

        await repository.AppendSystemEventAsync(MakeSystemEvent(EventSeverity.Info, BaseTime));
        var high = MakeSystemEvent(EventSeverity.High, BaseTime.AddMinutes(1));
        await repository.AppendSystemEventAsync(high);

        var all = await repository.QuerySystemEventsAsync(new EventQuery());
        Assert.Equal(2, all.TotalCount);
        Assert.Equal(high.EventId, all.Items[0].EventId);
        Assert.Equal("v", all.Items[0].Metadata["k"]);

        var onlyHigh = await repository.QuerySystemEventsAsync(new EventQuery(MinimumSeverity: EventSeverity.High));
        Assert.Single(onlyHigh.Items);
    }

    [Fact]
    public async Task NetworkEvents_ShouldRoundTripNestedDtos()
    {
        using var db = new TestDatabase();
        var repository = new SqliteEventRepository(db.Connections);
        var networkEvent = MakeNetworkEvent(EventSeverity.Low, BaseTime);

        await repository.AppendNetworkEventAsync(networkEvent);
        var page = await repository.QueryNetworkEventsAsync(new EventQuery());

        Assert.Single(page.Items);
        var loaded = page.Items[0];
        Assert.Equal(networkEvent.EventId, loaded.EventId);
        Assert.NotNull(loaded.Dns);
        Assert.Equal("exemple.test", loaded.Dns.QueryName);
        Assert.Equal("192.0.2.10", loaded.Dns.ResolvedAddresses[0]);
        Assert.Equal(NetworkReputation.Neutral, loaded.Reputation?.Verdict);
    }

    [Fact]
    public async Task Append_SameEventTwice_ShouldBeIdempotent()
    {
        using var db = new TestDatabase();
        var repository = new SqliteEventRepository(db.Connections);
        var audit = MakeAudit(BaseTime);

        await repository.AppendAuditEventAsync(audit);
        await repository.AppendAuditEventAsync(audit);

        var page = await repository.QueryAuditEventsAsync(new EventQuery());
        Assert.Equal(1, page.TotalCount);
    }

    [Fact]
    public async Task AuditEvents_ShouldRoundTripAndRefuseModification()
    {
        using var db = new TestDatabase();
        var repository = new SqliteEventRepository(db.Connections);
        var audit = MakeAudit(BaseTime);
        await repository.AppendAuditEventAsync(audit);

        var page = await repository.QueryAuditEventsAsync(new EventQuery());
        Assert.Equal(audit, page.Items[0]);

        await using var connection = await db.Connections.OpenAsync();
        await using var tamper = connection.CreateCommand();
        tamper.CommandText = "UPDATE AuditEvents SET Actor = 'attaquant'";

        await Assert.ThrowsAsync<SqliteException>(() => tamper.ExecuteNonQueryAsync());
    }

    [Fact]
    public async Task Purge_ShouldKeepAuditEventsUnlessExplicitlyRequested()
    {
        using var db = new TestDatabase();
        var repository = new SqliteEventRepository(db.Connections);
        var old = BaseTime.AddDays(-90);

        await repository.AppendSystemEventAsync(MakeSystemEvent(EventSeverity.Info, old));
        await repository.AppendNetworkEventAsync(MakeNetworkEvent(EventSeverity.Info, old));
        await repository.AppendAuditEventAsync(MakeAudit(old));
        await repository.AppendSystemEventAsync(MakeSystemEvent(EventSeverity.Info, BaseTime));

        var first = await repository.PurgeOlderThanAsync(BaseTime.AddDays(-30));
        Assert.Equal(1, first.SystemEventsDeleted);
        Assert.Equal(1, first.NetworkEventsDeleted);
        Assert.Equal(0, first.AuditEventsDeleted);
        Assert.Equal(1, (await repository.QueryAuditEventsAsync(new EventQuery())).TotalCount);

        var second = await repository.PurgeOlderThanAsync(BaseTime.AddDays(-30), includeAudit: true);
        Assert.Equal(1, second.AuditEventsDeleted);
        Assert.Equal(0, (await repository.QueryAuditEventsAsync(new EventQuery())).TotalCount);
        Assert.Equal(1, (await repository.QuerySystemEventsAsync(new EventQuery())).TotalCount);
    }
}
