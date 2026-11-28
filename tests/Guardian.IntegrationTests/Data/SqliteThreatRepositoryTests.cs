using Guardian.Contracts.AI.Models;
using Guardian.Contracts.Data;
using Guardian.Data;

namespace Guardian.IntegrationTests.Data;

public class SqliteThreatRepositoryTests
{
    private static readonly DateTimeOffset BaseTime = new(2026, 11, 1, 10, 0, 0, TimeSpan.Zero);

    private static ThreatRecordDto MakeThreat(
        Guid? id = null,
        ThreatStatus status = ThreatStatus.Detected,
        DateTimeOffset? detectedAt = null,
        string name = "Trojan.Test",
        int risk = 80,
        IReadOnlyList<ThreatEvidenceDto>? evidence = null)
    {
        var when = detectedAt ?? BaseTime;

        return new ThreatRecordDto(
            id ?? Guid.NewGuid(),
            when,
            when,
            name,
            ThreatVerdict.Malicious,
            risk,
            status,
            "Scanner",
            @"C:\Temp\sample.exe",
            "ABCDEF0123456789",
            evidence ?? []);
    }

    private static ThreatEvidenceDto MakeEvidence(DateTimeOffset? at = null) =>
        new(
            Guid.NewGuid(),
            at ?? BaseTime,
            "Signature",
            "Correspondance de signature",
            new Dictionary<string, string> { ["rule"] = "R-1" });

    [Fact]
    public async Task UpsertThenGet_ShouldRoundTripThreatAndEvidence()
    {
        using var db = new TestDatabase();
        var repository = new SqliteThreatRepository(db.Connections);
        var threat = MakeThreat(evidence: [MakeEvidence()]);

        await repository.UpsertAsync(threat);
        var loaded = await repository.GetByIdAsync(threat.ThreatId);

        Assert.NotNull(loaded);
        Assert.Equal(threat.DisplayName, loaded.DisplayName);
        Assert.Equal(threat.RiskScore, loaded.RiskScore);
        Assert.Equal(threat.DetectedAtUtc, loaded.DetectedAtUtc);
        Assert.Single(loaded.Evidence);
        Assert.Equal("R-1", loaded.Evidence[0].Metadata["rule"]);
    }

    [Fact]
    public async Task Upsert_ExistingThreat_ShouldUpdateWithoutChangingDetectionDate()
    {
        using var db = new TestDatabase();
        var repository = new SqliteThreatRepository(db.Connections);
        var threat = MakeThreat();
        await repository.UpsertAsync(threat);

        var changed = threat with
        {
            DetectedAtUtc = BaseTime.AddDays(5),
            UpdatedAtUtc = BaseTime.AddDays(5),
            RiskScore = 10
        };
        await repository.UpsertAsync(changed);

        var loaded = await repository.GetByIdAsync(threat.ThreatId);
        Assert.NotNull(loaded);
        Assert.Equal(10, loaded.RiskScore);
        Assert.Equal(BaseTime, loaded.DetectedAtUtc);
    }

    [Fact]
    public async Task Upsert_WithInvalidRiskScore_ShouldBeRejected()
    {
        using var db = new TestDatabase();
        var repository = new SqliteThreatRepository(db.Connections);

        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => repository.UpsertAsync(MakeThreat(risk: 101)));
    }

    [Fact]
    public async Task Upsert_WithSqlInjectionLikeText_ShouldStoreItAsPlainData()
    {
        using var db = new TestDatabase();
        var repository = new SqliteThreatRepository(db.Connections);
        var threat = MakeThreat(name: "x'); DROP TABLE Threats;--");

        await repository.UpsertAsync(threat);
        var loaded = await repository.GetByIdAsync(threat.ThreatId);

        Assert.NotNull(loaded);
        Assert.Equal("x'); DROP TABLE Threats;--", loaded.DisplayName);
    }

    [Fact]
    public async Task GetById_UnknownThreat_ShouldReturnNull()
    {
        using var db = new TestDatabase();
        var repository = new SqliteThreatRepository(db.Connections);

        Assert.Null(await repository.GetByIdAsync(Guid.NewGuid()));
    }

    [Fact]
    public async Task Query_ShouldFilterPageAndOrderNewestFirst()
    {
        using var db = new TestDatabase();
        var repository = new SqliteThreatRepository(db.Connections);

        for (var i = 0; i < 5; i++)
        {
            await repository.UpsertAsync(MakeThreat(detectedAt: BaseTime.AddHours(i)));
        }

        await repository.UpsertAsync(MakeThreat(status: ThreatStatus.Resolved, detectedAt: BaseTime.AddHours(10)));

        var all = await repository.QueryAsync(new ThreatQuery(Take: 3));
        Assert.Equal(6, all.TotalCount);
        Assert.Equal(3, all.Items.Count);
        Assert.Equal(BaseTime.AddHours(10), all.Items[0].DetectedAtUtc);

        var resolved = await repository.QueryAsync(new ThreatQuery(Status: ThreatStatus.Resolved));
        Assert.Equal(1, resolved.TotalCount);

        var window = await repository.QueryAsync(new ThreatQuery(FromUtc: BaseTime.AddHours(1), ToUtc: BaseTime.AddHours(3)));
        Assert.Equal(2, window.TotalCount);
    }

    [Fact]
    public async Task Query_WithAbsurdPaging_ShouldBeClamped()
    {
        using var db = new TestDatabase();
        var repository = new SqliteThreatRepository(db.Connections);
        await repository.UpsertAsync(MakeThreat());

        var page = await repository.QueryAsync(new ThreatQuery(Skip: -5, Take: 1_000_000));

        Assert.Equal(1, page.TotalCount);
        Assert.Single(page.Items);
    }

    [Fact]
    public async Task UpdateStatus_ShouldReportWhetherThreatExisted()
    {
        using var db = new TestDatabase();
        var repository = new SqliteThreatRepository(db.Connections);
        var threat = MakeThreat();
        await repository.UpsertAsync(threat);

        Assert.True(await repository.UpdateStatusAsync(threat.ThreatId, ThreatStatus.Quarantined));
        Assert.False(await repository.UpdateStatusAsync(Guid.NewGuid(), ThreatStatus.Quarantined));

        var loaded = await repository.GetByIdAsync(threat.ThreatId);
        Assert.NotNull(loaded);
        Assert.Equal(ThreatStatus.Quarantined, loaded.Status);
    }

    [Fact]
    public async Task AddEvidence_ShouldAttachOnlyToExistingThreat()
    {
        using var db = new TestDatabase();
        var repository = new SqliteThreatRepository(db.Connections);
        var threat = MakeThreat();
        await repository.UpsertAsync(threat);

        Assert.True(await repository.AddEvidenceAsync(threat.ThreatId, MakeEvidence()));
        Assert.False(await repository.AddEvidenceAsync(Guid.NewGuid(), MakeEvidence()));

        var loaded = await repository.GetByIdAsync(threat.ThreatId);
        Assert.NotNull(loaded);
        Assert.Single(loaded.Evidence);
    }

    [Fact]
    public async Task PurgeClosedOlderThan_ShouldRemoveOnlyOldClosedThreatsAndTheirEvidence()
    {
        using var db = new TestDatabase();
        var clock = new FixedTimeProvider(BaseTime);
        var repository = new SqliteThreatRepository(db.Connections, clock);

        var oldClosed = MakeThreat(status: ThreatStatus.Resolved, detectedAt: BaseTime.AddDays(-60), evidence: [MakeEvidence()]);
        var oldOpen = MakeThreat(status: ThreatStatus.Detected, detectedAt: BaseTime.AddDays(-60));
        var recentClosed = MakeThreat(status: ThreatStatus.Dismissed, detectedAt: BaseTime.AddDays(-1));

        await repository.UpsertAsync(oldClosed);
        await repository.UpsertAsync(oldOpen);
        await repository.UpsertAsync(recentClosed);

        var deleted = await repository.PurgeClosedOlderThanAsync(BaseTime.AddDays(-30));

        Assert.Equal(1, deleted);
        Assert.Null(await repository.GetByIdAsync(oldClosed.ThreatId));
        Assert.NotNull(await repository.GetByIdAsync(oldOpen.ThreatId));
        Assert.NotNull(await repository.GetByIdAsync(recentClosed.ThreatId));

        await using var connection = await db.Connections.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM ThreatEvidence";
        Assert.Equal(0L, await command.ExecuteScalarAsync());
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
