using Guardian.Data;
using Microsoft.Data.Sqlite;

namespace Guardian.IntegrationTests.Data;

public class SqliteMigrationTests
{
    private static readonly string[] ExpectedTables =
    [
        "ScanJobs", "ScanItems", "Threats", "ThreatEvidence", "QuarantineItems", "SystemEvents",
        "NetworkEvents", "PolicyDecisions", "Signatures", "ModelVersions", "UpdateHistory",
        "Exclusions", "Settings", "AuditEvents", "HealthChecks", "SandboxRuns"
    ];

    [Fact]
    public async Task Migrate_ShouldCreateAllSixteenSpecifiedTables()
    {
        using var db = new TestDatabase();

        await using var connection = await db.Connections.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table'";

        var tables = new List<string>();
        await using (var reader = await command.ExecuteReaderAsync())
        {
            while (await reader.ReadAsync())
            {
                tables.Add(reader.GetString(0));
            }
        }

        foreach (var expected in ExpectedTables)
        {
            Assert.Contains(expected, tables);
        }
    }

    [Fact]
    public async Task Migrate_CalledTwice_ShouldNotReapplyMigrations()
    {
        using var db = new TestDatabase();

        var appliedAgain = await db.Migrations.MigrateAsync();

        Assert.Equal(0, appliedAgain);
    }

    [Fact]
    public async Task Migrate_WhenAppliedMigrationWasModified_ShouldFail()
    {
        using var db = new TestDatabase();

        await using (var connection = await db.Connections.OpenAsync())
        await using (var tamper = connection.CreateCommand())
        {
            tamper.CommandText = "UPDATE SchemaMigrations SET Checksum = 'ALTERED'";
            await tamper.ExecuteNonQueryAsync();
        }

        await Assert.ThrowsAsync<InvalidOperationException>(() => db.Migrations.MigrateAsync());
    }

    [Fact]
    public async Task Migrate_WhenDatabaseIsNewerThanApplication_ShouldFail()
    {
        using var db = new TestDatabase();

        await using (var connection = await db.Connections.OpenAsync())
        await using (var future = connection.CreateCommand())
        {
            future.CommandText =
                "INSERT INTO SchemaMigrations (Version, Name, Checksum, AppliedAtUtc) VALUES (999, 'future', 'X', '2099-01-01T00:00:00.0000000Z')";
            await future.ExecuteNonQueryAsync();
        }

        await Assert.ThrowsAsync<InvalidOperationException>(() => db.Migrations.MigrateAsync());
    }

    [Fact]
    public async Task Connections_ShouldEnforceForeignKeys()
    {
        using var db = new TestDatabase();

        await using var connection = await db.Connections.OpenAsync();
        await using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT INTO ThreatEvidence (EvidenceId, ThreatId, ObservedAtUtc, Kind, Description)
            VALUES ('e1', 'inexistant', '2026-01-01T00:00:00.0000000Z', 'k', 'd')
            """;

        await Assert.ThrowsAsync<SqliteException>(() => command.ExecuteNonQueryAsync());
    }
}
