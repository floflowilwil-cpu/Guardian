using Guardian.Data;
using Microsoft.Data.Sqlite;

namespace Guardian.IntegrationTests.Data;

/// <summary>
/// Base SQLite temporaire, migrée, supprimée à la fin du test.
/// </summary>
internal sealed class TestDatabase : IDisposable
{
    public TestDatabase()
    {
        DatabasePath = Path.Combine(Path.GetTempPath(), $"guardian-test-{Guid.NewGuid():N}.db");
        Connections = new SqliteConnectionFactory(new GuardianDatabaseOptions { DatabasePath = DatabasePath });
        Migrations = new MigrationRunner(Connections);
        Migrations.MigrateAsync().GetAwaiter().GetResult();
    }

    public string DatabasePath { get; }

    public ISqliteConnectionFactory Connections { get; }

    public MigrationRunner Migrations { get; }

    public void Dispose()
    {
        SqliteConnection.ClearAllPools();

        foreach (var suffix in new[] { string.Empty, "-wal", "-shm" })
        {
            try
            {
                File.Delete(DatabasePath + suffix);
            }
            catch (IOException)
            {
                // Nettoyage au mieux : un fichier temporaire résiduel est sans conséquence.
            }
        }
    }
}
