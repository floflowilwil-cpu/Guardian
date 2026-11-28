using Microsoft.Data.Sqlite;

namespace Guardian.Data;

/// <summary>
/// Fabrique de connexions SQLite ouvertes et configurées.
/// </summary>
public interface ISqliteConnectionFactory
{
    /// <summary>
    /// Ouvre une nouvelle connexion configurée (clés étrangères actives, journal WAL).
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Connexion ouverte, à libérer par l'appelant.</returns>
    Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken = default);
}

/// <summary>
/// Implémentation par défaut de <see cref="ISqliteConnectionFactory"/>.
/// </summary>
public sealed class SqliteConnectionFactory : ISqliteConnectionFactory
{
    private readonly string _connectionString;
    private readonly string _databasePath;

    /// <summary>
    /// Crée la fabrique. Aucune opération disque n'est faite ici : le dossier est créé à l'ouverture.
    /// </summary>
    /// <param name="options">Options de la base.</param>
    public SqliteConnectionFactory(GuardianDatabaseOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _databasePath = options.DatabasePath;

        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = options.DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Pooling = true,
            ForeignKeys = true
        }.ToString();
    }

    /// <inheritdoc />
    public async Task<SqliteConnection> OpenAsync(CancellationToken cancellationToken = default)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(_databasePath));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var connection = new SqliteConnection(_connectionString);
        try
        {
            await connection.OpenAsync(cancellationToken);

            await using var pragma = connection.CreateCommand();
            pragma.CommandText = "PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA busy_timeout = 5000;";
            await pragma.ExecuteNonQueryAsync(cancellationToken);

            return connection;
        }
        catch
        {
            await connection.DisposeAsync();
            throw;
        }
    }
}
