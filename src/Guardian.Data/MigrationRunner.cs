using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace Guardian.Data;

/// <summary>
/// Script de migration SQL embarqué dans l'assembly.
/// </summary>
/// <param name="Version">Numéro de version, croissant.</param>
/// <param name="Name">Nom du script sans extension.</param>
/// <param name="Sql">Contenu SQL, fins de ligne normalisées.</param>
/// <param name="Checksum">Empreinte SHA-256 du contenu, en hexadécimal.</param>
public sealed record MigrationScript(int Version, string Name, string Sql, string Checksum);

/// <summary>
/// Applique les migrations SQL embarquées, dans l'ordre, chacune dans une transaction.
/// </summary>
/// <remarks>
/// Une migration déjà appliquée ne doit jamais être modifiée : son empreinte est vérifiée.
/// Une base plus récente que l'application est refusée (pas de retour arrière de schéma silencieux).
/// </remarks>
public sealed class MigrationRunner
{
    private const string ResourcePrefix = "Migrations/";

    private readonly ISqliteConnectionFactory _connections;
    private readonly IReadOnlyList<MigrationScript> _scripts;
    private readonly TimeProvider _time;

    /// <summary>
    /// Crée un exécuteur utilisant les migrations embarquées de <c>Guardian.Data</c>.
    /// </summary>
    /// <param name="connections">Fabrique de connexions.</param>
    /// <param name="timeProvider">Horloge, facultative.</param>
    public MigrationRunner(ISqliteConnectionFactory connections, TimeProvider? timeProvider = null)
        : this(connections, LoadEmbeddedScripts(typeof(MigrationRunner).Assembly), timeProvider)
    {
    }

    internal MigrationRunner(
        ISqliteConnectionFactory connections,
        IReadOnlyList<MigrationScript> scripts,
        TimeProvider? timeProvider = null)
    {
        _connections = connections ?? throw new ArgumentNullException(nameof(connections));
        _scripts = scripts ?? throw new ArgumentNullException(nameof(scripts));
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Charge les scripts <c>Migrations/NNN_nom.sql</c> embarqués dans un assembly.
    /// </summary>
    /// <param name="assembly">Assembly contenant les ressources.</param>
    /// <returns>Scripts triés par version.</returns>
    public static IReadOnlyList<MigrationScript> LoadEmbeddedScripts(Assembly assembly)
    {
        ArgumentNullException.ThrowIfNull(assembly);

        var scripts = new List<MigrationScript>();

        foreach (var resource in assembly.GetManifestResourceNames())
        {
            if (!resource.StartsWith(ResourcePrefix, StringComparison.Ordinal)
                || !resource.EndsWith(".sql", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var fileName = resource[ResourcePrefix.Length..];
            var separator = fileName.IndexOf('_');

            if (separator <= 0
                || !int.TryParse(fileName[..separator], NumberStyles.None, CultureInfo.InvariantCulture, out var version))
            {
                throw new InvalidOperationException($"Nom de migration invalide : '{fileName}'. Format attendu : NNN_nom.sql.");
            }

            using var stream = assembly.GetManifestResourceStream(resource)
                ?? throw new InvalidOperationException($"Ressource de migration introuvable : '{resource}'.");
            using var reader = new StreamReader(stream, Encoding.UTF8);

            var sql = reader.ReadToEnd().Replace("\r\n", "\n", StringComparison.Ordinal);
            var name = Path.GetFileNameWithoutExtension(fileName);

            scripts.Add(new MigrationScript(version, name, sql, ComputeChecksum(sql)));
        }

        var ordered = scripts.OrderBy(s => s.Version).ToList();

        for (var i = 1; i < ordered.Count; i++)
        {
            if (ordered[i].Version == ordered[i - 1].Version)
            {
                throw new InvalidOperationException($"Deux migrations portent la version {ordered[i].Version}.");
            }
        }

        return ordered;
    }

    /// <summary>
    /// Applique toutes les migrations en attente.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Nombre de migrations appliquées pendant cet appel.</returns>
    public async Task<int> MigrateAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await _connections.OpenAsync(cancellationToken);

        await using (var create = connection.CreateCommand())
        {
            create.CommandText = """
                CREATE TABLE IF NOT EXISTS SchemaMigrations (
                    Version        INTEGER NOT NULL PRIMARY KEY,
                    Name           TEXT    NOT NULL,
                    Checksum       TEXT    NOT NULL,
                    AppliedAtUtc   TEXT    NOT NULL
                ) STRICT;
                """;
            await create.ExecuteNonQueryAsync(cancellationToken);
        }

        var applied = await ReadAppliedAsync(connection, cancellationToken);

        var latestKnown = _scripts.Count == 0 ? 0 : _scripts[^1].Version;
        if (applied.Count > 0 && applied.Keys.Max() > latestKnown)
        {
            throw new InvalidOperationException(
                "La base de données est plus récente que cette version de Guardian. Mise à jour de l'application requise.");
        }

        var appliedNow = 0;

        foreach (var script in _scripts)
        {
            if (applied.TryGetValue(script.Version, out var checksum))
            {
                if (!string.Equals(checksum, script.Checksum, StringComparison.Ordinal))
                {
                    throw new InvalidOperationException(
                        $"La migration {script.Version} ('{script.Name}') a été modifiée après son application.");
                }

                continue;
            }

            await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

            await using (var apply = connection.CreateCommand())
            {
                apply.Transaction = transaction;
                apply.CommandText = script.Sql;
                await apply.ExecuteNonQueryAsync(cancellationToken);
            }

            await using (var record = connection.CreateCommand())
            {
                record.Transaction = transaction;
                record.CommandText =
                    "INSERT INTO SchemaMigrations (Version, Name, Checksum, AppliedAtUtc) VALUES (@version, @name, @checksum, @appliedAt)";
                record.AddParameter("@version", script.Version);
                record.AddParameter("@name", script.Name);
                record.AddParameter("@checksum", script.Checksum);
                record.AddParameter("@appliedAt", SqlValues.ToDb(_time.GetUtcNow()));
                await record.ExecuteNonQueryAsync(cancellationToken);
            }

            await transaction.CommitAsync(cancellationToken);
            appliedNow++;
        }

        return appliedNow;
    }

    private static async Task<Dictionary<int, string>> ReadAppliedAsync(
        SqliteConnection connection,
        CancellationToken cancellationToken)
    {
        var result = new Dictionary<int, string>();

        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT Version, Checksum FROM SchemaMigrations ORDER BY Version";

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            result[reader.GetInt32(0)] = reader.GetString(1);
        }

        return result;
    }

    private static string ComputeChecksum(string sql) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sql)));
}
