using System.Data.Common;
using System.Text.Json;
using Guardian.Contracts.Common;
using Guardian.Contracts.Data;
using Guardian.Contracts.Network;
using Guardian.Contracts.System;
using Microsoft.Data.Sqlite;

namespace Guardian.Data;

/// <summary>
/// Implémentation SQLite de <see cref="IEventRepository"/>.
/// </summary>
/// <remarks>
/// Toutes les valeurs passent par des paramètres SQL. Les noms de tables utilisés dans les requêtes
/// sont des constantes internes, jamais des données d'entrée.
/// </remarks>
public sealed class SqliteEventRepository : IEventRepository
{
    private const string SystemTable = "SystemEvents";
    private const string NetworkTable = "NetworkEvents";
    private const string AuditTable = "AuditEvents";

    private readonly ISqliteConnectionFactory _connections;

    /// <summary>
    /// Crée le dépôt d'événements.
    /// </summary>
    /// <param name="connections">Fabrique de connexions.</param>
    public SqliteEventRepository(ISqliteConnectionFactory connections)
    {
        _connections = connections ?? throw new ArgumentNullException(nameof(connections));
    }

    /// <inheritdoc />
    public async Task AppendSystemEventAsync(SystemSecurityEventDto systemEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(systemEvent);

        await using var connection = await _connections.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();

        command.CommandText = """
            INSERT INTO SystemEvents (EventId, TimestampUtc, Category, Severity, Source, ProcessId, Summary, PayloadJson)
            VALUES (@id, @ts, @category, @severity, @source, @pid, @summary, @payload)
            ON CONFLICT(EventId) DO NOTHING
            """;
        command.AddParameter("@id", SqlValues.ToDb(systemEvent.EventId));
        command.AddParameter("@ts", SqlValues.ToDb(systemEvent.TimestampUtc));
        command.AddParameter("@category", (int)systemEvent.Category);
        command.AddParameter("@severity", (int)systemEvent.Severity);
        command.AddParameter("@source", systemEvent.Source);
        command.AddParameter("@pid", systemEvent.ProcessId);
        command.AddParameter("@summary", systemEvent.Summary);
        command.AddParameter("@payload", JsonSerializer.Serialize(systemEvent));

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task AppendNetworkEventAsync(NetworkEventDto networkEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(networkEvent);

        await using var connection = await _connections.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();

        command.CommandText = """
            INSERT INTO NetworkEvents
                (EventId, TimestampUtc, Kind, Severity, Decision, AppliedRuleId, ProcessId, RemoteAddress, Domain, Summary, PayloadJson)
            VALUES
                (@id, @ts, @kind, @severity, @decision, @rule, @pid, @remote, @domain, @summary, @payload)
            ON CONFLICT(EventId) DO NOTHING
            """;
        command.AddParameter("@id", SqlValues.ToDb(networkEvent.EventId));
        command.AddParameter("@ts", SqlValues.ToDb(networkEvent.TimestampUtc));
        command.AddParameter("@kind", (int)networkEvent.Kind);
        command.AddParameter("@severity", (int)networkEvent.Severity);
        command.AddParameter("@decision", (int)networkEvent.Decision);
        command.AddParameter("@rule", networkEvent.AppliedRuleId is { } rule ? SqlValues.ToDb(rule) : null);
        command.AddParameter("@pid", networkEvent.Connection?.ProcessId ?? networkEvent.Dns?.ProcessId);
        command.AddParameter("@remote", networkEvent.Connection?.RemoteAddress);
        command.AddParameter("@domain", networkEvent.Dns?.QueryName ?? networkEvent.Connection?.AssociatedDomain);
        command.AddParameter("@summary", networkEvent.Summary);
        command.AddParameter("@payload", JsonSerializer.Serialize(networkEvent));

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task AppendAuditEventAsync(AuditEventDto auditEvent, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(auditEvent);

        await using var connection = await _connections.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();

        command.CommandText = """
            INSERT INTO AuditEvents (EventId, TimestampUtc, Category, Action, Actor, Target, Succeeded, Details)
            VALUES (@id, @ts, @category, @action, @actor, @target, @succeeded, @details)
            ON CONFLICT(EventId) DO NOTHING
            """;
        command.AddParameter("@id", SqlValues.ToDb(auditEvent.EventId));
        command.AddParameter("@ts", SqlValues.ToDb(auditEvent.TimestampUtc));
        command.AddParameter("@category", auditEvent.Category);
        command.AddParameter("@action", auditEvent.Action);
        command.AddParameter("@actor", auditEvent.Actor);
        command.AddParameter("@target", auditEvent.Target);
        command.AddParameter("@succeeded", auditEvent.Succeeded ? 1 : 0);
        command.AddParameter("@details", auditEvent.Details);

        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    /// <inheritdoc />
    public Task<PagedResult<SystemSecurityEventDto>> QuerySystemEventsAsync(EventQuery query, CancellationToken cancellationToken = default) =>
        QueryAsync(
            SystemTable,
            "PayloadJson",
            query,
            filterBySeverity: true,
            reader => DeserializePayload<SystemSecurityEventDto>(reader.GetString(0)),
            cancellationToken);

    /// <inheritdoc />
    public Task<PagedResult<NetworkEventDto>> QueryNetworkEventsAsync(EventQuery query, CancellationToken cancellationToken = default) =>
        QueryAsync(
            NetworkTable,
            "PayloadJson",
            query,
            filterBySeverity: true,
            reader => DeserializePayload<NetworkEventDto>(reader.GetString(0)),
            cancellationToken);

    /// <inheritdoc />
    public Task<PagedResult<AuditEventDto>> QueryAuditEventsAsync(EventQuery query, CancellationToken cancellationToken = default) =>
        QueryAsync(
            AuditTable,
            "EventId, TimestampUtc, Category, Action, Actor, Target, Succeeded, Details",
            query,
            filterBySeverity: false,
            reader => new AuditEventDto(
                SqlValues.GuidFromDb(reader.GetString(0)),
                SqlValues.FromDb(reader.GetString(1)),
                reader.GetString(2),
                reader.GetString(3),
                reader.GetString(4),
                reader.GetString(5),
                reader.GetInt32(6) != 0,
                reader.IsDBNull(7) ? null : reader.GetString(7)),
            cancellationToken);

    /// <inheritdoc />
    public async Task<RetentionPurgeResult> PurgeOlderThanAsync(
        DateTimeOffset cutoffUtc,
        bool includeAudit = false,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await _connections.OpenAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        var systemDeleted = await DeleteBeforeAsync(connection, transaction, SystemTable, cutoffUtc, cancellationToken);
        var networkDeleted = await DeleteBeforeAsync(connection, transaction, NetworkTable, cutoffUtc, cancellationToken);
        var auditDeleted = includeAudit
            ? await DeleteBeforeAsync(connection, transaction, AuditTable, cutoffUtc, cancellationToken)
            : 0;

        await transaction.CommitAsync(cancellationToken);

        return new RetentionPurgeResult(systemDeleted, networkDeleted, auditDeleted);
    }

    private async Task<PagedResult<T>> QueryAsync<T>(
        string table,
        string columns,
        EventQuery query,
        bool filterBySeverity,
        Func<DbDataReader, T> map,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);

        var (skip, take) = SqlValues.NormalizePaging(query.Skip, query.Take);

        var conditions = new List<string>();
        var parameters = new List<KeyValuePair<string, object?>>();

        if (query.FromUtc is { } fromUtc)
        {
            conditions.Add("TimestampUtc >= @fromUtc");
            parameters.Add(new("@fromUtc", SqlValues.ToDb(fromUtc)));
        }

        if (query.ToUtc is { } toUtc)
        {
            conditions.Add("TimestampUtc < @toUtc");
            parameters.Add(new("@toUtc", SqlValues.ToDb(toUtc)));
        }

        if (filterBySeverity && query.MinimumSeverity is { } minimum)
        {
            conditions.Add("Severity >= @minimum");
            parameters.Add(new("@minimum", (int)minimum));
        }

        var whereSql = conditions.Count == 0 ? string.Empty : " WHERE " + string.Join(" AND ", conditions);

        await using var connection = await _connections.OpenAsync(cancellationToken);

        int total;
        await using (var count = connection.CreateCommand())
        {
            count.CommandText = $"SELECT COUNT(*) FROM {table}{whereSql}";
            count.AddParameters(parameters);
            total = Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken), System.Globalization.CultureInfo.InvariantCulture);
        }

        var items = new List<T>();

        await using (var select = connection.CreateCommand())
        {
            select.CommandText =
                $"SELECT {columns} FROM {table}{whereSql} ORDER BY TimestampUtc DESC, EventId LIMIT @take OFFSET @skip";
            select.AddParameters(parameters);
            select.AddParameter("@take", take);
            select.AddParameter("@skip", skip);

            await using var reader = await select.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                items.Add(map(reader));
            }
        }

        return new PagedResult<T>(items, total);
    }

    private static async Task<int> DeleteBeforeAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        string table,
        DateTimeOffset cutoffUtc,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"DELETE FROM {table} WHERE TimestampUtc < @cutoff";
        command.AddParameter("@cutoff", SqlValues.ToDb(cutoffUtc));
        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static T DeserializePayload<T>(string json) =>
        JsonSerializer.Deserialize<T>(json)
        ?? throw new InvalidDataException($"Charge utile d'événement illisible pour {typeof(T).Name}.");
}
