using System.Text.Json;
using Guardian.Contracts.AI.Models;
using Guardian.Contracts.Data;
using Microsoft.Data.Sqlite;

namespace Guardian.Data;

/// <summary>
/// Implémentation SQLite de <see cref="IThreatRepository"/>.
/// </summary>
/// <remarks>
/// Toutes les valeurs passent par des paramètres SQL ; aucune donnée d'entrée n'est concaténée dans une requête.
/// </remarks>
public sealed class SqliteThreatRepository : IThreatRepository
{
    private readonly ISqliteConnectionFactory _connections;
    private readonly TimeProvider _time;

    /// <summary>
    /// Crée le dépôt de menaces.
    /// </summary>
    /// <param name="connections">Fabrique de connexions.</param>
    /// <param name="timeProvider">Horloge, facultative.</param>
    public SqliteThreatRepository(ISqliteConnectionFactory connections, TimeProvider? timeProvider = null)
    {
        _connections = connections ?? throw new ArgumentNullException(nameof(connections));
        _time = timeProvider ?? TimeProvider.System;
    }

    /// <inheritdoc />
    public async Task UpsertAsync(ThreatRecordDto threat, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(threat);

        if (threat.RiskScore is < 0 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(threat), "RiskScore doit être compris entre 0 et 100.");
        }

        await using var connection = await _connections.OpenAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        await using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO Threats
                    (ThreatId, DetectedAtUtc, UpdatedAtUtc, DisplayName, Verdict, RiskScore, Status, DetectionSource, FilePath, Sha256)
                VALUES
                    (@id, @detected, @updated, @name, @verdict, @risk, @status, @source, @path, @sha)
                ON CONFLICT(ThreatId) DO UPDATE SET
                    UpdatedAtUtc    = excluded.UpdatedAtUtc,
                    DisplayName     = excluded.DisplayName,
                    Verdict         = excluded.Verdict,
                    RiskScore       = excluded.RiskScore,
                    Status          = excluded.Status,
                    DetectionSource = excluded.DetectionSource,
                    FilePath        = excluded.FilePath,
                    Sha256          = excluded.Sha256
                """;
            command.AddParameter("@id", SqlValues.ToDb(threat.ThreatId));
            command.AddParameter("@detected", SqlValues.ToDb(threat.DetectedAtUtc));
            command.AddParameter("@updated", SqlValues.ToDb(threat.UpdatedAtUtc));
            command.AddParameter("@name", threat.DisplayName);
            command.AddParameter("@verdict", (int)threat.Verdict);
            command.AddParameter("@risk", threat.RiskScore);
            command.AddParameter("@status", (int)threat.Status);
            command.AddParameter("@source", threat.DetectionSource);
            command.AddParameter("@path", threat.FilePath);
            command.AddParameter("@sha", threat.Sha256);
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        foreach (var evidence in threat.Evidence)
        {
            await InsertEvidenceAsync(connection, transaction, threat.ThreatId, evidence, cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
    }

    /// <inheritdoc />
    public async Task<ThreatRecordDto?> GetByIdAsync(Guid threatId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connections.OpenAsync(cancellationToken);

        var parameters = new List<KeyValuePair<string, object?>> { new("@id", SqlValues.ToDb(threatId)) };
        var rows = await SelectThreatsAsync(connection, "WHERE ThreatId = @id", parameters, cancellationToken);

        if (rows.Count == 0)
        {
            return null;
        }

        var evidence = await LoadEvidenceAsync(connection, [threatId], cancellationToken);
        return ToDto(rows[0], evidence);
    }

    /// <inheritdoc />
    public async Task<PagedResult<ThreatRecordDto>> QueryAsync(ThreatQuery query, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        var (skip, take) = SqlValues.NormalizePaging(query.Skip, query.Take);

        var conditions = new List<string>();
        var parameters = new List<KeyValuePair<string, object?>>();

        if (query.FromUtc is { } fromUtc)
        {
            conditions.Add("DetectedAtUtc >= @fromUtc");
            parameters.Add(new("@fromUtc", SqlValues.ToDb(fromUtc)));
        }

        if (query.ToUtc is { } toUtc)
        {
            conditions.Add("DetectedAtUtc < @toUtc");
            parameters.Add(new("@toUtc", SqlValues.ToDb(toUtc)));
        }

        if (query.Status is { } status)
        {
            conditions.Add("Status = @status");
            parameters.Add(new("@status", (int)status));
        }

        if (query.Verdict is { } verdict)
        {
            conditions.Add("Verdict = @verdict");
            parameters.Add(new("@verdict", (int)verdict));
        }

        var whereSql = conditions.Count == 0 ? string.Empty : "WHERE " + string.Join(" AND ", conditions);

        await using var connection = await _connections.OpenAsync(cancellationToken);

        int total;
        await using (var count = connection.CreateCommand())
        {
            count.CommandText = $"SELECT COUNT(*) FROM Threats {whereSql}";
            count.AddParameters(parameters);
            total = Convert.ToInt32(await count.ExecuteScalarAsync(cancellationToken), System.Globalization.CultureInfo.InvariantCulture);
        }

        var pageParameters = new List<KeyValuePair<string, object?>>(parameters)
        {
            new("@take", take),
            new("@skip", skip)
        };

        var rows = await SelectThreatsAsync(
            connection,
            $"{whereSql} ORDER BY DetectedAtUtc DESC, ThreatId LIMIT @take OFFSET @skip",
            pageParameters,
            cancellationToken);

        var evidence = await LoadEvidenceAsync(connection, rows.Select(r => r.ThreatId).ToList(), cancellationToken);

        return new PagedResult<ThreatRecordDto>(rows.Select(r => ToDto(r, evidence)).ToList(), total);
    }

    /// <inheritdoc />
    public async Task<bool> UpdateStatusAsync(Guid threatId, ThreatStatus newStatus, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connections.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();

        command.CommandText = "UPDATE Threats SET Status = @status, UpdatedAtUtc = @now WHERE ThreatId = @id";
        command.AddParameter("@status", (int)newStatus);
        command.AddParameter("@now", SqlValues.ToDb(_time.GetUtcNow()));
        command.AddParameter("@id", SqlValues.ToDb(threatId));

        return await command.ExecuteNonQueryAsync(cancellationToken) > 0;
    }

    /// <inheritdoc />
    public async Task<bool> AddEvidenceAsync(Guid threatId, ThreatEvidenceDto evidence, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(evidence);

        await using var connection = await _connections.OpenAsync(cancellationToken);
        await using var transaction = (SqliteTransaction)await connection.BeginTransactionAsync(cancellationToken);

        await using (var exists = connection.CreateCommand())
        {
            exists.Transaction = transaction;
            exists.CommandText = "SELECT 1 FROM Threats WHERE ThreatId = @id";
            exists.AddParameter("@id", SqlValues.ToDb(threatId));

            if (await exists.ExecuteScalarAsync(cancellationToken) is null)
            {
                return false;
            }
        }

        await InsertEvidenceAsync(connection, transaction, threatId, evidence, cancellationToken);

        await using (var touch = connection.CreateCommand())
        {
            touch.Transaction = transaction;
            touch.CommandText = "UPDATE Threats SET UpdatedAtUtc = @now WHERE ThreatId = @id";
            touch.AddParameter("@now", SqlValues.ToDb(_time.GetUtcNow()));
            touch.AddParameter("@id", SqlValues.ToDb(threatId));
            await touch.ExecuteNonQueryAsync(cancellationToken);
        }

        await transaction.CommitAsync(cancellationToken);
        return true;
    }

    /// <inheritdoc />
    public async Task<int> PurgeClosedOlderThanAsync(DateTimeOffset cutoffUtc, CancellationToken cancellationToken = default)
    {
        await using var connection = await _connections.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();

        command.CommandText = "DELETE FROM Threats WHERE Status IN (@dismissed, @resolved) AND UpdatedAtUtc < @cutoff";
        command.AddParameter("@dismissed", (int)ThreatStatus.Dismissed);
        command.AddParameter("@resolved", (int)ThreatStatus.Resolved);
        command.AddParameter("@cutoff", SqlValues.ToDb(cutoffUtc));

        return await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task InsertEvidenceAsync(
        SqliteConnection connection,
        SqliteTransaction transaction,
        Guid threatId,
        ThreatEvidenceDto evidence,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO ThreatEvidence (EvidenceId, ThreatId, ObservedAtUtc, Kind, Description, MetadataJson)
            VALUES (@evidenceId, @threatId, @observed, @kind, @description, @metadata)
            ON CONFLICT(EvidenceId) DO NOTHING
            """;
        command.AddParameter("@evidenceId", SqlValues.ToDb(evidence.EvidenceId));
        command.AddParameter("@threatId", SqlValues.ToDb(threatId));
        command.AddParameter("@observed", SqlValues.ToDb(evidence.ObservedAtUtc));
        command.AddParameter("@kind", evidence.Kind);
        command.AddParameter("@description", evidence.Description);
        command.AddParameter("@metadata", JsonSerializer.Serialize(evidence.Metadata));
        await command.ExecuteNonQueryAsync(cancellationToken);
    }

    private static async Task<List<ThreatRow>> SelectThreatsAsync(
        SqliteConnection connection,
        string sqlSuffix,
        IReadOnlyList<KeyValuePair<string, object?>> parameters,
        CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = $"""
            SELECT ThreatId, DetectedAtUtc, UpdatedAtUtc, DisplayName, Verdict, RiskScore, Status, DetectionSource, FilePath, Sha256
            FROM Threats {sqlSuffix}
            """;
        command.AddParameters(parameters);

        var rows = new List<ThreatRow>();

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            rows.Add(new ThreatRow(
                SqlValues.GuidFromDb(reader.GetString(0)),
                SqlValues.FromDb(reader.GetString(1)),
                SqlValues.FromDb(reader.GetString(2)),
                reader.GetString(3),
                (ThreatVerdict)reader.GetInt32(4),
                reader.GetInt32(5),
                (ThreatStatus)reader.GetInt32(6),
                reader.GetString(7),
                reader.IsDBNull(8) ? null : reader.GetString(8),
                reader.IsDBNull(9) ? null : reader.GetString(9)));
        }

        return rows;
    }

    private static async Task<Dictionary<Guid, List<ThreatEvidenceDto>>> LoadEvidenceAsync(
        SqliteConnection connection,
        IReadOnlyList<Guid> threatIds,
        CancellationToken cancellationToken)
    {
        var result = new Dictionary<Guid, List<ThreatEvidenceDto>>();

        if (threatIds.Count == 0)
        {
            return result;
        }

        await using var command = connection.CreateCommand();

        var names = new List<string>();
        for (var i = 0; i < threatIds.Count; i++)
        {
            var name = "@t" + i.ToString(System.Globalization.CultureInfo.InvariantCulture);
            names.Add(name);
            command.AddParameter(name, SqlValues.ToDb(threatIds[i]));
        }

        var inList = string.Join(", ", names);

        command.CommandText = $"""
            SELECT ThreatId, EvidenceId, ObservedAtUtc, Kind, Description, MetadataJson
            FROM ThreatEvidence
            WHERE ThreatId IN ({inList})
            ORDER BY ObservedAtUtc, EvidenceId
            """;

        await using var reader = await command.ExecuteReaderAsync(cancellationToken);
        while (await reader.ReadAsync(cancellationToken))
        {
            var threatId = SqlValues.GuidFromDb(reader.GetString(0));
            var metadata = JsonSerializer.Deserialize<Dictionary<string, string>>(reader.GetString(5))
                ?? new Dictionary<string, string>();

            var dto = new ThreatEvidenceDto(
                SqlValues.GuidFromDb(reader.GetString(1)),
                SqlValues.FromDb(reader.GetString(2)),
                reader.GetString(3),
                reader.GetString(4),
                metadata);

            if (!result.TryGetValue(threatId, out var list))
            {
                list = [];
                result[threatId] = list;
            }

            list.Add(dto);
        }

        return result;
    }

    private static ThreatRecordDto ToDto(ThreatRow row, Dictionary<Guid, List<ThreatEvidenceDto>> evidence) =>
        new(
            row.ThreatId,
            row.DetectedAtUtc,
            row.UpdatedAtUtc,
            row.DisplayName,
            row.Verdict,
            row.RiskScore,
            row.Status,
            row.DetectionSource,
            row.FilePath,
            row.Sha256,
            evidence.TryGetValue(row.ThreatId, out var items) ? items : []);

    private sealed record ThreatRow(
        Guid ThreatId,
        DateTimeOffset DetectedAtUtc,
        DateTimeOffset UpdatedAtUtc,
        string DisplayName,
        ThreatVerdict Verdict,
        int RiskScore,
        ThreatStatus Status,
        string DetectionSource,
        string? FilePath,
        string? Sha256);
}
