using System.Collections.Concurrent;
using Guardian.Contracts.AI;
using Guardian.Contracts.AI.Models;

namespace Guardian.AI.Correlation;

/// <summary>
/// Service de mémoire locale des indicateurs de compromission et profils d'incidents (IThreatMemoryService).
/// Conserve les relations temporelles sans stocker de données personnelles ni de frappes clavier.
/// </summary>
public sealed class ThreatMemoryService : IThreatMemoryService
{
    private readonly ConcurrentBag<SecuritySignal> _signals = [];
    private readonly ConcurrentDictionary<string, ThreatGraph> _incidentGraphs = new(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc />
    public Task RecordSignalAsync(SecuritySignal signal, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Règle stricte de confidentialité : filtrer toute métadonnée sensible avant enregistrement
        var sanitizedMetadata = new Dictionary<string, string>();
        foreach (var (key, value) in signal.Metadata)
        {
            if (!IsSensitiveKey(key))
            {
                sanitizedMetadata[key] = value;
            }
        }

        var sanitizedSignal = signal with { Metadata = sanitizedMetadata };
        _signals.Add(sanitizedSignal);

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RecordIncidentGraphAsync(ThreatGraph graph, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _incidentGraphs[graph.IncidentId] = graph;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<SecuritySignal>> GetSignalsForEntityAsync(
        string entityId, 
        TimeSpan window, 
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        DateTime cutoff = DateTime.UtcNow - window;
        var results = _signals
            .Where(s => s.EntityId.Equals(entityId, StringComparison.OrdinalIgnoreCase) && s.TimestampUtc >= cutoff)
            .OrderByDescending(s => s.TimestampUtc)
            .ToList();

        return Task.FromResult<IReadOnlyList<SecuritySignal>>(results);
    }

    /// <inheritdoc />
    public Task<bool> HasRecentSuspiciousHistoryAsync(
        string entityId, 
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        DateTime cutoff = DateTime.UtcNow - TimeSpan.FromHours(24);
        bool hasSuspicious = _signals.Any(s =>
            s.EntityId.Equals(entityId, StringComparison.OrdinalIgnoreCase) &&
            s.TimestampUtc >= cutoff &&
            (s.Severity == SignalSeverity.High || s.Severity == SignalSeverity.Critical));

        return Task.FromResult(hasSuspicious);
    }

    /// <inheritdoc />
    public Task PurgeExpiredSignalsAsync(TimeSpan maxAge, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        DateTime cutoff = DateTime.UtcNow - maxAge;
        var validSignals = _signals.Where(s => s.TimestampUtc >= cutoff).ToList();

        _signals.Clear();
        foreach (var s in validSignals)
        {
            _signals.Add(s);
        }

        return Task.CompletedTask;
    }

    private static bool IsSensitiveKey(string key)
    {
        string lower = key.ToLowerInvariant();
        return lower.Contains("password") ||
               lower.Contains("secret") ||
               lower.Contains("token") ||
               lower.Contains("credential") ||
               lower.Contains("keystroke") ||
               lower.Contains("auth");
    }
}
