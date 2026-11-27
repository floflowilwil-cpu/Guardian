using Guardian.Contracts.Common;
using Guardian.Contracts.System;

namespace Guardian.SystemMonitor.Detection;

/// <summary>
/// Détecteur à fenêtre glissante des rafales inhabituelles d'opérations sur fichiers (comportement de type chiffrement massif / ransomware),
/// sans aucune lecture de contenu de fichier.
/// </summary>
public sealed class FileBurstDetector
{
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _window;
    private readonly int _threshold;
    private readonly TimeSpan _cooldown;
    private readonly object _gate = new();

    private readonly Dictionary<string, Queue<DateTimeOffset>> _timestampsByDirectory =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly Dictionary<string, DateTimeOffset> _cooldownUntilByDirectory =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Initialise le détecteur de rafales d'opérations fichiers.
    /// </summary>
    /// <param name="timeProvider">Horloge injectée.</param>
    /// <param name="windowSeconds">Largeur de la fenêtre glissante en secondes.</param>
    /// <param name="threshold">Nombre minimal d'opérations dans la fenêtre pour alerter.</param>
    /// <param name="cooldownSeconds">Délai de réarmement par répertoire en secondes.</param>
    public FileBurstDetector(
        TimeProvider timeProvider,
        int windowSeconds = 10,
        int threshold = 25,
        int cooldownSeconds = 30)
    {
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        ArgumentOutOfRangeException.ThrowIfLessThan(windowSeconds, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(threshold, 2);
        ArgumentOutOfRangeException.ThrowIfLessThan(cooldownSeconds, 1);

        _window = TimeSpan.FromSeconds(windowSeconds);
        _threshold = threshold;
        _cooldown = TimeSpan.FromSeconds(cooldownSeconds);
    }

    /// <summary>
    /// Enregistre une opération observée sur un répertoire (horodatage uniquement) et émet une alerte si le seuil est atteint.
    /// </summary>
    /// <param name="directoryPath">Répertoire concerné.</param>
    /// <param name="operationKind">Type d'opération (<c>Created</c>, <c>Changed</c>, <c>Renamed</c>, <c>Deleted</c>).</param>
    /// <returns>Un événement <see cref="SystemEventCategory.FileBurstAnomaly"/> si le seuil est atteint hors période de refroidissement, sinon <see langword="null"/>.</returns>
    public SystemSecurityEventDto? RecordFileOperation(string directoryPath, string operationKind)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directoryPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(operationKind);

        var now = _timeProvider.GetUtcNow();
        var normalizedDir = NormalizeDirectoryKey(directoryPath);
        var cutoff = now - _window;

        lock (_gate)
        {
            if (!_timestampsByDirectory.TryGetValue(normalizedDir, out var queue))
            {
                queue = new Queue<DateTimeOffset>();
                _timestampsByDirectory[normalizedDir] = queue;
            }

            while (queue.Count > 0 && queue.Peek() < cutoff)
            {
                queue.Dequeue();
            }

            queue.Enqueue(now);

            if (queue.Count < _threshold)
            {
                return null;
            }

            if (_cooldownUntilByDirectory.TryGetValue(normalizedDir, out var blockedUntil) && now < blockedUntil)
            {
                return null;
            }

            _cooldownUntilByDirectory[normalizedDir] = now + _cooldown;

            return new SystemSecurityEventDto(
                EventId: Guid.NewGuid(),
                TimestampUtc: now,
                Category: SystemEventCategory.FileBurstAnomaly,
                Severity: EventSeverity.High,
                Source: "Guardian.SystemMonitor.FileBurstDetector",
                ProcessId: null,
                ProcessName: null,
                Target: normalizedDir,
                Summary: $"Rafale inhabituelle détectée dans '{normalizedDir}' : {queue.Count} opérations ({operationKind}) en {(int)_window.TotalSeconds} s.",
                Metadata: new Dictionary<string, string>
                {
                    ["operationKind"] = operationKind,
                    ["eventCountInWindow"] = queue.Count.ToString(),
                    ["windowSeconds"] = ((int)_window.TotalSeconds).ToString()
                });
        }
    }

    private static string NormalizeDirectoryKey(string directoryPath)
    {
        try
        {
            return Path.GetFullPath(directoryPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        }
        catch (Exception)
        {
            return directoryPath.Trim();
        }
    }
}
