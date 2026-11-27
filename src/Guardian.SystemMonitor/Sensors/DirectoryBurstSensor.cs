using Guardian.SystemMonitor.Detection;
using Guardian.SystemMonitor.Events;
using Microsoft.Extensions.Logging;

namespace Guardian.SystemMonitor.Sensors;

/// <summary>
/// Capteur passif reposant sur <see cref="FileSystemWatcher"/> pour repérer les rafales d'opérations fichiers
/// sur des répertoires configurés, sans jamais lire le contenu ni les frappes utilisateur.
/// </summary>
public sealed class DirectoryBurstSensor : IDisposable
{
    private readonly FileBurstDetector _burstDetector;
    private readonly BoundedSystemEventStore _eventStore;
    private readonly ILogger _logger;
    private readonly object _gate = new();
    private readonly List<FileSystemWatcher> _watchers = [];
    private bool _disposed;

    /// <summary>
    /// Initialise le capteur de rafales sur répertoires.
    /// </summary>
    /// <param name="burstDetector">Détecteur à fenêtre glissante.</param>
    /// <param name="eventStore">Magasin borné recevant les événements détectés.</param>
    /// <param name="logger">Journaliseur structuré.</param>
    public DirectoryBurstSensor(
        FileBurstDetector burstDetector,
        BoundedSystemEventStore eventStore,
        ILogger logger)
    {
        _burstDetector = burstDetector ?? throw new ArgumentNullException(nameof(burstDetector));
        _eventStore = eventStore ?? throw new ArgumentNullException(nameof(eventStore));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <summary>
    /// Nombre de répertoires actuellement surveillés.
    /// </summary>
    public int ActiveWatcherCount
    {
        get
        {
            lock (_gate)
            {
                return _watchers.Count;
            }
        }
    }

    /// <summary>
    /// Démarre la surveillance des répertoires valides et accessibles fournis.
    /// </summary>
    /// <param name="directories">Liste des chemins de répertoires à surveiller.</param>
    public void Start(IEnumerable<string> directories)
    {
        ArgumentNullException.ThrowIfNull(directories);

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            StopWatchersUnsafe();

            foreach (var rawDir in directories.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                if (string.IsNullOrWhiteSpace(rawDir))
                {
                    continue;
                }

                try
                {
                    var fullPath = Path.GetFullPath(rawDir);
                    if (!Directory.Exists(fullPath))
                    {
                        continue;
                    }

                    var watcher = new FileSystemWatcher(fullPath)
                    {
                        IncludeSubdirectories = true,
                        InternalBufferSize = 32_768,
                        NotifyFilter = NotifyFilters.FileName
                            | NotifyFilters.DirectoryName
                            | NotifyFilters.LastWrite
                            | NotifyFilters.Size
                    };

                    watcher.Created += (_, _) => HandleOperation(fullPath, "Created");
                    watcher.Changed += (_, _) => HandleOperation(fullPath, "Changed");
                    watcher.Renamed += (_, _) => HandleOperation(fullPath, "Renamed");
                    watcher.Deleted += (_, _) => HandleOperation(fullPath, "Deleted");
                    watcher.Error += (_, e) => _logger.LogDebug(e.GetException(), "FileSystemWatcher error on '{Directory}'.", fullPath);

                    watcher.EnableRaisingEvents = true;
                    _watchers.Add(watcher);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException or ArgumentException)
                {
                    _logger.LogWarning(ex, "Unable to watch directory '{Directory}' for file bursts.", rawDir);
                }
            }
        }
    }

    /// <summary>
    /// Arrête tous les observateurs actifs sans jeter d'exception.
    /// </summary>
    public void Stop()
    {
        lock (_gate)
        {
            StopWatchersUnsafe();
        }
    }

    /// <inheritdoc />
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            StopWatchersUnsafe();
        }
    }

    private void HandleOperation(string rootDirectory, string operationKind)
    {
        var evt = _burstDetector.RecordFileOperation(rootDirectory, operationKind);
        if (evt is not null)
        {
            _eventStore.Publish(evt);
        }
    }

    private void StopWatchersUnsafe()
    {
        foreach (var watcher in _watchers)
        {
            try
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }
            catch
            {
                // Ignorer les erreurs lors de la libération.
            }
        }

        _watchers.Clear();
    }
}
