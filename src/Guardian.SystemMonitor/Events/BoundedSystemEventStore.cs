using System.Collections.ObjectModel;
using Guardian.Contracts.System;
using Guardian.SystemMonitor.Configuration;
using Microsoft.Extensions.Options;

namespace Guardian.SystemMonitor.Events;

/// <summary>
/// Tampon circulaire thread-safe conservant les événements système récents tout en filtrant toute clé sensible.
/// </summary>
public sealed class BoundedSystemEventStore
{
    private const int MaxMetadataValueLength = 512;

    private static readonly string[] ForbiddenMetadataFragments =
    [
        "password",
        "secret",
        "privatekey",
        "keystroke",
        "token"
    ];

    private readonly object _gate = new();
    private readonly Queue<SystemSecurityEventDto> _events = new();
    private readonly int _capacity;

    /// <summary>
    /// Initialise le tampon borné d'événements avec les options validées du moniteur système.
    /// </summary>
    /// <param name="options">Options de configuration du moniteur système.</param>
    public BoundedSystemEventStore(IOptions<SystemMonitorOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _capacity = Math.Clamp(options.Value.MaxRetainedEvents, 10, 10_000);
    }

    /// <summary>
    /// Initialise le tampon borné avec une capacité explicite (utile pour les tests unitaires).
    /// </summary>
    /// <param name="capacity">Nombre maximal d'événements conservés en mémoire.</param>
    public BoundedSystemEventStore(int capacity)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        _capacity = capacity;
    }

    /// <summary>
    /// Événement déclenché dès qu'un événement système aseptisé est enregistré.
    /// </summary>
    public event EventHandler<SystemSecurityEventDto>? EventDetected;

    /// <summary>
    /// Aseptise les métadonnées, stocke l'événement dans le tampon borné et notifie les abonnés hors verrou.
    /// </summary>
    /// <param name="systemEvent">Événement de sécurité détecté.</param>
    /// <returns>L'événement normalisé tel que stocké et publié.</returns>
    public SystemSecurityEventDto Publish(SystemSecurityEventDto systemEvent)
    {
        ArgumentNullException.ThrowIfNull(systemEvent);

        var sanitized = systemEvent with
        {
            Metadata = SanitizeMetadata(systemEvent.Metadata)
        };

        lock (_gate)
        {
            _events.Enqueue(sanitized);
            while (_events.Count > _capacity)
            {
                _events.Dequeue();
            }
        }

        NotifySubscribers(sanitized);
        return sanitized;
    }

    /// <summary>
    /// Retourne les événements les plus récents du tampon, ordonnés du plus récent au plus ancien.
    /// </summary>
    /// <param name="maxCount">Nombre maximal d'événements souhaité.</param>
    /// <returns>Liste ordonnée et bornée des événements récents.</returns>
    public IReadOnlyList<SystemSecurityEventDto> GetRecent(int maxCount = 100)
    {
        var limit = Math.Clamp(maxCount, 1, _capacity);

        lock (_gate)
        {
            return _events
                .Reverse()
                .Take(limit)
                .ToArray();
        }
    }

    /// <summary>
    /// Retourne le nombre actuel d'événements retenus dans le tampon.
    /// </summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _events.Count;
            }
        }
    }

    private void NotifySubscribers(SystemSecurityEventDto sanitized)
    {
        var handler = EventDetected;
        if (handler is null)
        {
            return;
        }

        foreach (var subscriber in handler.GetInvocationList().Cast<EventHandler<SystemSecurityEventDto>>())
        {
            try
            {
                subscriber(this, sanitized);
            }
            catch
            {
                // Un abonné défaillant ne doit jamais interrompre les autres consommateurs ni la boucle de surveillance.
            }
        }
    }

    private static IReadOnlyDictionary<string, string> SanitizeMetadata(IReadOnlyDictionary<string, string>? metadata)
    {
        if (metadata is null || metadata.Count == 0)
        {
            return ReadOnlyDictionary<string, string>.Empty;
        }

        var safe = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in metadata)
        {
            if (string.IsNullOrWhiteSpace(pair.Key) || IsForbiddenKey(pair.Key))
            {
                continue;
            }

            var value = pair.Value ?? string.Empty;
            if (value.Length > MaxMetadataValueLength)
            {
                value = value[..MaxMetadataValueLength];
            }

            safe[pair.Key] = value;
        }

        return new ReadOnlyDictionary<string, string>(safe);
    }

    private static bool IsForbiddenKey(string key)
    {
        foreach (var fragment in ForbiddenMetadataFragments)
        {
            if (key.Contains(fragment, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }
}
