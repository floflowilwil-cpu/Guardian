using Guardian.Contracts.Common;
using Guardian.Contracts.System;

namespace Guardian.SystemMonitor.Detection;

/// <summary>
/// Détecteur différentiel des changements sur les points de démarrage, clés registre critiques,
/// tâches planifiées et services Windows.
/// </summary>
public sealed class PersistenceChangeTracker
{
    private readonly TimeProvider _timeProvider;
    private readonly object _gate = new();

    private bool _hasStartupBaseline;
    private Dictionary<string, StartupEntryDto> _knownStartup = new(StringComparer.OrdinalIgnoreCase);

    private bool _hasServiceBaseline;
    private Dictionary<string, WindowsServiceInfoDto> _knownServices = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Initialise le traceur de mécanismes de persistance.
    /// </summary>
    /// <param name="timeProvider">Horloge injectée.</param>
    public PersistenceChangeTracker(TimeProvider timeProvider)
    {
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    /// <summary>
    /// Compare l'inventaire courant des entrées de démarrage et tâches planifiées au précédent.
    /// </summary>
    /// <param name="entries">Entrées de persistance observables.</param>
    /// <returns>Événements générés (vide lors de la capture initiale de référence).</returns>
    public IReadOnlyList<SystemSecurityEventDto> EvaluateStartupEntries(IReadOnlyList<StartupEntryDto> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);

        var now = _timeProvider.GetUtcNow();
        var current = new Dictionary<string, StartupEntryDto>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in entries)
        {
            current[BuildStartupKey(entry)] = entry;
        }

        lock (_gate)
        {
            if (!_hasStartupBaseline)
            {
                _knownStartup = current;
                _hasStartupBaseline = true;
                return [];
            }

            var events = new List<SystemSecurityEventDto>();

            foreach (var pair in current)
            {
                var entry = pair.Value;
                if (!_knownStartup.TryGetValue(pair.Key, out var previous))
                {
                    events.Add(BuildStartupEvent(entry, "ajoutée", GetStartupModificationSeverity(entry.Kind), now));
                }
                else if (!string.Equals(previous.CommandOrPath, entry.CommandOrPath, StringComparison.OrdinalIgnoreCase))
                {
                    events.Add(BuildStartupEvent(entry, "modifiée", GetStartupModificationSeverity(entry.Kind), now));
                }
            }

            foreach (var pair in _knownStartup)
            {
                if (!current.ContainsKey(pair.Key))
                {
                    events.Add(BuildStartupEvent(pair.Value, "supprimée", EventSeverity.Low, now));
                }
            }

            _knownStartup = current;
            return events;
        }
    }

    /// <summary>
    /// Compare l'inventaire courant des services Windows au précédent.
    /// </summary>
    /// <param name="services">Services Windows inventoriés.</param>
    /// <returns>Événements générés (vide lors de la capture initiale de référence).</returns>
    public IReadOnlyList<SystemSecurityEventDto> EvaluateServices(IReadOnlyList<WindowsServiceInfoDto> services)
    {
        ArgumentNullException.ThrowIfNull(services);

        var now = _timeProvider.GetUtcNow();
        var current = new Dictionary<string, WindowsServiceInfoDto>(StringComparer.OrdinalIgnoreCase);
        foreach (var service in services)
        {
            current[service.ServiceName] = service;
        }

        lock (_gate)
        {
            if (!_hasServiceBaseline)
            {
                _knownServices = current;
                _hasServiceBaseline = true;
                return [];
            }

            var events = new List<SystemSecurityEventDto>();

            foreach (var pair in current)
            {
                var service = pair.Value;
                if (!_knownServices.TryGetValue(pair.Key, out var previous))
                {
                    var severity = ProcessActivityTracker.IsSuspiciousTempOrPublicPath(service.BinaryPath)
                        ? EventSeverity.High
                        : EventSeverity.Medium;

                    events.Add(BuildServiceEvent(
                        service,
                        severity,
                        $"Nouveau service Windows enregistré : '{service.ServiceName}' ({service.StartMode}).",
                        now));
                }
                else if (!string.Equals(previous.BinaryPath, service.BinaryPath, StringComparison.OrdinalIgnoreCase))
                {
                    events.Add(BuildServiceEvent(
                        service,
                        EventSeverity.High,
                        $"Chemin binaire modifié pour le service Windows '{service.ServiceName}'.",
                        now));
                }
                else if (previous.StartMode != service.StartMode)
                {
                    events.Add(BuildServiceEvent(
                        service,
                        EventSeverity.Medium,
                        $"Mode de démarrage modifié pour le service '{service.ServiceName}' : {previous.StartMode} -> {service.StartMode}.",
                        now));
                }
            }

            _knownServices = current;
            return events;
        }
    }

    private static string BuildStartupKey(StartupEntryDto entry) =>
        $"{entry.Kind}|{entry.Scope}|{entry.Location}|{entry.Name}";

    private static SystemEventCategory MapStartupCategory(PersistenceEntryKind kind) =>
        kind is PersistenceEntryKind.RegistryRun
            or PersistenceEntryKind.RegistryRunOnce
            or PersistenceEntryKind.Winlogon
            or PersistenceEntryKind.ImageFileExecutionOptions
            ? SystemEventCategory.RegistryModification
            : SystemEventCategory.PersistenceChange;

    private static EventSeverity GetStartupModificationSeverity(PersistenceEntryKind kind) =>
        kind is PersistenceEntryKind.Winlogon or PersistenceEntryKind.ImageFileExecutionOptions
            ? EventSeverity.High
            : EventSeverity.Medium;

    private static SystemSecurityEventDto BuildStartupEvent(
        StartupEntryDto entry,
        string actionVerb,
        EventSeverity severity,
        DateTimeOffset now)
    {
        return new SystemSecurityEventDto(
            EventId: Guid.NewGuid(),
            TimestampUtc: now,
            Category: MapStartupCategory(entry.Kind),
            Severity: severity,
            Source: "Guardian.SystemMonitor.PersistenceTracker",
            ProcessId: null,
            ProcessName: null,
            Target: $"{entry.Location}\\{entry.Name}",
            Summary: $"Entrée de persistance ({entry.Kind}) {actionVerb} : {entry.Name} -> {entry.CommandOrPath}",
            Metadata: new Dictionary<string, string>
            {
                ["kind"] = entry.Kind.ToString(),
                ["scope"] = entry.Scope,
                ["command"] = entry.CommandOrPath
            });
    }

    private static SystemSecurityEventDto BuildServiceEvent(
        WindowsServiceInfoDto service,
        EventSeverity severity,
        string summary,
        DateTimeOffset now)
    {
        return new SystemSecurityEventDto(
            EventId: Guid.NewGuid(),
            TimestampUtc: now,
            Category: SystemEventCategory.PersistenceChange,
            Severity: severity,
            Source: "Guardian.SystemMonitor.PersistenceTracker",
            ProcessId: service.ProcessId,
            ProcessName: service.ServiceName,
            Target: service.BinaryPath ?? service.ServiceName,
            Summary: summary,
            Metadata: new Dictionary<string, string>
            {
                ["serviceName"] = service.ServiceName,
                ["startMode"] = service.StartMode.ToString(),
                ["state"] = service.State.ToString()
            });
    }
}
