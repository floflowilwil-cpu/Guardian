using Guardian.Contracts.Common;
using Guardian.Contracts.Memory;
using Guardian.Contracts.System;

namespace Guardian.SystemMonitor.Detection;

/// <summary>
/// Détecteur différentiel de création de processus, filiations suspectes, modules chargés anormaux
/// et métadonnées mémoire défensives sans aucune capture d'entrée ni lecture de secrets.
/// </summary>
public sealed class ProcessActivityTracker
{
    private static readonly HashSet<string> OfficeAndDocumentParents = new(StringComparer.OrdinalIgnoreCase)
    {
        "winword",
        "excel",
        "powerpnt",
        "outlook",
        "onenote",
        "acrord32",
        "acrobat",
        "chrome",
        "msedge",
        "firefox"
    };

    private static readonly HashSet<string> ScriptAndLivingOffTheLandChildren = new(StringComparer.OrdinalIgnoreCase)
    {
        "powershell",
        "pwsh",
        "cmd",
        "wscript",
        "cscript",
        "mshta",
        "rundll32",
        "regsvr32",
        "certutil",
        "bitsadmin"
    };

    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _alertCooldown;
    private readonly object _gate = new();

    private bool _hasBaseline;
    private Dictionary<int, ProcessSnapshot> _knownProcesses = new();
    private readonly Dictionary<(int ProcessId, MemorySignalKind Kind), DateTimeOffset> _memoryCooldowns = new();
    private readonly Dictionary<(int ProcessId, string ModulePath), DateTimeOffset> _moduleCooldowns = new();

    /// <summary>
    /// Initialise le traceur d'activité processus et mémoire.
    /// </summary>
    /// <param name="timeProvider">Horloge injectée.</param>
    /// <param name="memoryAlertCooldownMinutes">Durée de déduplication des signaux répétitifs en minutes.</param>
    public ProcessActivityTracker(TimeProvider timeProvider, int memoryAlertCooldownMinutes = 5)
    {
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        ArgumentOutOfRangeException.ThrowIfLessThan(memoryAlertCooldownMinutes, 1);
        _alertCooldown = TimeSpan.FromMinutes(memoryAlertCooldownMinutes);
    }

    /// <summary>
    /// Compare l'instantané courant des processus à la référence précédente et produit les événements défensifs.
    /// </summary>
    /// <param name="currentProcesses">Liste des processus observés.</param>
    /// <returns>Événements générés (vide lors de la capture initiale de référence).</returns>
    public IReadOnlyList<SystemSecurityEventDto> EvaluateProcessSnapshot(IReadOnlyList<ProcessInfoDto> currentProcesses)
    {
        ArgumentNullException.ThrowIfNull(currentProcesses);

        var now = _timeProvider.GetUtcNow();
        var currentByPid = new Dictionary<int, ProcessInfoDto>(currentProcesses.Count);
        foreach (var proc in currentProcesses)
        {
            currentByPid.TryAdd(proc.ProcessId, proc);
        }

        lock (_gate)
        {
            PruneExpiredCooldowns(now);

            if (!_hasBaseline)
            {
                _knownProcesses = BuildSnapshotDictionary(currentByPid);
                _hasBaseline = true;
                return [];
            }

            var events = new List<SystemSecurityEventDto>();

            foreach (var proc in currentProcesses)
            {
                var isNewProcess = !_knownProcesses.TryGetValue(proc.ProcessId, out var prev) ||
                    !string.Equals(prev.ProcessName, proc.ProcessName, StringComparison.OrdinalIgnoreCase);

                if (isNewProcess)
                {
                    events.Add(BuildProcessCreationEvent(proc, currentByPid, now));
                }

                if (proc.Modules is { Count: > 0 })
                {
                    foreach (var module in proc.Modules)
                    {
                        if (!IsSuspiciousTempOrPublicPath(module.FilePath))
                        {
                            continue;
                        }

                        var moduleKey = (proc.ProcessId, module.FilePath ?? module.ModuleName);
                        if (_moduleCooldowns.TryGetValue(moduleKey, out var blockedUntil) && now < blockedUntil)
                        {
                            continue;
                        }

                        _moduleCooldowns[moduleKey] = now + _alertCooldown;

                        events.Add(new SystemSecurityEventDto(
                            EventId: Guid.NewGuid(),
                            TimestampUtc: now,
                            Category: SystemEventCategory.InterProcessAccess,
                            Severity: EventSeverity.High,
                            Source: "Guardian.SystemMonitor.ProcessTracker",
                            ProcessId: proc.ProcessId,
                            ProcessName: proc.ProcessName,
                            Target: module.FilePath ?? module.ModuleName,
                            Summary: $"Module chargé depuis un emplacement temporaire ou public dans '{proc.ProcessName}' ({module.ModuleName}).",
                            Metadata: new Dictionary<string, string>
                            {
                                ["moduleName"] = module.ModuleName,
                                ["isSigned"] = module.IsSigned?.ToString() ?? "Unknown"
                            }));
                    }
                }
            }

            _knownProcesses = BuildSnapshotDictionary(currentByPid);
            return events;
        }
    }

    /// <summary>
    /// Transforme les rapports d'analyse mémoire défensive en événements comportementaux dédupliqués,
    /// en excluant strictement tout processus protégé ignoré (ex. <c>lsass</c>).
    /// </summary>
    /// <param name="reports">Rapports produits par <see cref="IMemoryAnalyzer"/>.</param>
    /// <returns>Liste des événements comportementaux relevés.</returns>
    public IReadOnlyList<SystemSecurityEventDto> EvaluateMemoryReports(IReadOnlyList<MemoryAnalysisReportDto> reports)
    {
        ArgumentNullException.ThrowIfNull(reports);

        var now = _timeProvider.GetUtcNow();
        var events = new List<SystemSecurityEventDto>();

        lock (_gate)
        {
            PruneExpiredCooldowns(now);

            foreach (var report in reports)
            {
                foreach (var signal in report.Signals)
                {
                    if (signal.Kind == MemorySignalKind.ProtectedProcessSkipped)
                    {
                        continue;
                    }

                    var key = (report.ProcessId, signal.Kind);
                    if (_memoryCooldowns.TryGetValue(key, out var blockedUntil) && now < blockedUntil)
                    {
                        continue;
                    }

                    _memoryCooldowns[key] = now + _alertCooldown;

                    var severity = signal.Kind is MemorySignalKind.ReadWriteExecuteRegion
                        or MemorySignalKind.UnbackedExecutableRegion
                        or MemorySignalKind.SuspiciousHookIndicator
                        ? EventSeverity.High
                        : EventSeverity.Medium;

                    events.Add(new SystemSecurityEventDto(
                        EventId: Guid.NewGuid(),
                        TimestampUtc: now,
                        Category: SystemEventCategory.InterProcessAccess,
                        Severity: severity,
                        Source: "Guardian.SystemMonitor.MemoryAnalyzer",
                        ProcessId: report.ProcessId,
                        ProcessName: report.ProcessName,
                        Target: $"0x{signal.BaseAddress:X}",
                        Summary: $"{signal.Kind} détecté dans '{report.ProcessName}' (PID {report.ProcessId}) : {signal.Description}",
                        Metadata: new Dictionary<string, string>
                        {
                            ["signalKind"] = signal.Kind.ToString(),
                            ["regionSizeBytes"] = signal.RegionSizeBytes.ToString()
                        }));
                }
            }
        }

        return events;
    }

    /// <summary>
    /// Indique si un chemin binaire pointe vers un répertoire utilisateur temporaire ou public fréquemment exploité.
    /// </summary>
    /// <param name="path">Chemin du fichier exécutable ou module.</param>
    /// <returns><see langword="true"/> si le chemin se situe dans un dossier temporaire ou public.</returns>
    public static bool IsSuspiciousTempOrPublicPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var normalized = path.Replace('/', '\\');
        return normalized.Contains(@"\appdata\local\temp\", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains(@"\users\public\", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains(@"\windows\temp\", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains(@"\tmp\", StringComparison.OrdinalIgnoreCase);
    }

    private SystemSecurityEventDto BuildProcessCreationEvent(
        ProcessInfoDto proc,
        Dictionary<int, ProcessInfoDto> currentByPid,
        DateTimeOffset now)
    {
        string? parentName = null;
        if (proc.ParentProcessId is { } parentPid)
        {
            if (currentByPid.TryGetValue(parentPid, out var liveParent))
            {
                parentName = liveParent.ProcessName;
            }
            else if (_knownProcesses.TryGetValue(parentPid, out var prevParent))
            {
                parentName = prevParent.ProcessName;
            }
        }

        var childBase = NormalizeProcessName(proc.ProcessName);
        var parentBase = NormalizeProcessName(parentName);
        var isSuspiciousSpawn = parentBase is not null
            && OfficeAndDocumentParents.Contains(parentBase)
            && ScriptAndLivingOffTheLandChildren.Contains(childBase);

        var isTempBinary = IsSuspiciousTempOrPublicPath(proc.ExecutablePath);

        var severity = isSuspiciousSpawn
            ? EventSeverity.High
            : isTempBinary
                ? EventSeverity.Medium
                : EventSeverity.Info;

        var summary = isSuspiciousSpawn
            ? $"Enchaînement parent/enfant suspect : '{parentName}' (PID {proc.ParentProcessId}) a lancé '{proc.ProcessName}' (PID {proc.ProcessId})."
            : isTempBinary
                ? $"Exécutable lancé depuis un dossier temporaire ou public : '{proc.ProcessName}' ({proc.ExecutablePath})."
                : $"Nouveau processus observé : '{proc.ProcessName}' (PID {proc.ProcessId}).";

        var metadata = new Dictionary<string, string>
        {
            ["sessionId"] = proc.SessionId.ToString(),
            ["accessStatus"] = proc.AccessStatus.ToString()
        };

        if (proc.ParentProcessId is { } ppid)
        {
            metadata["parentPid"] = ppid.ToString();
        }

        if (!string.IsNullOrWhiteSpace(parentName))
        {
            metadata["parentProcess"] = parentName;
        }

        return new SystemSecurityEventDto(
            EventId: Guid.NewGuid(),
            TimestampUtc: now,
            Category: SystemEventCategory.ProcessLifecycle,
            Severity: severity,
            Source: "Guardian.SystemMonitor.ProcessTracker",
            ProcessId: proc.ProcessId,
            ProcessName: proc.ProcessName,
            Target: proc.ExecutablePath,
            Summary: summary,
            Metadata: metadata);
    }

    private void PruneExpiredCooldowns(DateTimeOffset now)
    {
        foreach (var key in _memoryCooldowns.Where(p => now >= p.Value).Select(p => p.Key).ToArray())
        {
            _memoryCooldowns.Remove(key);
        }

        foreach (var key in _moduleCooldowns.Where(p => now >= p.Value).Select(p => p.Key).ToArray())
        {
            _moduleCooldowns.Remove(key);
        }
    }

    private static Dictionary<int, ProcessSnapshot> BuildSnapshotDictionary(Dictionary<int, ProcessInfoDto> source)
    {
        var result = new Dictionary<int, ProcessSnapshot>(source.Count);
        foreach (var pair in source)
        {
            result[pair.Key] = new ProcessSnapshot(pair.Value.ProcessName, pair.Value.ExecutablePath);
        }

        return result;
    }

    private static string NormalizeProcessName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return string.Empty;
        }

        var trimmed = name.Trim();
        return trimmed.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? trimmed[..^4]
            : trimmed;
    }

    private sealed record ProcessSnapshot(string ProcessName, string? ExecutablePath);
}
