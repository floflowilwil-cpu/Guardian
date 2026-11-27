using Guardian.Desktop.Infrastructure;

namespace Guardian.Desktop.Models;

/// <summary>États de santé affichés fidèlement par l'interface (doc technique §16).</summary>
public enum ProtectionState
{
    Unknown,
    Healthy,
    Degraded,
    Stopped,
    OutOfDate,
}

public enum RiskLevel
{
    Low,
    Medium,
    High,
}

public enum ScanKind
{
    Quick,
    Full,
    Custom,
}

public sealed record ScanProgress(
    int Percent,
    string CurrentPath,
    int FilesProcessed = 0,
    int FilesTotal = 0,
    int ThreatsFound = 0,
    int FilesSkipped = 0);

public sealed record EngineStatus(string Name, ProtectionState State);

public sealed record ThreatItem(
    Guid Id,
    string Name,
    RiskLevel Risk,
    DateTime DetectedAt,
    string Path,
    string Behavior);

public sealed class QuarantineItem : ObservableObject
{
    private bool _isChecked;

    public QuarantineItem(Guid id, string name, DateTime date, RiskLevel risk)
    {
        Id = id;
        Name = name;
        Date = date;
        Risk = risk;
    }

    public Guid Id { get; }

    public string Name { get; }

    public DateTime Date { get; }

    public RiskLevel Risk { get; }

    public string RiskLabel => Risk switch
    {
        RiskLevel.High => Loc.T("Élevé"),
        RiskLevel.Medium => Loc.T("Moyen"),
        _ => Loc.T("Faible"),
    };

    public bool IsChecked
    {
        get => _isChecked;
        set => Set(ref _isChecked, value);
    }
}

public sealed record NetworkDestination(string Name, int Percent, bool IsSafe);

public sealed class ChatMessage
{
    public ChatMessage(string text, bool fromUser)
    {
        Text = text;
        FromUser = fromUser;
    }

    public string Text { get; }

    public bool FromUser { get; }
}

/// <summary>Vue instantanée de l'état de Guardian, fournie par le service via IPC.</summary>
public sealed record GuardianSnapshot(
    ProtectionState State,
    bool AiEngineActive,
    bool DefinitionsUpToDate,
    bool RealtimeActive,
    IReadOnlyList<EngineStatus> Engines,
    IReadOnlyList<ThreatItem> Threats,
    int BlockedThreats,
    IReadOnlyList<QuarantineItem> Quarantine,
    int EventCount,
    int ActiveConnections,
    int SuspiciousConnections,
    IReadOnlyList<NetworkDestination> Destinations,
    DateTime? LastCheck)
{
    /// <summary>Snapshot utilisé tant que le service ne répond pas : aucune protection n'est affichée.</summary>
    public static GuardianSnapshot Unknown { get; } = new(
        ProtectionState.Unknown, false, false, false,
        Array.Empty<EngineStatus>(), Array.Empty<ThreatItem>(), 0,
        Array.Empty<QuarantineItem>(), 0, 0, 0,
        Array.Empty<NetworkDestination>(), null);
}
