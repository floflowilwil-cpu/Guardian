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

/// <summary>Couleur sémantique d'une ligne : statut d'une analyse, gravité d'un événement.</summary>
public enum StatusTone
{
    Neutral,
    Good,
    Warning,
    Bad,
}

/// <summary>Gravité d'un événement système (reprend l'échelle des contrats, sans en dépendre).</summary>
public enum EventLevel
{
    Info,
    Low,
    Medium,
    High,
    Critical,
}

public enum SecurityControlKind
{
    Defender,
    Firewall,
    Uac,
    SecureBoot,
    Tpm,
    VirtualizationSecurity,
    CredentialGuard,
    Lsass,
}

public enum PrivilegeKind
{
    Unknown,
    Standard,
    Administrator,
    System,
}

public enum SystemEventKind
{
    Process,
    Registry,
    Persistence,
    FileBurst,
    Usb,
    InterProcess,
    PostureChange,
    SelfIntegrity,
}

/// <summary>
/// Un contrôle de sécurité natif de Windows observé en lecture seule (Defender, pare-feu, UAC...).
/// Les libellés sont calculés à l'affichage pour suivre la langue choisie.
/// </summary>
public sealed record SecurityControlRow(
    SecurityControlKind Kind,
    ProtectionState State,
    string Summary,
    bool NeedsElevation = false,
    string? Recommendation = null)
{
    public string Name => Kind switch
    {
        SecurityControlKind.Defender => Loc.T("Microsoft Defender"),
        SecurityControlKind.Firewall => Loc.T("Pare-feu Windows"),
        SecurityControlKind.Uac => Loc.T("Contrôle de compte (UAC)"),
        SecurityControlKind.SecureBoot => Loc.T("Démarrage sécurisé"),
        SecurityControlKind.Tpm => Loc.T("Module TPM"),
        SecurityControlKind.VirtualizationSecurity => Loc.T("Sécurité par virtualisation (VBS)"),
        SecurityControlKind.CredentialGuard => Loc.T("Credential Guard"),
        _ => Loc.T("Protection LSASS"),
    };

    public string StatusLabel => State switch
    {
        ProtectionState.Healthy => Loc.T("Actif"),
        ProtectionState.Stopped => Loc.T("Inactif"),
        _ => Loc.T("Inconnu"),
    };

    /// <summary>Icône Segoe MDL2 : coche, croix ou information selon l'état.</summary>
    public string StateGlyph => State switch
    {
        ProtectionState.Healthy => "\uE73E",
        ProtectionState.Stopped => "\uE711",
        _ => "\uE946",
    };

    /// <summary>Précision affichée sous le contrôle : droits manquants, sinon recommandation du service.</summary>
    public string? Note => NeedsElevation ? Loc.T("Nécessite les droits administrateur") : Recommendation;
}

/// <summary>Un événement de sécurité récent remonté par la surveillance système.</summary>
public sealed record SystemEventRow(
    DateTime Time,
    SystemEventKind Kind,
    EventLevel Level,
    string Source,
    string? Process,
    string Summary)
{
    public string TimeText => Time.ToString("dd/MM HH:mm:ss");

    public string SourceText => string.IsNullOrWhiteSpace(Process) ? Source : Process!;

    public StatusTone Tone => Level switch
    {
        EventLevel.Info => StatusTone.Neutral,
        EventLevel.Low => StatusTone.Good,
        EventLevel.Medium => StatusTone.Warning,
        _ => StatusTone.Bad,
    };

    public string LevelLabel => Level switch
    {
        EventLevel.Info => Loc.T("Info"),
        EventLevel.Low => Loc.T("Faible"),
        EventLevel.Medium => Loc.T("Moyen"),
        EventLevel.High => Loc.T("Élevé"),
        _ => Loc.T("Critique"),
    };

    public string KindLabel => Kind switch
    {
        SystemEventKind.Process => Loc.T("Processus"),
        SystemEventKind.Registry => Loc.T("Registre"),
        SystemEventKind.Persistence => Loc.T("Démarrage / persistance"),
        SystemEventKind.FileBurst => Loc.T("Activité fichiers anormale"),
        SystemEventKind.Usb => Loc.T("Périphérique USB"),
        SystemEventKind.InterProcess => Loc.T("Accès inter-processus"),
        SystemEventKind.PostureChange => Loc.T("Changement de protection"),
        _ => Loc.T("Auto-intégrité"),
    };
}

/// <summary>État de Windows vu par Guardian : posture de sécurité, recommandations et événements récents.</summary>
public sealed record SystemOverview(
    DateTime? CapturedAt,
    string OsVersion,
    string WindowsEdition,
    PrivilegeKind Privilege,
    IReadOnlyList<SecurityControlRow> Controls,
    IReadOnlyList<string> Recommendations,
    IReadOnlyList<SystemEventRow> Events);

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
    DateTime? LastCheck,
    SystemOverview? SystemInfo = null)
{
    /// <summary>Snapshot utilisé tant que le service ne répond pas : aucune protection n'est affichée.</summary>
    public static GuardianSnapshot Unknown { get; } = new(
        ProtectionState.Unknown, false, false, false,
        Array.Empty<EngineStatus>(), Array.Empty<ThreatItem>(), 0,
        Array.Empty<QuarantineItem>(), 0, 0, 0,
        Array.Empty<NetworkDestination>(), null);
}
