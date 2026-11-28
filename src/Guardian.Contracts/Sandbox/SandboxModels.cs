using Guardian.Contracts.AI.Models;

namespace Guardian.Contracts.Sandbox;

/// <summary>Raison pour laquelle l'analyse dynamique n'est pas disponible.</summary>
public enum SandboxUnavailableReason
{
    None = 0,
    UnsupportedPlatform = 1,
    HyperVNotInstalled = 2,
    NotImplemented = 3
}

/// <summary>Disponibilité de l'analyse dynamique sur cette machine.</summary>
public sealed record SandboxAvailability(
    bool IsAvailable,
    SandboxUnavailableReason Reason,
    string Message);

/// <summary>
/// Réseau de la machine d'analyse. Aucun accès Internet réel n'est proposé :
/// c'est volontaire, l'échantillon ne doit jamais atteindre un vrai réseau.
/// </summary>
public enum SandboxNetworkMode
{
    Disabled = 0,
    Simulated = 1
}

/// <summary>Limites appliquées à une analyse dynamique.</summary>
public sealed record SandboxLimits
{
    public static SandboxLimits Default { get; } = new();

    public TimeSpan Timeout { get; init; } = TimeSpan.FromMinutes(5);

    public int MaxMemoryMegabytes { get; init; } = 2048;

    public int MaxCpuCores { get; init; } = 2;

    public int MaxDiskMegabytes { get; init; } = 4096;

    public int MaxProcesses { get; init; } = 64;

    public SandboxNetworkMode Network { get; init; } = SandboxNetworkMode.Disabled;
}

/// <summary>Demande d'analyse dynamique d'un fichier.</summary>
public sealed record SandboxAnalysisRequest
{
    public required string FilePath { get; init; }

    public SandboxLimits Limits { get; init; } = SandboxLimits.Default;
}

public enum SandboxRunStatus
{
    Unavailable = 0,
    Completed = 1,
    TimedOut = 2,
    Canceled = 3,
    Failed = 4
}

/// <summary>Comportement observé pendant l'exécution dans la sandbox.</summary>
public sealed record SandboxObservation(
    string Kind,
    string Description,
    SignalSeverity Severity);

/// <summary>Résultat d'une analyse dynamique.</summary>
public sealed record SandboxAnalysisResult
{
    public required Guid RunId { get; init; }
    public required SandboxRunStatus Status { get; init; }
    public required ThreatVerdict Verdict { get; init; }
    public required string Summary { get; init; }
    public required DateTime StartedAtUtc { get; init; }
    public DateTime? CompletedAtUtc { get; init; }
    public IReadOnlyList<SandboxObservation> Observations { get; init; } = [];
}
