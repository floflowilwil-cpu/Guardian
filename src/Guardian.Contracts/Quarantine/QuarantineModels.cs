namespace Guardian.Contracts.Quarantine;

/// <summary>Demande de mise en quarantaine d'un fichier.</summary>
public sealed record QuarantineRequest
{
    public required string FilePath { get; init; }
    public required string Reason { get; init; }

    /// <summary>Moteur à l'origine de la décision (ex. "Scanner.Signature").</summary>
    public required string DetectionEngine { get; init; }

    public string? ThreatName { get; init; }
}

/// <summary>Élément conservé en quarantaine.</summary>
public sealed record QuarantineItem
{
    public required Guid Id { get; init; }
    public required string OriginalPath { get; init; }
    public required string Sha256 { get; init; }
    public required long SizeBytes { get; init; }
    public required DateTime QuarantinedAtUtc { get; init; }
    public required string Reason { get; init; }
    public required string DetectionEngine { get; init; }
    public string? ThreatName { get; init; }
}