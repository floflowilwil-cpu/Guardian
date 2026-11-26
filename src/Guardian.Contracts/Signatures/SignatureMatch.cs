using Guardian.Contracts.AI.Models;

namespace Guardian.Contracts.Signatures;

/// <summary>
/// Correspondance trouvée entre un fichier et une signature connue.
/// </summary>
public sealed record SignatureMatch
{
    public required string SignatureId { get; init; }
    public required string Sha256 { get; init; }
    public required string ThreatName { get; init; }
    public string? ThreatFamily { get; init; }
    public required SignalSeverity Severity { get; init; }
}