using Guardian.Contracts.AI.Models;
using Guardian.Contracts.Signatures;

namespace Guardian.Contracts.Scanning;

/// <summary>
/// Résultat d'analyse d'un fichier. Constat uniquement : l'action à mener
/// est décidée par la politique de sécurité.
/// </summary>
public sealed record FileScanResult
{
    public required string FilePath { get; init; }
    public required ThreatVerdict Verdict { get; init; }
    public required IReadOnlyList<string> Reasons { get; init; }

    public string? Sha256 { get; init; }
    public long FileSizeBytes { get; init; }

    /// <summary>Type réel détecté à partir du contenu (ex. "Pdf", "WindowsExecutable").</summary>
    public string? DetectedFileType { get; init; }

    public bool IsDisguisedExecutable { get; init; }
    public SignatureMatch? Signature { get; init; }
    public DateTime ScannedAtUtc { get; init; } = DateTime.UtcNow;
}
