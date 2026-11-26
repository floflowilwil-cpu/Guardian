namespace Guardian.Contracts.Scanning;

/// <summary>
/// Demande d'analyse d'un fichier.
/// </summary>
public sealed record FileScanRequest
{
    /// <summary>Taille maximale par défaut analysée (256 Mo).</summary>
    public const long DefaultMaxFileSizeBytes = 256L * 1024 * 1024;

    public required string FilePath { get; init; }

    public long MaxFileSizeBytes { get; init; } = DefaultMaxFileSizeBytes;
}
