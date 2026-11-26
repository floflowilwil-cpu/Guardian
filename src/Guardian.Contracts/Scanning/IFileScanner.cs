namespace Guardian.Contracts.Scanning;

/// <summary>
/// Analyse d'un fichier unique.
/// </summary>
public interface IFileScanner
{
    Task<FileScanResult> ScanAsync(
        FileScanRequest request,
        CancellationToken cancellationToken = default);
}
