namespace Guardian.Contracts.Scanning;

/// <summary>
/// Analyse de plusieurs fichiers avec progression et annulation.
/// L'annulation lève <see cref="OperationCanceledException"/>.
/// </summary>
public interface IScanOrchestrator
{
    Task<ScanSummary> RunAsync(
        ScanJobRequest request,
        IProgress<ScanProgressInfo>? progress = null,
        CancellationToken cancellationToken = default);
}
