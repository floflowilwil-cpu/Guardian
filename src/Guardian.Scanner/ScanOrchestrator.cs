using System.Diagnostics;
using Guardian.Contracts.AI.Models;
using Guardian.Contracts.Scanning;

namespace Guardian.Scanner;

/// <summary>
/// Parcourt les fichiers à analyser, appelle <see cref="IFileScanner"/> pour chacun
/// et rapporte la progression.
/// </summary>
public sealed class ScanOrchestrator : IScanOrchestrator
{
    private const long ProgressIntervalMs = 100;

    private static readonly EnumerationOptions EnumOptions = new()
    {
        RecurseSubdirectories = true,
        IgnoreInaccessible = true,
        AttributesToSkip = FileAttributes.ReparsePoint
    };

    private readonly IFileScanner _fileScanner;
    private readonly IScanTargetResolver _targets;

    public ScanOrchestrator(IFileScanner fileScanner, IScanTargetResolver targets)
    {
        ArgumentNullException.ThrowIfNull(fileScanner);
        ArgumentNullException.ThrowIfNull(targets);
        _fileScanner = fileScanner;
        _targets = targets;
    }

    public async Task<ScanSummary> RunAsync(
        ScanJobRequest request,
        IProgress<ScanProgressInfo>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        DateTime startedAt = DateTime.UtcNow;
        var clock = Stopwatch.StartNew();

        List<string> files = CollectFiles(_targets.ResolveRoots(request), cancellationToken);

        var findings = new List<FileScanResult>();
        int analysed = 0;
        int skipped = 0;
        long lastReportMs = -ProgressIntervalMs;

        for (int i = 0; i < files.Count; i++)
        {
            cancellationToken.ThrowIfCancellationRequested();

            string path = files[i];
            FileScanResult result = await _fileScanner.ScanAsync(
                new FileScanRequest { FilePath = path },
                cancellationToken);

            if (result.Verdict is ThreatVerdict.Error or ThreatVerdict.Inconclusive)
            {
                skipped++;
            }
            else
            {
                analysed++;

                if (result.Verdict is ThreatVerdict.Suspicious or ThreatVerdict.Malicious)
                {
                    findings.Add(result);
                }
            }

            long now = clock.ElapsedMilliseconds;
            if (now - lastReportMs >= ProgressIntervalMs)
            {
                lastReportMs = now;
                int processed = i + 1;
                int percent = (int)(processed * 100L / files.Count);
                progress?.Report(new ScanProgressInfo(percent, path, processed, files.Count, findings.Count));
            }
        }

        progress?.Report(new ScanProgressInfo(100, string.Empty, files.Count, files.Count, findings.Count));

        return new ScanSummary
        {
            Scope = request.Scope,
            FilesScanned = analysed,
            FilesSkipped = skipped,
            Findings = findings,
            StartedAtUtc = startedAt,
            Duration = clock.Elapsed
        };
    }

    private static List<string> CollectFiles(IReadOnlyList<string> roots, CancellationToken cancellationToken)
    {
        var files = new List<string>();

        foreach (string root in roots)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (File.Exists(root))
            {
                files.Add(root);
                continue;
            }

            if (!Directory.Exists(root))
            {
                continue;
            }

            try
            {
                foreach (string file in Directory.EnumerateFiles(root, "*", EnumOptions))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    files.Add(file);
                }
            }
            catch (IOException)
            {
                // Dossier devenu illisible pendant le parcours : on continue avec les autres.
            }
            catch (UnauthorizedAccessException)
            {
                // Idem : accès refusé sur une partie de l'arborescence.
            }
        }

        return files;
    }
}
