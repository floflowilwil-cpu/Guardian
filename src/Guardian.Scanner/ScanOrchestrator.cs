using System.Diagnostics;
using Guardian.Contracts.AI.Models;
using Guardian.Contracts.Scanning;

namespace Guardian.Scanner;

/// <summary>
/// Parcourt les fichiers au fil de l'eau et appelle <see cref="IFileScanner"/> pour chacun.
/// Un comptage parallèle estime le total : la progression démarre immédiatement et devient
/// exacte quand le comptage est terminé. Aucune liste complète de chemins n'est gardée en mémoire.
/// </summary>
public sealed class ScanOrchestrator : IScanOrchestrator
{
    private const long ProgressIntervalMs = 100;
    private const int MaxPercentBeforeCompletion = 99;

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
        IReadOnlyList<string> roots = _targets.ResolveRoots(request);

        var discovery = new DiscoveryCounter();
        using var countCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task countingTask = Task.Run(() => discovery.Run(roots, countCts.Token), CancellationToken.None);

        var findings = new List<FileScanResult>();
        int analysed = 0;
        int skipped = 0;
        int processed = 0;
        int lastPercent = 0;
        long lastReportMs = -ProgressIntervalMs;

        try
        {
            foreach (string path in EnumerateFiles(roots, cancellationToken))
            {
                cancellationToken.ThrowIfCancellationRequested();

                FileScanResult result = await _fileScanner.ScanAsync(
                    new FileScanRequest { FilePath = path },
                    cancellationToken);

                processed++;

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

                    long total = Math.Max(discovery.Discovered, processed);
                    int percent = (int)Math.Min(MaxPercentBeforeCompletion, processed * 100L / total);
                    lastPercent = Math.Max(lastPercent, percent);
                    int totalForReport = (int)Math.Min(int.MaxValue, total);

                    progress?.Report(new ScanProgressInfo(
                        lastPercent, path, processed, totalForReport, findings.Count));
                }
            }
        }
        finally
        {
            await countCts.CancelAsync();
            await countingTask;
        }

        progress?.Report(new ScanProgressInfo(100, string.Empty, processed, processed, findings.Count));

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

    private static IEnumerable<string> EnumerateFiles(
        IReadOnlyList<string> roots,
        CancellationToken cancellationToken)
    {
        foreach (string root in roots)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (File.Exists(root))
            {
                yield return root;
                continue;
            }

            if (!Directory.Exists(root))
            {
                continue;
            }

            IEnumerator<string>? enumerator = OpenEnumerator(root);
            if (enumerator is null)
            {
                continue;
            }

            using (enumerator)
            {
                while (MoveNextSafely(enumerator))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    yield return enumerator.Current;
                }
            }
        }
    }

    private static IEnumerator<string>? OpenEnumerator(string root)
    {
        try
        {
            return Directory.EnumerateFiles(root, "*", EnumOptions).GetEnumerator();
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static bool MoveNextSafely(IEnumerator<string> enumerator)
    {
        try
        {
            return enumerator.MoveNext();
        }
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Compte les fichiers en parallèle du scan, pour estimer le total.</summary>
    private sealed class DiscoveryCounter
    {
        private long _discovered;

        public long Discovered => Interlocked.Read(ref _discovered);

        public void Run(IReadOnlyList<string> roots, CancellationToken cancellationToken)
        {
            try
            {
                foreach (string _ in EnumerateFiles(roots, cancellationToken))
                {
                    Interlocked.Increment(ref _discovered);
                }
            }
            catch (OperationCanceledException)
            {
                // Scan terminé ou annulé : le comptage s'arrête.
            }
            catch (Exception)
            {
                // Le comptage n'est qu'une estimation : il ne doit jamais faire échouer l'analyse.
            }
        }
    }
}
