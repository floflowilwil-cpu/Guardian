using Guardian.Contracts.AI.Models;
using Guardian.Contracts.Scanning;
using Guardian.Scanner;

namespace Guardian.UnitTests.Scanner;

public class ScanOrchestratorStreamingTests
{
    private sealed class FakeScanner : IFileScanner
    {
        private readonly Action<int>? _onCall;

        public FakeScanner(Action<int>? onCall = null) => _onCall = onCall;

        public int Calls { get; private set; }

        public Task<FileScanResult> ScanAsync(
            FileScanRequest request,
            CancellationToken cancellationToken = default)
        {
            Calls++;
            _onCall?.Invoke(Calls);

            return Task.FromResult(new FileScanResult
            {
                FilePath = request.FilePath,
                Verdict = ThreatVerdict.Clean,
                Reasons = []
            });
        }
    }

    private sealed class ListProgress : IProgress<ScanProgressInfo>
    {
        public List<ScanProgressInfo> Reports { get; } = [];

        public void Report(ScanProgressInfo value) => Reports.Add(value);
    }

    private static DirectoryInfo CreateFiles(int count)
    {
        DirectoryInfo dir = Directory.CreateTempSubdirectory("guardian-stream-");

        for (int i = 0; i < count; i++)
        {
            File.WriteAllText(Path.Combine(dir.FullName, $"fichier{i}.txt"), "contenu");
        }

        return dir;
    }

    [Fact]
    public async Task RunAsync_ScansEveryFile()
    {
        DirectoryInfo dir = CreateFiles(60);
        try
        {
            var scanner = new FakeScanner();
            var orchestrator = new ScanOrchestrator(scanner, new DefaultScanTargetResolver());

            ScanSummary summary = await orchestrator.RunAsync(
                new ScanJobRequest { Scope = ScanScope.Custom, CustomPath = dir.FullName });

            Assert.Equal(60, scanner.Calls);
            Assert.Equal(60, summary.FilesScanned);
        }
        finally
        {
            dir.Delete(true);
        }
    }

    [Fact]
    public async Task RunAsync_CancelAfterFirstFile_StopsImmediately()
    {
        DirectoryInfo dir = CreateFiles(50);
        try
        {
            using var cts = new CancellationTokenSource();
            var scanner = new FakeScanner(call =>
            {
                if (call == 1)
                {
                    cts.Cancel();
                }
            });
            var orchestrator = new ScanOrchestrator(scanner, new DefaultScanTargetResolver());

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => orchestrator.RunAsync(
                    new ScanJobRequest { Scope = ScanScope.Custom, CustomPath = dir.FullName },
                    null,
                    cts.Token));

            Assert.Equal(1, scanner.Calls);
        }
        finally
        {
            dir.Delete(true);
        }
    }

    [Fact]
    public async Task RunAsync_Progress_IsMonotonicAndReaches100OnlyAtTheEnd()
    {
        DirectoryInfo dir = CreateFiles(60);
        try
        {
            var progress = new ListProgress();
            var orchestrator = new ScanOrchestrator(new FakeScanner(), new DefaultScanTargetResolver());

            await orchestrator.RunAsync(
                new ScanJobRequest { Scope = ScanScope.Custom, CustomPath = dir.FullName },
                progress);

            Assert.NotEmpty(progress.Reports);
            Assert.Equal(100, progress.Reports[^1].Percent);
            Assert.All(progress.Reports.SkipLast(1), r => Assert.True(r.Percent <= 99));
            Assert.All(progress.Reports, r => Assert.True(r.FilesTotal >= r.FilesProcessed));

            for (int i = 1; i < progress.Reports.Count; i++)
            {
                Assert.True(progress.Reports[i].Percent >= progress.Reports[i - 1].Percent);
            }
        }
        finally
        {
            dir.Delete(true);
        }
    }
}