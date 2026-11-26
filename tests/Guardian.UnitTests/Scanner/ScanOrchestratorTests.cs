using Guardian.Contracts.AI.Models;
using Guardian.Contracts.Scanning;
using Guardian.Contracts.Signatures;
using Guardian.Scanner;
using Guardian.Signatures;

namespace Guardian.UnitTests.Scanner;

public class ScanOrchestratorTests
{
    private const string AbcSha256 =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    private sealed class ListProgress : IProgress<ScanProgressInfo>
    {
        public List<ScanProgressInfo> Reports { get; } = [];

        public void Report(ScanProgressInfo value) => Reports.Add(value);
    }

    private static ScanOrchestrator CreateOrchestrator()
    {
        var signature = new SignatureMatch
        {
            SignatureId = "SIG-0001",
            Sha256 = AbcSha256,
            ThreatName = "Test.Malware.Sample",
            Severity = SignalSeverity.High
        };

        var fileScanner = new FileScanner(new InMemorySignatureProvider([signature]));
        return new ScanOrchestrator(fileScanner, new DefaultScanTargetResolver());
    }

    [Fact]
    public async Task RunAsync_CustomFolder_ScansRecursivelyAndFindsThreats()
    {
        DirectoryInfo dir = Directory.CreateTempSubdirectory("guardian-test-");
        try
        {
            string sub = Path.Combine(dir.FullName, "sub");
            Directory.CreateDirectory(sub);

            await File.WriteAllBytesAsync(Path.Combine(dir.FullName, "propre.txt"), "bonjour"u8.ToArray());
            await File.WriteAllBytesAsync(Path.Combine(dir.FullName, "connu.txt"), "abc"u8.ToArray());
            await File.WriteAllBytesAsync(Path.Combine(sub, "faux.pdf"), [0x4D, 0x5A, 0x90, 0x00, 0x03]);

            var progress = new ListProgress();

            ScanSummary summary = await CreateOrchestrator().RunAsync(
                new ScanJobRequest { Scope = ScanScope.Custom, CustomPath = dir.FullName },
                progress);

            Assert.Equal(3, summary.FilesScanned);
            Assert.Equal(0, summary.FilesSkipped);
            Assert.Equal(2, summary.Findings.Count);
            Assert.Equal(100, progress.Reports[^1].Percent);
        }
        finally
        {
            dir.Delete(true);
        }
    }

    [Fact]
    public async Task RunAsync_EmptyFolder_ReportsComplete()
    {
        DirectoryInfo dir = Directory.CreateTempSubdirectory("guardian-test-");
        try
        {
            var progress = new ListProgress();

            ScanSummary summary = await CreateOrchestrator().RunAsync(
                new ScanJobRequest { Scope = ScanScope.Custom, CustomPath = dir.FullName },
                progress);

            Assert.Equal(0, summary.FilesScanned);
            Assert.Empty(summary.Findings);
            Assert.Equal(100, progress.Reports[^1].Percent);
        }
        finally
        {
            dir.Delete(true);
        }
    }

    [Fact]
    public async Task RunAsync_CustomWithoutPath_Throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(
            () => CreateOrchestrator().RunAsync(new ScanJobRequest { Scope = ScanScope.Custom }));
    }

    [Fact]
    public async Task RunAsync_CanceledToken_Throws()
    {
        DirectoryInfo dir = Directory.CreateTempSubdirectory("guardian-test-");
        try
        {
            await File.WriteAllBytesAsync(Path.Combine(dir.FullName, "a.txt"), "abc"u8.ToArray());

            using var cts = new CancellationTokenSource();
            await cts.CancelAsync();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => CreateOrchestrator().RunAsync(
                    new ScanJobRequest { Scope = ScanScope.Custom, CustomPath = dir.FullName },
                    null,
                    cts.Token));
        }
        finally
        {
            dir.Delete(true);
        }
    }
}
