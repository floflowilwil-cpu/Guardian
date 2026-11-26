using Guardian.Contracts.AI.Models;
using Guardian.Contracts.Scanning;
using Guardian.Contracts.Signatures;
using Guardian.Scanner;
using Guardian.Signatures;

namespace Guardian.UnitTests.Scanner;

public class FileScannerTests
{
    private const string AbcSha256 =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    private static FileScanner CreateScanner(params SignatureMatch[] signatures) =>
        new(new InMemorySignatureProvider(signatures));

    private static async Task<string> WriteTempFileAsync(string extension, byte[] content)
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + extension);
        await File.WriteAllBytesAsync(path, content);
        return path;
    }

    [Fact]
    public async Task ScanAsync_HarmlessFile_IsClean()
    {
        string path = await WriteTempFileAsync(".txt", "bonjour"u8.ToArray());
        try
        {
            FileScanResult result = await CreateScanner().ScanAsync(
                new FileScanRequest { FilePath = path });

            Assert.Equal(ThreatVerdict.Clean, result.Verdict);
            Assert.NotNull(result.Sha256);
            Assert.False(result.IsDisguisedExecutable);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ScanAsync_KnownSignature_IsMalicious()
    {
        string path = await WriteTempFileAsync(".txt", "abc"u8.ToArray());
        try
        {
            var signature = new SignatureMatch
            {
                SignatureId = "SIG-0001",
                Sha256 = AbcSha256,
                ThreatName = "Test.Malware.Sample",
                Severity = SignalSeverity.High
            };

            FileScanResult result = await CreateScanner(signature).ScanAsync(
                new FileScanRequest { FilePath = path });

            Assert.Equal(ThreatVerdict.Malicious, result.Verdict);
            Assert.Equal("SIG-0001", result.Signature?.SignatureId);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ScanAsync_ExecutableRenamedAsPdf_IsSuspicious()
    {
        string path = await WriteTempFileAsync(".pdf", [0x4D, 0x5A, 0x90, 0x00, 0x03]);
        try
        {
            FileScanResult result = await CreateScanner().ScanAsync(
                new FileScanRequest { FilePath = path });

            Assert.Equal(ThreatVerdict.Suspicious, result.Verdict);
            Assert.True(result.IsDisguisedExecutable);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ScanAsync_MissingFile_ReturnsError()
    {
        string missing = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".bin");

        FileScanResult result = await CreateScanner().ScanAsync(
            new FileScanRequest { FilePath = missing });

        Assert.Equal(ThreatVerdict.Error, result.Verdict);
    }

    [Fact]
    public async Task ScanAsync_FileTooLarge_IsInconclusive()
    {
        string path = await WriteTempFileAsync(".txt", "abc"u8.ToArray());
        try
        {
            FileScanResult result = await CreateScanner().ScanAsync(
                new FileScanRequest { FilePath = path, MaxFileSizeBytes = 1 });

            Assert.Equal(ThreatVerdict.Inconclusive, result.Verdict);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ScanAsync_CanceledToken_Throws()
    {
        string path = await WriteTempFileAsync(".txt", "abc"u8.ToArray());
        try
        {
            using var cts = new CancellationTokenSource();
            await cts.CancelAsync();

            await Assert.ThrowsAnyAsync<OperationCanceledException>(
                () => CreateScanner().ScanAsync(
                    new FileScanRequest { FilePath = path }, cts.Token));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
