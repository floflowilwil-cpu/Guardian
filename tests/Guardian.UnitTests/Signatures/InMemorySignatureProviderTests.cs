using Guardian.Contracts.AI.Models;
using Guardian.Contracts.Signatures;
using Guardian.Scanner.Hashing;
using Guardian.Signatures;

namespace Guardian.UnitTests.Signatures;

public class InMemorySignatureProviderTests
{
    private const string AbcSha256 =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    private static SignatureMatch CreateSignature(string sha256) => new()
    {
        SignatureId = "SIG-0001",
        Sha256 = sha256,
        ThreatName = "Test.Malware.Sample",
        ThreatFamily = "TestFamily",
        Severity = SignalSeverity.High
    };

    [Fact]
    public async Task FindBySha256Async_KnownHash_ReturnsMatch()
    {
        var provider = new InMemorySignatureProvider([CreateSignature(AbcSha256)]);

        SignatureMatch? match = await provider.FindBySha256Async(AbcSha256);

        Assert.NotNull(match);
        Assert.Equal("SIG-0001", match.SignatureId);
    }

    [Fact]
    public async Task FindBySha256Async_UnknownHash_ReturnsNull()
    {
        var provider = new InMemorySignatureProvider([CreateSignature(AbcSha256)]);

        SignatureMatch? match = await provider.FindBySha256Async(new string('0', 64));

        Assert.Null(match);
    }

    [Fact]
    public async Task FindBySha256Async_IsCaseInsensitive()
    {
        var provider = new InMemorySignatureProvider([CreateSignature(AbcSha256)]);

        SignatureMatch? match = await provider.FindBySha256Async(AbcSha256.ToUpperInvariant());

        Assert.NotNull(match);
    }

    [Fact]
    public void Constructor_InvalidHash_Throws()
    {
        Assert.Throws<ArgumentException>(
            () => new InMemorySignatureProvider([CreateSignature("pas-un-hash")]));
    }

    [Fact]
    public async Task FindBySha256Async_CanceledToken_Throws()
    {
        var provider = new InMemorySignatureProvider([CreateSignature(AbcSha256)]);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAsync<OperationCanceledException>(
            () => provider.FindBySha256Async(AbcSha256, cts.Token));
    }

    [Fact]
    public async Task HashedFile_MatchesSignature_EndToEnd()
    {
        string path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "abc");
            var provider = new InMemorySignatureProvider([CreateSignature(AbcSha256)]);

            string hash = await FileHasher.ComputeSha256Async(path);
            SignatureMatch? match = await provider.FindBySha256Async(hash);

            Assert.NotNull(match);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
