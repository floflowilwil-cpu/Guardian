using System.Security.Cryptography;
using System.Text;
using Guardian.Windows.Security;

namespace Guardian.UnitTests.Windows;

public class WindowsAuthenticodeVerifierTests
{
    [Fact]
    public async Task VerifyFileAsync_WhenFileDoesNotExist_ShouldReturnExistsFalseWithoutThrowing()
    {
        var verifier = new WindowsAuthenticodeVerifier();
        var missingPath = Path.Combine(Path.GetTempPath(), $"guardian-missing-{Guid.NewGuid():N}.bin");

        var result = await verifier.VerifyFileAsync(missingPath, expectedSha256: "0000");

        Assert.False(result.Exists);
        Assert.Null(result.Sha256);
        Assert.False(result.ExpectedHashMatched);
        Assert.False(result.IsSignatureValid);
    }

    [Fact]
    public async Task VerifyFileAsync_ShouldComputeSha256AndCompareConstantTimeExpectedHash()
    {
        var verifier = new WindowsAuthenticodeVerifier();
        var tempFile = Path.Combine(Path.GetTempPath(), $"guardian-hash-{Guid.NewGuid():N}.bin");

        try
        {
            var payload = Encoding.UTF8.GetBytes("Guardian integrity test payload");
            await File.WriteAllBytesAsync(tempFile, payload);
            var expectedHex = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();

            var matched = await verifier.VerifyFileAsync(tempFile, expectedSha256: expectedHex.ToUpperInvariant());
            var mismatched = await verifier.VerifyFileAsync(tempFile, expectedSha256: new string('f', 64));

            Assert.True(matched.Exists);
            Assert.Equal(expectedHex, matched.Sha256);
            Assert.True(matched.ExpectedHashMatched);
            Assert.False(matched.IsAuthenticodeSigned);
            Assert.False(matched.IsSignatureValid);

            Assert.True(mismatched.Exists);
            Assert.Equal(expectedHex, mismatched.Sha256);
            Assert.False(mismatched.ExpectedHashMatched);
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }
}
