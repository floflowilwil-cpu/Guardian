using System.Security.Cryptography;

namespace Guardian.Scanner.Hashing;

/// <summary>
/// Calcule l'empreinte SHA-256 d'un fichier sans le charger entièrement en mémoire.
/// </summary>
public static class FileHasher
{
    public static async Task<string> ComputeSha256Async(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        await using var stream = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite,
            bufferSize: 81920,
            useAsync: true);

        byte[] hash = await SHA256.HashDataAsync(stream, cancellationToken);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
