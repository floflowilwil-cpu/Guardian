using Guardian.Contracts.Signatures;

namespace Guardian.Signatures;

/// <summary>
/// Fournisseur de signatures en mémoire. Utile pour les tests et comme base
/// avant le branchement sur la base SQLite.
/// </summary>
public sealed class InMemorySignatureProvider : ISignatureProvider
{
    private readonly Dictionary<string, SignatureMatch> _bySha256 =
        new(StringComparer.OrdinalIgnoreCase);

    public InMemorySignatureProvider(IEnumerable<SignatureMatch> signatures)
    {
        ArgumentNullException.ThrowIfNull(signatures);

        foreach (SignatureMatch signature in signatures)
        {
            if (!Sha256Format.IsValid(signature.Sha256))
            {
                throw new ArgumentException(
                    $"SHA-256 invalide pour la signature '{signature.SignatureId}'.",
                    nameof(signatures));
            }

            _bySha256[signature.Sha256] = signature;
        }
    }

    public int Count => _bySha256.Count;

    public Task<SignatureMatch?> FindBySha256Async(
        string sha256,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sha256);
        cancellationToken.ThrowIfCancellationRequested();

        string key = sha256.Trim();
        SignatureMatch? match = null;

        if (_bySha256.ContainsKey(key))
        {
            match = _bySha256[key];
        }

        return Task.FromResult(match);
    }
}