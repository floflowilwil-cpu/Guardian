namespace Guardian.Contracts.Signatures;

/// <summary>
/// Source de signatures de menaces connues.
/// </summary>
public interface ISignatureProvider
{
    /// <summary>
    /// Cherche une signature correspondant à l'empreinte SHA-256 donnée.
    /// Retourne null si aucune signature ne correspond.
    /// </summary>
    Task<SignatureMatch?> FindBySha256Async(
        string sha256,
        CancellationToken cancellationToken = default);
}