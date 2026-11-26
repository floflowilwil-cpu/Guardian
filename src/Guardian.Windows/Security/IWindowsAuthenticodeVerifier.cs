using Guardian.Contracts.System;

namespace Guardian.Windows.Security;

/// <summary>
/// Contrat de vérification d'intégrité cryptographique SHA-256 et de signature Authenticode Windows.
/// </summary>
public interface IWindowsAuthenticodeVerifier
{
    /// <summary>
    /// Calcule l'empreinte SHA-256 d'un fichier et vérifie sa signature Authenticode via les APIs système Windows.
    /// </summary>
    /// <param name="filePath">Chemin du fichier à contrôler.</param>
    /// <param name="expectedSha256">Empreinte SHA-256 attendue optionnelle.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Résultat détaillé du contrôle d'intégrité et de signature.</returns>
    Task<FileIntegrityResultDto> VerifyFileAsync(
        string filePath,
        string? expectedSha256 = null,
        CancellationToken cancellationToken = default);
}
