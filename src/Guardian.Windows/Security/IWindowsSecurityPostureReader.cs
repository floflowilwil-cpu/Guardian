using Guardian.Contracts.System;

namespace Guardian.Windows.Security;

/// <summary>
/// Contrat d'évaluation strictement en lecture seule de la posture de sécurité native Windows.
/// </summary>
public interface IWindowsSecurityPostureReader
{
    /// <summary>
    /// Lit l'état courant des défenses Windows (Defender, pare-feu, UAC, Secure Boot, TPM, VBS, Credential Guard, LSASS)
    /// sans jamais modifier ni affaiblir la configuration du système.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Instantané complet de posture sécurité et recommandations de durcissement.</returns>
    Task<WindowsSecurityPostureDto> ReadPostureAsync(CancellationToken cancellationToken = default);
}
