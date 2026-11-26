using Guardian.Contracts.Common;

namespace Guardian.Contracts.System;

/// <summary>
/// Instantané en lecture seule de la posture de sécurité native du poste Windows.
/// </summary>
/// <remarks>
/// Guardian observe ces contrôles de manière strictement passive afin de détecter
/// tout affaiblissement sans jamais désactiver ni contourner les défenses Windows.
/// </remarks>
/// <param name="CapturedAtUtc">Horodatage UTC de l'observation.</param>
/// <param name="OsVersion">Chaîne de version du système d'exploitation.</param>
/// <param name="WindowsEdition">Édition Windows détectée (ex. <c>Professional</c>, <c>Home</c>).</param>
/// <param name="CurrentPrivilege">Niveau de privilège effectif du processus appelant.</param>
/// <param name="Defender">État en lecture seule de Microsoft Defender.</param>
/// <param name="Firewall">État en lecture seule du pare-feu Windows.</param>
/// <param name="Uac">État en lecture seule du contrôle de compte utilisateur (UAC).</param>
/// <param name="SecureBoot">État observable du démarrage sécurisé Secure Boot.</param>
/// <param name="Tpm">État observable du module TPM (Trusted Platform Module).</param>
/// <param name="VirtualizationBasedSecurity">État observable de la sécurité basée sur la virtualisation (VBS).</param>
/// <param name="CredentialGuard">État observable de Windows Defender Credential Guard.</param>
/// <param name="LsassProtection">État observable de la protection PPL du processus LSASS.</param>
/// <param name="Recommendations">Liste consolidée des recommandations de durcissement applicables.</param>
public sealed record WindowsSecurityPostureDto(
    DateTimeOffset CapturedAtUtc,
    string OsVersion,
    string WindowsEdition,
    PrivilegeLevel CurrentPrivilege,
    SecurityControlStatusDto Defender,
    SecurityControlStatusDto Firewall,
    SecurityControlStatusDto Uac,
    SecurityControlStatusDto SecureBoot,
    SecurityControlStatusDto Tpm,
    SecurityControlStatusDto VirtualizationBasedSecurity,
    SecurityControlStatusDto CredentialGuard,
    SecurityControlStatusDto LsassProtection,
    IReadOnlyList<string> Recommendations);
