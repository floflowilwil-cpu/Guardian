using Guardian.Contracts.Common;

namespace Guardian.Windows.Environment;

/// <summary>
/// Décrit l'environnement d'exécution Windows et le niveau de privilège effectif du processus.
/// </summary>
/// <param name="IsWindows">Indique si le processus s'exécute sous Windows.</param>
/// <param name="OsVersion">Version du système d'exploitation.</param>
/// <param name="WindowsEdition">Édition et nom du produit Windows détectés en lecture seule.</param>
/// <param name="BuildNumber">Numéro de build Windows.</param>
/// <param name="Is64BitOperatingSystem">Indique si le système d'exploitation est en architecture 64 bits.</param>
/// <param name="CurrentPrivilege">Niveau de privilège effectif du compte courant.</param>
/// <param name="IsElevated">Indique si le jeton courant dispose d'une élévation administrateur ou système.</param>
/// <param name="CurrentIdentityName">Nom du compte Windows ou utilisateur courant.</param>
public sealed record WindowsEnvironmentInfo(
    bool IsWindows,
    string OsVersion,
    string WindowsEdition,
    string BuildNumber,
    bool Is64BitOperatingSystem,
    PrivilegeLevel CurrentPrivilege,
    bool IsElevated,
    string CurrentIdentityName);
