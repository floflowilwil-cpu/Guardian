namespace Guardian.Contracts.Common;

/// <summary>
/// Niveau de privilège effectif d'un processus ou contexte d'exécution Windows.
/// </summary>
public enum PrivilegeLevel
{
    /// <summary>
    /// Privilège inconnu ou plateforme non Windows.
    /// </summary>
    Unknown = 0,

    /// <summary>
    /// Utilisateur standard sans élévation administrateur.
    /// </summary>
    StandardUser = 1,

    /// <summary>
    /// Contexte membre du groupe Administrateurs avec élévation effective.
    /// </summary>
    Administrator = 2,

    /// <summary>
    /// Compte de service local Windows (<c>NT AUTHORITY\LOCAL SERVICE</c>).
    /// </summary>
    LocalService = 3,

    /// <summary>
    /// Compte de service réseau Windows (<c>NT AUTHORITY\NETWORK SERVICE</c>).
    /// </summary>
    NetworkService = 4,

    /// <summary>
    /// Compte système local (<c>NT AUTHORITY\SYSTEM</c>).
    /// </summary>
    LocalSystem = 5
}
