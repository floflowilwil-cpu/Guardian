namespace Guardian.Windows.Environment;

/// <summary>
/// Contrat d'inspection en lecture seule de l'environnement Windows, des privilèges courants et des chemins standards Guardian.
/// </summary>
public interface IWindowsPrivilegeInspector
{
    /// <summary>
    /// Collecte les informations sur le système d'exploitation, l'édition Windows et les privilèges effectifs du processus courant.
    /// </summary>
    /// <returns>Instantané descriptif de l'environnement et du privilège effectif.</returns>
    WindowsEnvironmentInfo GetEnvironmentInfo();

    /// <summary>
    /// Résout les chemins standards Guardian conformément aux API Windows et aux emplacements de référence.
    /// </summary>
    /// <param name="programDataRootOverride">Racine de remplacement optionnelle pour <c>%ProgramData%</c> (utile en test).</param>
    /// <param name="programFilesRootOverride">Racine de remplacement optionnelle pour <c>%ProgramFiles%</c> (utile en test).</param>
    /// <param name="localAppDataRootOverride">Racine de remplacement optionnelle pour <c>%LocalAppData%</c> (utile en test).</param>
    /// <returns>Ensemble des chemins normalisés pour les composants Guardian.</returns>
    GuardianPaths GetStandardPaths(
        string? programDataRootOverride = null,
        string? programFilesRootOverride = null,
        string? localAppDataRootOverride = null);
}
