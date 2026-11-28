namespace Guardian.Data;

/// <summary>
/// Options de la base SQLite locale de Guardian.
/// </summary>
/// <remarks>
/// Le chemin n'a volontairement pas de valeur par défaut : la source unique des chemins Guardian est
/// <c>IWindowsPrivilegeInspector.GetStandardPaths()</c> (Guardian.Windows), résolue par le service.
/// </remarks>
public sealed class GuardianDatabaseOptions
{
    /// <summary>
    /// Chemin complet du fichier de base (ex. <c>%ProgramData%\Guardian\data\guardian.db</c>).
    /// </summary>
    public required string DatabasePath { get; init; }
}
