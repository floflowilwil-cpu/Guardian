namespace Guardian.Data;

/// <summary>
/// Options de la base SQLite locale de Guardian.
/// </summary>
public sealed class GuardianDatabaseOptions
{
    /// <summary>
    /// Chemin complet du fichier de base. Par défaut : <c>%ProgramData%\Guardian\data\guardian.db</c>.
    /// </summary>
    public string DatabasePath { get; init; } = GetDefaultDatabasePath();

    /// <summary>
    /// Résout le chemin par défaut via l'API Windows plutôt qu'un chemin codé en dur.
    /// </summary>
    /// <returns>Chemin par défaut du fichier de base.</returns>
    public static string GetDefaultDatabasePath()
    {
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        return Path.Combine(programData, "Guardian", "data", "guardian.db");
    }
}
