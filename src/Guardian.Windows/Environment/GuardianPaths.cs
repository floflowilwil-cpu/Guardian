namespace Guardian.Windows.Environment;

/// <summary>
/// Regroupe les répertoires et emplacements de fichiers normalisés utilisés par Guardian sous Windows.
/// </summary>
/// <param name="BinariesDirectory">Répertoire des binaires (<c>%ProgramFiles%\Guardian</c>).</param>
/// <param name="ConfigDirectory">Répertoire de configuration machine (<c>%ProgramData%\Guardian\config</c>).</param>
/// <param name="DataDirectory">Répertoire des données applicatives (<c>%ProgramData%\Guardian\data</c>).</param>
/// <param name="DatabaseFilePath">Chemin complet de la base SQLite (<c>%ProgramData%\Guardian\data\guardian.db</c>).</param>
/// <param name="QuarantineDirectory">Répertoire isolé de quarantaine (<c>%ProgramData%\Guardian\quarantine</c>).</param>
/// <param name="SignaturesDirectory">Répertoire des bases de signatures (<c>%ProgramData%\Guardian\signatures</c>).</param>
/// <param name="ModelsDirectory">Répertoire des modèles IA locaux (<c>%ProgramData%\Guardian\models</c>).</param>
/// <param name="LogsDirectory">Répertoire des journaux de service (<c>%ProgramData%\Guardian\logs</c>).</param>
/// <param name="BackupDirectory">Répertoire des sauvegardes (<c>%ProgramData%\Guardian\backup</c>).</param>
/// <param name="UiPreferencesDirectory">Répertoire des préférences utilisateur UI (<c>%LocalAppData%\Guardian</c>).</param>
public sealed record GuardianPaths(
    string BinariesDirectory,
    string ConfigDirectory,
    string DataDirectory,
    string DatabaseFilePath,
    string QuarantineDirectory,
    string SignaturesDirectory,
    string ModelsDirectory,
    string LogsDirectory,
    string BackupDirectory,
    string UiPreferencesDirectory);
