using System.IO;
using System.Text.Json;

namespace Guardian.Desktop.Infrastructure;

/// <summary>Préférences d'interface stockées dans %LocalAppData%\Guardian\ (doc technique §12).</summary>
public sealed record UiPreferences(ThemeMode Theme, string Language, bool SilentMode, bool OfflineMode)
{
    private static string FilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Guardian", "ui-preferences.json");

    public static UiPreferences Default { get; } = new(ThemeMode.Dark, "Français", false, false);

    public static UiPreferences Load()
    {
        try
        {
            return File.Exists(FilePath)
                ? JsonSerializer.Deserialize<UiPreferences>(File.ReadAllText(FilePath)) ?? Default
                : Default;
        }
        catch
        {
            return Default;
        }
    }

    public static void Save(UiPreferences prefs)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(prefs));
        }
        catch
        {
            // Les préférences ne sont pas critiques : on ignore les erreurs d'écriture.
        }
    }
}
