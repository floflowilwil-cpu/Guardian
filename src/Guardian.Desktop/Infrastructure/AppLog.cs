using System.IO;

namespace Guardian.Desktop.Infrastructure;

public static class AppLog
{
    private static readonly object Gate = new();
    private static readonly string LogPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Guardian", "guardian-errors.log");

    public static void Write(Exception exception, string source)
    {
        try
        {
            lock (Gate)
            {
                Directory.CreateDirectory(Path.GetDirectoryName(LogPath)!);
                File.AppendAllText(LogPath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {source}{Environment.NewLine}{exception}{Environment.NewLine}{new string('-', 72)}{Environment.NewLine}");
            }
        }
        catch { /* Le journal ne doit jamais provoquer un second plantage. */ }
    }
}
