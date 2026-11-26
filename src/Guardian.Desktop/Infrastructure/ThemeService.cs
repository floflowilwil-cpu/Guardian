using System.Windows;
using Microsoft.Win32;

namespace Guardian.Desktop.Infrastructure;

public enum ThemeMode
{
    Light,
    Dark,
    Auto,
}

/// <summary>Charge le dictionnaire de couleurs sombre ou clair (tous les styles utilisent DynamicResource).</summary>
public static class ThemeService
{
    private static ResourceDictionary? _current;

    public static ThemeMode Mode { get; private set; } = ThemeMode.Dark;

    public static void Apply(ThemeMode mode)
    {
        Mode = mode;
        var dark = mode == ThemeMode.Dark || (mode == ThemeMode.Auto && !SystemUsesLightTheme());
        var uri = new Uri(
            dark ? "Themes/Colors.Dark.xaml" : "Themes/Colors.Light.xaml",
            UriKind.Relative);

        var dictionaries = Application.Current.Resources.MergedDictionaries;
        if (_current is not null)
        {
            dictionaries.Remove(_current);
        }

        _current = new ResourceDictionary { Source = uri };
        dictionaries.Insert(0, _current);
    }

    private static bool SystemUsesLightTheme()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(
                @"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int v && v == 1;
        }
        catch
        {
            return false;
        }
    }
}
