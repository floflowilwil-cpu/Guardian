using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using Guardian.Desktop.Models;

namespace Guardian.Desktop.Infrastructure;

/// <summary>Convertit un état (ProtectionState / RiskLevel) en pinceau du thème courant.</summary>
public sealed class StateToBrushConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var key = value switch
        {
            ProtectionState.Healthy => "SuccessBrush",
            ProtectionState.Degraded => "WarningBrush",
            ProtectionState.OutOfDate => "WarningBrush",
            ProtectionState.Stopped => "DangerBrush",
            RiskLevel.Low => "SuccessBrush",
            RiskLevel.Medium => "WarningBrush",
            RiskLevel.High => "DangerBrush",
            StatusTone.Good => "SuccessBrush",
            StatusTone.Warning => "WarningBrush",
            StatusTone.Bad => "DangerBrush",
            _ => "UnknownBrush",
        };

        return Application.Current.TryFindResource(key) as Brush ?? Brushes.Gray;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Affiche un élément seulement si la valeur est non nulle.</summary>
public sealed class NullToCollapsedConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is null ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Affiche un élément seulement quand la valeur est nulle (ex. message "aucune sélection").</summary>
public sealed class NullToVisibleConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is null ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

public sealed class InverseBoolToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
