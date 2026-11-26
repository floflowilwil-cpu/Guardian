using System.Globalization;
using System.Runtime.Versioning;
using System.Security;
using Guardian.Contracts.Common;
using Guardian.Contracts.System;
using Microsoft.Win32;

namespace Guardian.Windows.Registry;

/// <summary>
/// Adaptateur en lecture seule pour le registre Windows et l'inventaire des entrées de démarrage.
/// </summary>
public sealed class WindowsRegistryAdapter : IWindowsRegistryAdapter
{
    private static readonly IReadOnlyDictionary<string, string> EmptyValues =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc />
    public RegistryReadResult<int> TryReadDword(RegistryHive hive, string subKeyPath, string valueName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subKeyPath);
        ArgumentNullException.ThrowIfNull(valueName);

        if (!OperatingSystem.IsWindows())
        {
            return new RegistryReadResult<int>(false, default, FeatureAvailabilityStatus.Unavailable, "Non-Windows platform.");
        }

        return TryReadDwordWindows(hive, subKeyPath, valueName);
    }

    /// <inheritdoc />
    public RegistryReadResult<string> TryReadString(RegistryHive hive, string subKeyPath, string valueName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subKeyPath);
        ArgumentNullException.ThrowIfNull(valueName);

        if (!OperatingSystem.IsWindows())
        {
            return new RegistryReadResult<string>(false, null, FeatureAvailabilityStatus.Unavailable, "Non-Windows platform.");
        }

        return TryReadStringWindows(hive, subKeyPath, valueName);
    }

    /// <inheritdoc />
    public (FeatureAvailabilityStatus Availability, IReadOnlyDictionary<string, string> Values, string? ErrorMessage) EnumerateValuePairs(
        RegistryHive hive,
        string subKeyPath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subKeyPath);

        if (!OperatingSystem.IsWindows())
        {
            return (FeatureAvailabilityStatus.Unavailable, EmptyValues, "Non-Windows platform.");
        }

        return EnumerateValuePairsWindows(hive, subKeyPath);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<StartupEntryDto>> GetStartupEntriesAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<StartupEntryDto>>([]);
        }

        var entries = CollectStartupEntriesWindows(cancellationToken);
        return Task.FromResult<IReadOnlyList<StartupEntryDto>>(entries);
    }

    [SupportedOSPlatform("windows")]
    private static RegistryReadResult<int> TryReadDwordWindows(RegistryHive hive, string subKeyPath, string valueName)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(subKeyPath, writable: false);
            if (key is null)
            {
                return new RegistryReadResult<int>(false, default, FeatureAvailabilityStatus.Available);
            }

            var rawValue = key.GetValue(valueName);
            return rawValue switch
            {
                null => new RegistryReadResult<int>(false, default, FeatureAvailabilityStatus.Available),
                int intValue => new RegistryReadResult<int>(true, intValue, FeatureAvailabilityStatus.Available),
                long longValue => new RegistryReadResult<int>(true, unchecked((int)longValue), FeatureAvailabilityStatus.Available),
                string textValue when int.TryParse(textValue, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed)
                    => new RegistryReadResult<int>(true, parsed, FeatureAvailabilityStatus.Available),
                _ => new RegistryReadResult<int>(false, default, FeatureAvailabilityStatus.Degraded, $"Unexpected registry value type: {rawValue.GetType().Name}.")
            };
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException)
        {
            return new RegistryReadResult<int>(false, default, FeatureAvailabilityStatus.RequiresElevation, ex.Message);
        }
    }

    [SupportedOSPlatform("windows")]
    private static RegistryReadResult<string> TryReadStringWindows(RegistryHive hive, string subKeyPath, string valueName)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(subKeyPath, writable: false);
            if (key is null)
            {
                return new RegistryReadResult<string>(false, null, FeatureAvailabilityStatus.Available);
            }

            var rawValue = key.GetValue(valueName);
            if (rawValue is null)
            {
                return new RegistryReadResult<string>(false, null, FeatureAvailabilityStatus.Available);
            }

            var formatted = FormatRegistryValue(rawValue);
            return new RegistryReadResult<string>(true, formatted, FeatureAvailabilityStatus.Available);
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException)
        {
            return new RegistryReadResult<string>(false, null, FeatureAvailabilityStatus.RequiresElevation, ex.Message);
        }
    }

    [SupportedOSPlatform("windows")]
    private static (FeatureAvailabilityStatus Availability, IReadOnlyDictionary<string, string> Values, string? ErrorMessage) EnumerateValuePairsWindows(
        RegistryHive hive,
        string subKeyPath)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(subKeyPath, writable: false);
            if (key is null)
            {
                return (FeatureAvailabilityStatus.Available, EmptyValues, null);
            }

            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var name in key.GetValueNames())
            {
                if (string.IsNullOrEmpty(name))
                {
                    continue;
                }

                var rawValue = key.GetValue(name);
                if (rawValue is not null)
                {
                    result[name] = FormatRegistryValue(rawValue);
                }
            }

            return (FeatureAvailabilityStatus.Available, result, null);
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException)
        {
            return (FeatureAvailabilityStatus.RequiresElevation, EmptyValues, ex.Message);
        }
    }

    [SupportedOSPlatform("windows")]
    private IReadOnlyList<StartupEntryDto> CollectStartupEntriesWindows(CancellationToken cancellationToken)
    {
        var entries = new List<StartupEntryDto>();

        var registryTargets = new (RegistryHive Hive, string SubKey, PersistenceEntryKind Kind, string Scope)[]
        {
            (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", PersistenceEntryKind.RegistryRun, "Machine"),
            (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", PersistenceEntryKind.RegistryRunOnce, "Machine"),
            (RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", PersistenceEntryKind.RegistryRun, "MachineWow64"),
            (RegistryHive.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", PersistenceEntryKind.RegistryRunOnce, "MachineWow64"),
            (RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", PersistenceEntryKind.RegistryRun, "User"),
            (RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", PersistenceEntryKind.RegistryRunOnce, "User")
        };

        foreach (var target in registryTargets)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var (availability, values, _) = EnumerateValuePairsWindows(target.Hive, target.SubKey);
            var location = $@"{FormatHiveName(target.Hive)}\{target.SubKey}";

            if (availability == FeatureAvailabilityStatus.RequiresElevation)
            {
                entries.Add(new StartupEntryDto(
                    Name: "(AccessDenied)",
                    Kind: target.Kind,
                    Location: location,
                    CommandOrPath: string.Empty,
                    Scope: target.Scope,
                    AccessStatus: FeatureAvailabilityStatus.RequiresElevation));
                continue;
            }

            foreach (var pair in values)
            {
                entries.Add(new StartupEntryDto(
                    Name: pair.Key,
                    Kind: target.Kind,
                    Location: location,
                    CommandOrPath: pair.Value,
                    Scope: target.Scope,
                    AccessStatus: FeatureAvailabilityStatus.Available));
            }
        }

        CollectWinlogonEntries(entries, cancellationToken);
        CollectIfeoDebuggerEntries(entries, cancellationToken);
        CollectStartupFolderEntries(entries, global::System.Environment.SpecialFolder.CommonStartup, "Machine", cancellationToken);
        CollectStartupFolderEntries(entries, global::System.Environment.SpecialFolder.Startup, "User", cancellationToken);

        return entries;
    }

    [SupportedOSPlatform("windows")]
    private void CollectWinlogonEntries(List<StartupEntryDto> entries, CancellationToken cancellationToken)
    {
        const string winlogonSubKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        var location = $@"HKLM\{winlogonSubKey}";

        foreach (var valueName in new[] { "Shell", "Userinit" })
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = TryReadStringWindows(RegistryHive.LocalMachine, winlogonSubKey, valueName);
            if (result.Availability == FeatureAvailabilityStatus.RequiresElevation)
            {
                entries.Add(new StartupEntryDto(valueName, PersistenceEntryKind.Winlogon, location, string.Empty, "Machine", FeatureAvailabilityStatus.RequiresElevation));
            }
            else if (result.Found && !string.IsNullOrWhiteSpace(result.Value))
            {
                entries.Add(new StartupEntryDto(valueName, PersistenceEntryKind.Winlogon, location, result.Value, "Machine", FeatureAvailabilityStatus.Available));
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static void CollectIfeoDebuggerEntries(List<StartupEntryDto> entries, CancellationToken cancellationToken)
    {
        const string ifeoSubKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var ifeoKey = baseKey.OpenSubKey(ifeoSubKey, writable: false);
            if (ifeoKey is null)
            {
                return;
            }

            foreach (var subKeyName in ifeoKey.GetSubKeyNames())
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    using var appKey = ifeoKey.OpenSubKey(subKeyName, writable: false);
                    var debugger = appKey?.GetValue("Debugger") as string;
                    if (!string.IsNullOrWhiteSpace(debugger))
                    {
                        entries.Add(new StartupEntryDto(
                            Name: subKeyName,
                            Kind: PersistenceEntryKind.ImageFileExecutionOptions,
                            Location: $@"HKLM\{ifeoSubKey}\{subKeyName}",
                            CommandOrPath: debugger,
                            Scope: "Machine",
                            AccessStatus: FeatureAvailabilityStatus.Available));
                    }
                }
                catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException)
                {
                    // Sous-clé protégée ignorée individuellement sans bloquer l'inventaire global.
                }
            }
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException)
        {
            entries.Add(new StartupEntryDto(
                Name: "(AccessDenied)",
                Kind: PersistenceEntryKind.ImageFileExecutionOptions,
                Location: $@"HKLM\{ifeoSubKey}",
                CommandOrPath: string.Empty,
                Scope: "Machine",
                AccessStatus: FeatureAvailabilityStatus.RequiresElevation));
        }
    }

    private static void CollectStartupFolderEntries(
        List<StartupEntryDto> entries,
        global::System.Environment.SpecialFolder folder,
        string scope,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var folderPath = global::System.Environment.GetFolderPath(folder);
        if (string.IsNullOrWhiteSpace(folderPath) || !Directory.Exists(folderPath))
        {
            return;
        }

        try
        {
            foreach (var filePath in Directory.EnumerateFiles(folderPath))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var fileName = Path.GetFileName(filePath);
                if (string.Equals(fileName, "desktop.ini", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                entries.Add(new StartupEntryDto(
                    Name: fileName,
                    Kind: PersistenceEntryKind.StartupFolder,
                    Location: folderPath,
                    CommandOrPath: filePath,
                    Scope: scope,
                    AccessStatus: FeatureAvailabilityStatus.Available));
            }
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or SecurityException)
        {
            entries.Add(new StartupEntryDto(
                Name: "(AccessDenied)",
                Kind: PersistenceEntryKind.StartupFolder,
                Location: folderPath,
                CommandOrPath: string.Empty,
                Scope: scope,
                AccessStatus: FeatureAvailabilityStatus.RequiresElevation));
        }
        catch (IOException)
        {
            // Dossier indisponible temporairement.
        }
    }

    private static string FormatRegistryValue(object rawValue)
    {
        return rawValue switch
        {
            string s => s,
            string[] arr => string.Join("; ", arr),
            byte[] bytes => Convert.ToHexString(bytes),
            IFormattable formattable => formattable.ToString(null, CultureInfo.InvariantCulture),
            _ => rawValue.ToString() ?? string.Empty
        };
    }

    [SupportedOSPlatform("windows")]
    private static string FormatHiveName(RegistryHive hive)
    {
        return hive switch
        {
            RegistryHive.LocalMachine => "HKLM",
            RegistryHive.CurrentUser => "HKCU",
            RegistryHive.ClassesRoot => "HKCR",
            RegistryHive.Users => "HKU",
            RegistryHive.CurrentConfig => "HKCC",
            _ => hive.ToString()
        };
    }
}
