using System.Globalization;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Principal;
using Guardian.Contracts.Common;
using Microsoft.Win32;

namespace Guardian.Windows.Environment;

/// <summary>
/// Implémentation en lecture seule de l'inspection d'environnement Windows et de la résolution des chemins Guardian.
/// </summary>
public sealed class WindowsPrivilegeInspector : IWindowsPrivilegeInspector
{
    private const string CurrentVersionSubKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";

    /// <inheritdoc />
    public WindowsEnvironmentInfo GetEnvironmentInfo()
    {
        if (!OperatingSystem.IsWindows())
        {
            return new WindowsEnvironmentInfo(
                IsWindows: false,
                OsVersion: global::System.Environment.OSVersion.VersionString,
                WindowsEdition: "Non-Windows",
                BuildNumber: global::System.Environment.OSVersion.Version.Build.ToString(CultureInfo.InvariantCulture),
                Is64BitOperatingSystem: global::System.Environment.Is64BitOperatingSystem,
                CurrentPrivilege: PrivilegeLevel.Unknown,
                IsElevated: false,
                CurrentIdentityName: global::System.Environment.UserName);
        }

        return GetWindowsEnvironmentInfo();
    }

    /// <inheritdoc />
    public GuardianPaths GetStandardPaths(
        string? programDataRootOverride = null,
        string? programFilesRootOverride = null,
        string? localAppDataRootOverride = null)
    {
        var programFilesRoot = ResolveRoot(
            programFilesRootOverride,
            global::System.Environment.SpecialFolder.ProgramFiles);

        var programDataRoot = ResolveRoot(
            programDataRootOverride,
            global::System.Environment.SpecialFolder.CommonApplicationData);

        var localAppDataRoot = ResolveRoot(
            localAppDataRootOverride,
            global::System.Environment.SpecialFolder.LocalApplicationData);

        var programDataGuardian = Path.Combine(programDataRoot, "Guardian");
        var dataDirectory = Path.Combine(programDataGuardian, "data");

        return new GuardianPaths(
            BinariesDirectory: Path.Combine(programFilesRoot, "Guardian"),
            ConfigDirectory: Path.Combine(programDataGuardian, "config"),
            DataDirectory: dataDirectory,
            DatabaseFilePath: Path.Combine(dataDirectory, "guardian.db"),
            QuarantineDirectory: Path.Combine(programDataGuardian, "quarantine"),
            SignaturesDirectory: Path.Combine(programDataGuardian, "signatures"),
            ModelsDirectory: Path.Combine(programDataGuardian, "models"),
            LogsDirectory: Path.Combine(programDataGuardian, "logs"),
            BackupDirectory: Path.Combine(programDataGuardian, "backup"),
            UiPreferencesDirectory: Path.Combine(localAppDataRoot, "Guardian"));
    }

    [SupportedOSPlatform("windows")]
    private static WindowsEnvironmentInfo GetWindowsEnvironmentInfo()
    {
        var (edition, buildNumber) = ReadWindowsVersionMetadata();
        var (privilegeLevel, isElevated, identityName) = ReadCurrentPrivilege();

        return new WindowsEnvironmentInfo(
            IsWindows: true,
            OsVersion: global::System.Environment.OSVersion.VersionString,
            WindowsEdition: edition,
            BuildNumber: buildNumber,
            Is64BitOperatingSystem: global::System.Environment.Is64BitOperatingSystem,
            CurrentPrivilege: privilegeLevel,
            IsElevated: isElevated,
            CurrentIdentityName: identityName);
    }

    [SupportedOSPlatform("windows")]
    private static (string Edition, string BuildNumber) ReadWindowsVersionMetadata()
    {
        var fallbackBuild = global::System.Environment.OSVersion.Version.Build.ToString(CultureInfo.InvariantCulture);

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var currentVersion = baseKey.OpenSubKey(CurrentVersionSubKey, writable: false);
            if (currentVersion is null)
            {
                return ("Unknown", fallbackBuild);
            }

            var productName = currentVersion.GetValue("ProductName") as string;
            var editionId = currentVersion.GetValue("EditionID") as string;
            var build = currentVersion.GetValue("CurrentBuildNumber") as string
                ?? currentVersion.GetValue("CurrentBuild") as string
                ?? fallbackBuild;

            string edition;
            if (!string.IsNullOrWhiteSpace(productName) && !string.IsNullOrWhiteSpace(editionId))
            {
                edition = productName.Contains(editionId, StringComparison.OrdinalIgnoreCase)
                    ? productName
                    : $"{productName} ({editionId})";
            }
            else if (!string.IsNullOrWhiteSpace(editionId))
            {
                edition = editionId;
            }
            else if (!string.IsNullOrWhiteSpace(productName))
            {
                edition = productName;
            }
            else
            {
                edition = "Unknown";
            }

            return (edition, build);
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException)
        {
            return ("Unknown (RequiresElevation)", fallbackBuild);
        }
    }

    [SupportedOSPlatform("windows")]
    private static (PrivilegeLevel Level, bool IsElevated, string IdentityName) ReadCurrentPrivilege()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var identityName = string.IsNullOrWhiteSpace(identity.Name)
                ? global::System.Environment.UserName
                : identity.Name;

            if (identity.User?.IsWellKnown(WellKnownSidType.LocalSystemSid) == true)
            {
                return (PrivilegeLevel.LocalSystem, true, identityName);
            }

            if (identity.User?.IsWellKnown(WellKnownSidType.LocalServiceSid) == true)
            {
                return (PrivilegeLevel.LocalService, false, identityName);
            }

            if (identity.User?.IsWellKnown(WellKnownSidType.NetworkServiceSid) == true)
            {
                return (PrivilegeLevel.NetworkService, false, identityName);
            }

            var principal = new WindowsPrincipal(identity);
            var isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);

            return (
                isAdmin ? PrivilegeLevel.Administrator : PrivilegeLevel.StandardUser,
                isAdmin,
                identityName);
        }
        catch (Exception ex) when (ex is SecurityException or UnauthorizedAccessException)
        {
            return (PrivilegeLevel.Unknown, false, global::System.Environment.UserName);
        }
    }

    private static string ResolveRoot(string? overridePath, global::System.Environment.SpecialFolder folder)
    {
        if (!string.IsNullOrWhiteSpace(overridePath))
        {
            return Path.GetFullPath(overridePath);
        }

        var resolved = global::System.Environment.GetFolderPath(folder);
        return string.IsNullOrWhiteSpace(resolved)
            ? Path.GetTempPath()
            : Path.GetFullPath(resolved);
    }
}
