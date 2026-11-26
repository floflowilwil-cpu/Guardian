using Guardian.Contracts.Scanning;

namespace Guardian.Scanner;

/// <summary>Détermine les dossiers à parcourir pour une demande d'analyse.</summary>
public interface IScanTargetResolver
{
    IReadOnlyList<string> ResolveRoots(ScanJobRequest request);
}

public sealed class DefaultScanTargetResolver : IScanTargetResolver
{
    public IReadOnlyList<string> ResolveRoots(ScanJobRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        switch (request.Scope)
        {
            case ScanScope.Quick:
                return QuickRoots();

            case ScanScope.Full:
                return FullRoots();

            case ScanScope.Custom:
                if (string.IsNullOrWhiteSpace(request.CustomPath))
                {
                    throw new ArgumentException(
                        "Un chemin est requis pour une analyse personnalisée.",
                        nameof(request));
                }

                return [Path.GetFullPath(request.CustomPath)];

            default:
                throw new ArgumentOutOfRangeException(nameof(request));
        }
    }

    private static List<string> QuickRoots()
    {
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        string downloads = string.IsNullOrEmpty(profile) ? string.Empty : Path.Combine(profile, "Downloads");

        string[] candidates =
        [
            downloads,
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
            Path.GetTempPath()
        ];

        return candidates
            .Where(p => !string.IsNullOrWhiteSpace(p) && Directory.Exists(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static List<string> FullRoots()
    {
        return DriveInfo.GetDrives()
            .Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
            .Select(d => d.RootDirectory.FullName)
            .ToList();
    }
}
