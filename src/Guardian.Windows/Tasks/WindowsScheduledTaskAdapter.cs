using System.Xml;
using System.Xml.Linq;
using Guardian.Contracts.Common;
using Guardian.Contracts.System;

namespace Guardian.Windows.Tasks;

/// <summary>
/// Adaptateur en lecture seule des tâches planifiées Windows (<c>%SystemRoot%\System32\Tasks</c>)
/// avec parseur XML durci contre les attaques XXE et limites de taille strictes.
/// </summary>
public sealed class WindowsScheduledTaskAdapter : IWindowsScheduledTaskAdapter
{
    /// <summary>
    /// Taille maximale autorisée par descripteur XML de tâche planifiée (256 Kio).
    /// </summary>
    public const long DefaultMaxTaskFileBytes = 262_144;

    /// <summary>
    /// Nombre maximal de tâches retournées par inventaire afin de borner la consommation mémoire.
    /// </summary>
    public const int DefaultMaxTaskCount = 500;

    private static readonly EnumerationOptions TaskEnumOptions = new()
    {
        RecurseSubdirectories = true,
        IgnoreInaccessible = true,
        AttributesToSkip = FileAttributes.ReparsePoint
    };

    private readonly string? _tasksRootOverride;
    private readonly int _maxTaskCount;

    /// <summary>
    /// Initialise l'adaptateur en ciblant le dossier système des tâches planifiées Windows.
    /// </summary>
    public WindowsScheduledTaskAdapter()
        : this(null, DefaultMaxTaskCount)
    {
    }

    /// <summary>
    /// Initialise l'adaptateur avec un répertoire racine optionnel et une limite de tâches (tests / isolation).
    /// </summary>
    /// <param name="tasksRootOverride">Répertoire racine alternatif contenant les fichiers XML de tâches.</param>
    /// <param name="maxTaskCount">Nombre maximal d'entrées retournées.</param>
    public WindowsScheduledTaskAdapter(string? tasksRootOverride, int maxTaskCount = DefaultMaxTaskCount)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maxTaskCount, 0);
        _tasksRootOverride = tasksRootOverride;
        _maxTaskCount = maxTaskCount;
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<StartupEntryDto>> GetScheduledTasksAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(_tasksRootOverride) && !OperatingSystem.IsWindows())
        {
            return Task.FromResult<IReadOnlyList<StartupEntryDto>>([]);
        }

        var rootPath = ResolveTasksRoot();
        if (string.IsNullOrWhiteSpace(rootPath) || !Directory.Exists(rootPath))
        {
            return Task.FromResult<IReadOnlyList<StartupEntryDto>>([]);
        }

        var entries = new List<StartupEntryDto>();
        foreach (var filePath in EnumerateTaskFiles(rootPath, cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (entries.Count >= _maxTaskCount)
            {
                break;
            }

            if (TryParseTaskFile(rootPath, filePath, out var taskEntries))
            {
                foreach (var entry in taskEntries)
                {
                    if (entries.Count >= _maxTaskCount)
                    {
                        break;
                    }

                    entries.Add(entry);
                }
            }
        }

        IReadOnlyList<StartupEntryDto> sorted = entries
            .OrderBy(e => e.Location, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.CommandOrPath, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return Task.FromResult(sorted);
    }

    private string? ResolveTasksRoot()
    {
        if (!string.IsNullOrWhiteSpace(_tasksRootOverride))
        {
            return Path.GetFullPath(_tasksRootOverride);
        }

        var windowsFolder = global::System.Environment.GetFolderPath(global::System.Environment.SpecialFolder.Windows);
        return string.IsNullOrWhiteSpace(windowsFolder)
            ? null
            : Path.Combine(windowsFolder, "System32", "Tasks");
    }

    private static IEnumerable<string> EnumerateTaskFiles(string rootPath, CancellationToken cancellationToken)
    {
        IEnumerator<string>? enumerator = null;
        try
        {
            enumerator = Directory.EnumerateFiles(rootPath, "*", TaskEnumOptions).GetEnumerator();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            yield break;
        }

        using (enumerator)
        {
            while (MoveNextSafely(enumerator))
            {
                cancellationToken.ThrowIfCancellationRequested();
                yield return enumerator.Current;
            }
        }
    }

    private static bool MoveNextSafely(IEnumerator<string> enumerator)
    {
        try
        {
            return enumerator.MoveNext();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return false;
        }
    }

    private static bool TryParseTaskFile(
        string rootPath,
        string filePath,
        out List<StartupEntryDto> entries)
    {
        entries = [];

        try
        {
            var info = new FileInfo(filePath);
            if (!info.Exists || info.Length <= 0 || info.Length > DefaultMaxTaskFileBytes)
            {
                return false;
            }

            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = DefaultMaxTaskFileBytes
            };

            using var reader = XmlReader.Create(stream, settings);
            var document = XDocument.Load(reader);
            var relativePath = Path.GetRelativePath(rootPath, filePath);
            var taskName = Path.GetFileName(filePath);
            var location = $"\\{relativePath}";

            foreach (var execElement in document.Descendants().Where(e =>
                string.Equals(e.Name.LocalName, "Exec", StringComparison.OrdinalIgnoreCase)))
            {
                var command = execElement.Elements()
                    .FirstOrDefault(e => string.Equals(e.Name.LocalName, "Command", StringComparison.OrdinalIgnoreCase))
                    ?.Value?.Trim();

                if (string.IsNullOrWhiteSpace(command))
                {
                    continue;
                }

                var arguments = execElement.Elements()
                    .FirstOrDefault(e => string.Equals(e.Name.LocalName, "Arguments", StringComparison.OrdinalIgnoreCase))
                    ?.Value?.Trim();

                var commandOrPath = string.IsNullOrWhiteSpace(arguments)
                    ? command
                    : $"{command} {arguments}";

                entries.Add(new StartupEntryDto(
                    Name: taskName,
                    Kind: PersistenceEntryKind.ScheduledTask,
                    Location: location,
                    CommandOrPath: commandOrPath,
                    Scope: "Machine",
                    AccessStatus: FeatureAvailabilityStatus.Available));
            }

            return entries.Count > 0;
        }
        catch (Exception ex) when (ex is XmlException or InvalidOperationException or IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return false;
        }
    }
}
