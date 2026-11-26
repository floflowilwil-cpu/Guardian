using System.IO.Compression;
using System.Text;
using Guardian.Contracts.AI.Models;
using Guardian.Contracts.Heuristics;
using Guardian.Scanner.FileTypes;

namespace Guardian.Scanner.Heuristics;

/// <summary>Identifiants stables des règles heuristiques.</summary>
public static class HeuristicRuleIds
{
    public const string DoubleExtension = "HEUR-DOUBLE-EXTENSION";
    public const string Rtlo = "HEUR-RTLO";
    public const string DisguisedExecutable = "HEUR-DISGUISED-EXECUTABLE";
    public const string ScriptPattern = "HEUR-SCRIPT-PATTERN";
    public const string Macro = "HEUR-MACRO";
    public const string MacroHidden = "HEUR-MACRO-HIDDEN";
    public const string ArchiveBomb = "HEUR-ARCHIVE-BOMB";
    public const string ArchiveExecutable = "HEUR-ARCHIVE-EXECUTABLE";
    public const string ArchiveCorrupt = "HEUR-ARCHIVE-CORRUPT";
    public const string ArchiveTooLarge = "HEUR-ARCHIVE-TOO-LARGE";
}

/// <summary>
/// Analyse heuristique statique : noms de fichiers trompeurs, scripts suspects,
/// macros Office, archives piégées. L'entropie et les en-têtes PE sont traités
/// par Guardian.AI et ne sont pas dupliqués ici.
/// </summary>
public sealed class HeuristicAnalyzer : IHeuristicAnalyzer
{
    public const int MaxArchiveEntries = 10_000;
    public const long MaxArchiveUncompressedBytes = 1024L * 1024 * 1024;
    public const double MaxArchiveCompressionRatio = 100.0;

    /// <summary>Le ratio n'est évalué qu'au-delà de cette taille décompressée (10 Mo).</summary>
    public const long RatioCheckMinBytes = 10L * 1024 * 1024;

    /// <summary>Au-delà (100 Mo), l'archive n'est pas ouverte.</summary>
    public const long MaxArchiveFileBytes = 100L * 1024 * 1024;

    private const int MaxScriptChars = 512 * 1024;
    private const long MaxOleScanBytes = 16L * 1024 * 1024;

    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".scr", ".com", ".bat", ".cmd", ".js", ".vbs", ".ps1",
        ".hta", ".jar", ".msi", ".wsf", ".lnk", ".dll"
    };

    private static readonly HashSet<string> DecoyExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".jpg", ".jpeg", ".png", ".gif", ".txt", ".zip", ".mp3", ".mp4"
    };

    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".ps1", ".vbs", ".js", ".bat", ".cmd", ".hta", ".wsf"
    };

    private static readonly HashSet<string> MacroFreeOfficeExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".docx", ".xlsx", ".pptx"
    };

    private static readonly (string Pattern, string Label, double Weight)[] ScriptPatterns =
    [
        ("-encodedcommand", "commande PowerShell encodée", 0.30),
        ("frombase64string", "décodage Base64 à l'exécution", 0.20),
        ("invoke-expression", "exécution dynamique de texte", 0.20),
        ("downloadstring", "téléchargement de code distant", 0.25),
        ("downloadfile", "téléchargement de fichier distant", 0.20),
        ("-windowstyle hidden", "fenêtre masquée", 0.15),
        ("executionpolicy bypass", "contournement de la politique d'exécution", 0.20),
        ("wscript.shell", "exécution via WScript.Shell", 0.15)
    ];

    private static readonly byte[] OleVbaMarker = Encoding.Unicode.GetBytes("_VBA_PROJECT");

    public async Task<HeuristicAnalysisResult> AnalyzeAsync(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        string path = Path.GetFullPath(filePath);

        if (!File.Exists(path))
        {
            throw new FileNotFoundException("Fichier à analyser introuvable.", path);
        }

        var findings = new List<HeuristicFinding>();
        string extension = Path.GetExtension(path);

        CheckFileName(Path.GetFileName(path), findings);

        DetectedFileType type = await FileTypeDetector.DetectAsync(path, cancellationToken);

        if (FileTypeDetector.IsDisguisedExecutable(path, type))
        {
            findings.Add(Finding(
                HeuristicRuleIds.DisguisedExecutable,
                "Exécutable Windows dont l'extension ne correspond pas au contenu.",
                0.50,
                SignalSeverity.High));
        }

        if (ScriptExtensions.Contains(extension))
        {
            await CheckScriptAsync(path, findings, cancellationToken);
        }

        switch (type)
        {
            case DetectedFileType.Zip:
                CheckZip(path, extension, findings, cancellationToken);
                break;

            case DetectedFileType.OleCompound:
                await CheckOleMacrosAsync(path, findings, cancellationToken);
                break;
        }

        double score = Math.Round(Math.Min(1.0, findings.Sum(f => f.Weight)), 2);

        return new HeuristicAnalysisResult
        {
            FilePath = path,
            Score = score,
            Findings = findings
        };
    }

    private static void CheckFileName(string fileName, List<HeuristicFinding> findings)
    {
        if (fileName.Contains('\u202E'))
        {
            findings.Add(Finding(
                HeuristicRuleIds.Rtlo,
                "Le nom contient un caractère d'inversion de texte qui masque la vraie extension.",
                0.60,
                SignalSeverity.High));
        }

        string lastExtension = Path.GetExtension(fileName);
        string innerExtension = Path.GetExtension(Path.GetFileNameWithoutExtension(fileName));

        if (ExecutableExtensions.Contains(lastExtension) && DecoyExtensions.Contains(innerExtension))
        {
            findings.Add(Finding(
                HeuristicRuleIds.DoubleExtension,
                $"Double extension trompeuse ({innerExtension}{lastExtension}).",
                0.45,
                SignalSeverity.High));
        }
    }

    private static async Task CheckScriptAsync(
        string path,
        List<HeuristicFinding> findings,
        CancellationToken cancellationToken)
    {
        string content;

        try
        {
            await using var stream = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 4096, true);
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);

            char[] buffer = new char[MaxScriptChars];
            int read = await reader.ReadBlockAsync(buffer.AsMemory(), cancellationToken);
            content = new string(buffer, 0, read);
        }
        catch (IOException)
        {
            return;
        }
        catch (UnauthorizedAccessException)
        {
            return;
        }

        foreach ((string pattern, string label, double weight) in ScriptPatterns)
        {
            if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                findings.Add(Finding(
                    HeuristicRuleIds.ScriptPattern,
                    $"Script : {label}.",
                    weight,
                    SignalSeverity.Medium));
            }
        }
    }

    private static void CheckZip(
        string path,
        string extension,
        List<HeuristicFinding> findings,
        CancellationToken cancellationToken)
    {
        try
        {
            if (new FileInfo(path).Length > MaxArchiveFileBytes)
            {
                findings.Add(Finding(
                    HeuristicRuleIds.ArchiveTooLarge,
                    "Archive trop volumineuse pour être inspectée.",
                    0.10,
                    SignalSeverity.Low));
                return;
            }

            using ZipArchive zip = ZipFile.OpenRead(path);

            int count = 0;
            long totalUncompressed = 0;
            long totalCompressed = 0;
            bool hasMacro = false;
            bool hasExecutable = false;

            foreach (ZipArchiveEntry entry in zip.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();

                count++;
                totalUncompressed += entry.Length;
                totalCompressed += entry.CompressedLength;

                if (entry.Name.Equals("vbaProject.bin", StringComparison.OrdinalIgnoreCase))
                {
                    hasMacro = true;
                }

                if (ExecutableExtensions.Contains(Path.GetExtension(entry.Name)))
                {
                    hasExecutable = true;
                }

                if (count > MaxArchiveEntries)
                {
                    break;
                }
            }

            double ratio = (double)totalUncompressed / Math.Max(1L, totalCompressed);

            bool bomb = count > MaxArchiveEntries
                || totalUncompressed > MaxArchiveUncompressedBytes
                || (totalUncompressed > RatioCheckMinBytes && ratio > MaxArchiveCompressionRatio);

            if (bomb)
            {
                findings.Add(Finding(
                    HeuristicRuleIds.ArchiveBomb,
                    "Archive suspecte : trop d'entrées, taille ou taux de compression excessifs.",
                    0.45,
                    SignalSeverity.High));
            }

            if (hasMacro)
            {
                AddMacroFinding(extension, findings);
            }

            if (hasExecutable)
            {
                findings.Add(Finding(
                    HeuristicRuleIds.ArchiveExecutable,
                    "L'archive contient un fichier exécutable ou un script.",
                    0.20,
                    SignalSeverity.Medium));
            }
        }
        catch (InvalidDataException)
        {
            findings.Add(Finding(
                HeuristicRuleIds.ArchiveCorrupt,
                "Archive illisible ou malformée.",
                0.15,
                SignalSeverity.Low));
        }
        catch (IOException)
        {
            // Fichier verrouillé ou disparu : pas d'indice exploitable.
        }
        catch (UnauthorizedAccessException)
        {
            // Accès refusé : pas d'indice exploitable.
        }
    }

    private static async Task CheckOleMacrosAsync(
        string path,
        List<HeuristicFinding> findings,
        CancellationToken cancellationToken)
    {
        try
        {
            if (new FileInfo(path).Length > MaxOleScanBytes)
            {
                return;
            }

            byte[] data = await File.ReadAllBytesAsync(path, cancellationToken);

            if (data.AsSpan().IndexOf((ReadOnlySpan<byte>)OleVbaMarker) >= 0)
            {
                AddMacroFinding(Path.GetExtension(path), findings);
            }
        }
        catch (IOException)
        {
            // Fichier verrouillé ou disparu.
        }
        catch (UnauthorizedAccessException)
        {
            // Accès refusé.
        }
    }

    private static void AddMacroFinding(string extension, List<HeuristicFinding> findings)
    {
        if (MacroFreeOfficeExtensions.Contains(extension))
        {
            findings.Add(Finding(
                HeuristicRuleIds.MacroHidden,
                "Macros VBA dans un document dont le format n'en contient pas.",
                0.55,
                SignalSeverity.High));
        }
        else
        {
            findings.Add(Finding(
                HeuristicRuleIds.Macro,
                "Le document contient des macros VBA.",
                0.30,
                SignalSeverity.Medium));
        }
    }

    private static HeuristicFinding Finding(
        string ruleId,
        string description,
        double weight,
        SignalSeverity severity) =>
        new()
        {
            RuleId = ruleId,
            Description = description,
            Weight = weight,
            Severity = severity
        };
}
