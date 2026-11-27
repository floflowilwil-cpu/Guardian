using Guardian.Contracts.AI.Models;
using Guardian.Contracts.Heuristics;
using Guardian.Contracts.Scanning;
using Guardian.Contracts.Signatures;
using Guardian.Scanner.FileTypes;
using Guardian.Scanner.Hashing;

namespace Guardian.Scanner;

/// <summary>
/// Enchaîne les étapes d'analyse d'un fichier : taille, type réel, SHA-256,
/// signatures et, si disponible, analyse heuristique.
/// </summary>
public sealed class FileScanner : IFileScanner
{
    /// <summary>Score heuristique à partir duquel un fichier est déclaré suspect.</summary>
    public const double SuspiciousHeuristicThreshold = 0.60;

    private readonly ISignatureProvider _signatures;
    private readonly IHeuristicAnalyzer? _heuristics;

    public FileScanner(ISignatureProvider signatures, IHeuristicAnalyzer? heuristics = null)
    {
        ArgumentNullException.ThrowIfNull(signatures);
        _signatures = signatures;
        _heuristics = heuristics;
    }

    public async Task<FileScanResult> ScanAsync(
        FileScanRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.FilePath);

        string path = request.FilePath;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            var info = new FileInfo(path);
            if (!info.Exists)
            {
                return Failure(path, ThreatVerdict.Error, "Fichier introuvable.");
            }

            if (info.Length > request.MaxFileSizeBytes)
            {
                return new FileScanResult
                {
                    FilePath = path,
                    Verdict = ThreatVerdict.Inconclusive,
                    FileSizeBytes = info.Length,
                    Reasons = [$"Fichier trop volumineux pour l'analyse ({info.Length} octets)."]
                };
            }

            DetectedFileType type = await FileTypeDetector.DetectAsync(path, cancellationToken);
            string sha256 = await FileHasher.ComputeSha256Async(path, cancellationToken);
            SignatureMatch? match = await _signatures.FindBySha256Async(sha256, cancellationToken);
            bool disguised = FileTypeDetector.IsDisguisedExecutable(path, type);
            HeuristicAnalysisResult? heuristic = await TryAnalyzeAsync(path, cancellationToken);

            var reasons = new List<string>();
            ThreatVerdict verdict = ThreatVerdict.Clean;

            if (disguised)
            {
                verdict = ThreatVerdict.Suspicious;
                reasons.Add("Exécutable Windows déguisé : l'extension ne correspond pas au contenu.");
            }

            if (heuristic is not null)
            {
                foreach (HeuristicFinding finding in heuristic.Findings)
                {
                    reasons.Add($"Heuristique {finding.RuleId} : {finding.Description}");
                }

                if (heuristic.Score >= SuspiciousHeuristicThreshold)
                {
                    verdict = ThreatVerdict.Suspicious;
                    reasons.Add(
                        $"Score heuristique élevé : {heuristic.Score:F2} (seuil {SuspiciousHeuristicThreshold:F2}).");
                }
            }

            if (match is not null)
            {
                verdict = ThreatVerdict.Malicious;
                reasons.Add($"Signature connue : {match.ThreatName} ({match.SignatureId}).");
            }

            if (reasons.Count == 0)
            {
                reasons.Add("Aucune signature connue ni anomalie détectée.");
            }

            return new FileScanResult
            {
                FilePath = path,
                Verdict = verdict,
                Reasons = reasons,
                Sha256 = sha256,
                FileSizeBytes = info.Length,
                DetectedFileType = type.ToString(),
                IsDisguisedExecutable = disguised,
                Signature = match,
                HeuristicScore = heuristic?.Score ?? 0.0,
                HeuristicFindings = heuristic?.Findings ?? Array.Empty<HeuristicFinding>()
            };
        }
        catch (UnauthorizedAccessException)
        {
            return Failure(path, ThreatVerdict.Error, "Accès au fichier refusé.");
        }
        catch (NotSupportedException)
        {
            return Failure(path, ThreatVerdict.Error, "Chemin de fichier invalide.");
        }
        catch (IOException ex)
        {
            return Failure(path, ThreatVerdict.Error, $"Erreur de lecture : {ex.Message}");
        }
    }

    private async Task<HeuristicAnalysisResult?> TryAnalyzeAsync(
        string path,
        CancellationToken cancellationToken)
    {
        if (_heuristics is null)
        {
            return null;
        }

        try
        {
            return await _heuristics.AnalyzeAsync(path, cancellationToken);
        }
        catch (IOException)
        {
            return null;
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    private static FileScanResult Failure(string path, ThreatVerdict verdict, string reason) =>
        new()
        {
            FilePath = path,
            Verdict = verdict,
            Reasons = [reason]
        };
}