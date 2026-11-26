using Guardian.Contracts.AI.Models;
using Guardian.Contracts.Scanning;
using Guardian.Contracts.Signatures;
using Guardian.Scanner.FileTypes;
using Guardian.Scanner.Hashing;

namespace Guardian.Scanner;

/// <summary>
/// Enchaîne les étapes d'analyse d'un fichier : taille, type réel, SHA-256, signatures.
/// </summary>
public sealed class FileScanner : IFileScanner
{
    private readonly ISignatureProvider _signatures;

    public FileScanner(ISignatureProvider signatures)
    {
        ArgumentNullException.ThrowIfNull(signatures);
        _signatures = signatures;
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

            var reasons = new List<string>();
            ThreatVerdict verdict = ThreatVerdict.Clean;

            if (disguised)
            {
                verdict = ThreatVerdict.Suspicious;
                reasons.Add("Exécutable Windows déguisé : l'extension ne correspond pas au contenu.");
            }

            if (match is not null)
            {
                verdict = ThreatVerdict.Malicious;
                reasons.Add($"Signature connue : {match.ThreatName} ({match.SignatureId}).");
            }

            if (reasons.Count == 0)
            {
                reasons.Add("Aucune signature connue ni anomalie de type détectée.");
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
                Signature = match
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

    private static FileScanResult Failure(string path, ThreatVerdict verdict, string reason) =>
        new()
        {
            FilePath = path,
            Verdict = verdict,
            Reasons = [reason]
        };
}
