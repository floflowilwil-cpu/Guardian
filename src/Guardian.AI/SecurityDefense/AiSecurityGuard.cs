using System.Collections.Concurrent;
using System.Text.RegularExpressions;
using Guardian.Contracts.AI;
using Guardian.Contracts.AI.Models;

namespace Guardian.AI.SecurityDefense;

/// <summary>
/// Bouclier de protection des modèles d'IA contre les attaques adversariales (IAiSecurityGuard).
/// Détecte prompt injections, data poisoning, perturbations adversariales (evasion),
/// extraction de modèles et jailbreaks.
/// </summary>
public sealed class AiSecurityGuard : IAiSecurityGuard
{
    private static readonly string[] PromptInjectionPatterns =
    [
        @"ignore\s+(all\s+)?(previous|prior)\s+instructions",
        @"system\s+override",
        @"you\s+are\s+now\s+(in\s+)?(unrestricted|developer|jailbreak)\s+mode",
        @"bypass\s+guardian\s+policy",
        @"disregard\s+all\s+safety\s+checks",
        @"delete\s+(all\s+)?quarantined\s+files",
        @"grant\s+root\s+access",
        @"drop\s+table",
        @"powershell\s+(-enc|-encodedcommand)",
        @"cmd\.exe\s+/c",
        @"format\s+c:",
        @"curl\s+https?://",
        @"wget\s+https?://"
    ];

    private readonly ConcurrentDictionary<string, List<(DateTime Timestamp, double Score)>> _clientQueryHistory = new();
    private const int MaxQueriesPerMinute = 120;
    private const int MaxProbingQueriesPerMinute = 20;

    /// <inheritdoc />
    public Task<AiSecurityEvaluation> InspectTextAsync(
        string input, 
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(input))
        {
            return Task.FromResult(new AiSecurityEvaluation
            {
                IsSafe = true,
                DetectedAttackType = AiAttackType.None,
                RiskConfidence = 0.0,
                AnalysisDetail = "Entrée vide."
            });
        }

        var blockedPatterns = new List<string>();

        foreach (var pattern in PromptInjectionPatterns)
        {
            if (Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
            {
                blockedPatterns.Add(pattern);
            }
        }

        if (blockedPatterns.Count > 0)
        {
            bool isJailbreak = input.Contains("jailbreak", StringComparison.OrdinalIgnoreCase) ||
                               input.Contains("unrestricted", StringComparison.OrdinalIgnoreCase);

            var attackType = isJailbreak ? AiAttackType.JailbreakAttempt : AiAttackType.PromptInjection;

            return Task.FromResult(new AiSecurityEvaluation
            {
                IsSafe = false,
                DetectedAttackType = attackType,
                RiskConfidence = 0.98,
                AnalysisDetail = $"Tentative détectée : pattern malveillant identifié dans la requête ou la métadonnée ({blockedPatterns.Count} motif(s)).",
                BlockedPatterns = blockedPatterns
            });
        }

        return Task.FromResult(new AiSecurityEvaluation
        {
            IsSafe = true,
            DetectedAttackType = AiAttackType.None,
            RiskConfidence = 0.05,
            AnalysisDetail = "Texte inspecté et validé conforme aux règles de sécurité."
        });
    }

    /// <inheritdoc />
    public Task<AiSecurityEvaluation> InspectFeaturesAsync(
        FileFeatureVector features, 
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // 1. Détection de manipulation d'overlay PE (padding artificiel pour fausser la distribution)
        if (features.FileSizeBytes > 50_000_000 && features.ShannonEntropy < 1.0)
        {
            return Task.FromResult(new AiSecurityEvaluation
            {
                IsSafe = false,
                DetectedAttackType = AiAttackType.AdversarialPerturbation,
                RiskConfidence = 0.92,
                AnalysisDetail = "Fichier anormalement volumineux avec entropie quasi-nulle (remplissage d'octets nuls pour contourner l'analyse d'entropie).",
                BlockedPatterns = ["ZeroBytePaddingAdversarial"]
            });
        }

        // 2. Détection de contradiction adversariale : binaire obfusqué mais simulant une signature nulle ou corrompue
        if (features.IsPackedOrObfuscated && features.SuspiciousApiCallCount >= 5 && features.ShannonEntropy > 7.6)
        {
            // Vérifier si le chemin ou le binaire contient des injections de prompt dans ses métadonnées
            if (features.CustomFeatures.ContainsKey("IsAdversarialEvasion"))
            {
                return Task.FromResult(new AiSecurityEvaluation
                {
                    IsSafe = false,
                    DetectedAttackType = AiAttackType.AdversarialPerturbation,
                    RiskConfidence = 0.95,
                    AnalysisDetail = "Tentative d'évasion adversariale détectée par altération intentionnelle des caractéristiques.",
                    BlockedPatterns = ["FeatureEvasion"]
                });
            }
        }

        return Task.FromResult(new AiSecurityEvaluation
        {
            IsSafe = true,
            DetectedAttackType = AiAttackType.None,
            RiskConfidence = 0.05,
            AnalysisDetail = "Caractéristiques validées, aucune perturbation adversariale anormale identifiée."
        });
    }

    /// <inheritdoc />
    public Task<bool> TrackAndDetectExtractionAttemptAsync(
        string clientId, 
        double modelProbability, 
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        DateTime now = DateTime.UtcNow;
        var history = _clientQueryHistory.GetOrAdd(clientId, _ => []);

        lock (history)
        {
            // Nettoyage des requêtes de plus d'une minute
            history.RemoveAll(entry => (now - entry.Timestamp) > TimeSpan.FromMinutes(1));
            history.Add((now, modelProbability));

            // Détection 1 : Cadence globale excessive
            if (history.Count > MaxQueriesPerMinute)
            {
                return Task.FromResult(true);
            }

            // Détection 2 : Probing intentionnel de la frontière de décision (0.48 <= P <= 0.52)
            int boundaryQueries = history.Count(entry => entry.Score >= 0.48 && entry.Score <= 0.52);
            if (boundaryQueries > MaxProbingQueriesPerMinute)
            {
                return Task.FromResult(true); // Extraction de frontière suspectée
            }
        }

        return Task.FromResult(false);
    }

    /// <inheritdoc />
    public Task<bool> ValidateTrainingSampleIntegrityAsync(
        FileFeatureVector sample, 
        ThreatVerdict declaredLabel, 
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // Règle 1 : Un échantillon déclaré Clean avec des API massives d'injection et une forte entropie
        // est un empoisonnement évident (data poisoning)
        if (declaredLabel == ThreatVerdict.Clean)
        {
            if (sample.SuspiciousApiCallCount >= 4 && sample.ShannonEntropy > 7.5 && sample.IsPackedOrObfuscated)
            {
                return Task.FromResult(false); // Rejeté : tentative d'empoisonnement
            }
        }

        // Règle 2 : Un échantillon déclaré Malicious qui est un binaire système signé intègre
        if (declaredLabel == ThreatVerdict.Malicious)
        {
            if (sample.HasValidDigitalSignature && sample.SuspiciousApiCallCount == 0 && sample.ShannonEntropy < 6.5)
            {
                return Task.FromResult(false); // Rejeté : tentative de création artificielle de faux positifs
            }
        }

        return Task.FromResult(true); // Valide
    }
}
