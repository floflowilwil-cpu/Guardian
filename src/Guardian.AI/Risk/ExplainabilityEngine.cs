using Guardian.Contracts.AI.Models;

namespace Guardian.AI.Risk;

/// <summary>
/// Produit des explications heuristiques lisibles à partir des caractéristiques et scores fournis.
/// Ces facteurs ne sont pas des valeurs SHAP ni une décomposition mathématique exacte du score final.
/// </summary>
public sealed class ExplainabilityEngine
{
    /// <summary>
    /// Décompose un vecteur de caractéristiques et génère la liste ordonnée des facteurs d'influence.
    /// </summary>
    public IReadOnlyList<ContributingFactor> ExplainFileFeatures(FileFeatureVector features, double modelProbability)
    {
        var factors = new List<ContributingFactor>();

        // 1. Entropie globale
        if (features.ShannonEntropy > 7.2)
        {
            factors.Add(new ContributingFactor
            {
                Name = "Entropie globale élevée",
                Weight = 0.25,
                ScoreContribution = 0.25 * (features.ShannonEntropy / 8.0),
                RawValue = features.ShannonEntropy,
                Impact = FactorImpact.IncreasesRisk,
                Explanation = $"L'entropie de Shannon de {features.ShannonEntropy:F2} indique un contenu fortement compressé, chiffré ou obfusqué (typiquement observé dans les packers et malwares)."
            });
        }
        else if (features.ShannonEntropy < 6.0 && features.ShannonEntropy > 0.0)
        {
            factors.Add(new ContributingFactor
            {
                Name = "Entropie standard",
                Weight = 0.10,
                ScoreContribution = -0.08,
                RawValue = features.ShannonEntropy,
                Impact = FactorImpact.DecreasesRisk,
                Explanation = $"L'entropie de {features.ShannonEntropy:F2} correspond à un binaire classique non compressé."
            });
        }

        // 2. Sections anormales ou packers
        if (features.AnomalousSectionNameCount > 0 || features.IsPackedOrObfuscated)
        {
            factors.Add(new ContributingFactor
            {
                Name = "Indicateur d'empaquetage / sections anormales",
                Weight = 0.30,
                ScoreContribution = 0.28,
                RawValue = features.AnomalousSectionNameCount,
                Impact = FactorImpact.IncreasesRisk,
                Explanation = $"Présence de {features.AnomalousSectionNameCount} sections suspectes ou signature de packer identifiée, masquant potentiellement le code malveillant."
            });
        }

        // 3. Appels d'API sensibles
        if (features.SuspiciousApiCallCount >= 3)
        {
            factors.Add(new ContributingFactor
            {
                Name = "Nombre élevé d'API d'injection et de persistance",
                Weight = 0.35,
                ScoreContribution = Math.Min(0.35, features.SuspiciousApiCallCount * 0.07),
                RawValue = features.SuspiciousApiCallCount,
                Impact = FactorImpact.IncreasesRisk,
                Explanation = $"Détection de {features.SuspiciousApiCallCount} API sensibles fréquemment associées à l'injection mémoire, la manipulation de threads ou la persistance (e.g. VirtualAlloc, WriteProcessMemory)."
            });
        }

        // 4. La signature est un élément de contexte, pas une preuve d'innocuité.
        if (features.HasValidDigitalSignature)
        {
            factors.Add(new ContributingFactor
            {
                Name = "Signature déclarée valide (contexte)",
                Weight = 0.30,
                ScoreContribution = 0.0,
                RawValue = 1.0,
                Impact = FactorImpact.Neutral,
                Explanation = "Une signature a été déclarée valide en amont; l'extracteur actuel ne la vérifie pas et cette information ne réduit pas le score du classifieur."
            });
        }

        // 5. Sections exécutables multiples
        if (features.ExecutableSectionCount > 1)
        {
            factors.Add(new ContributingFactor
            {
                Name = "Sections exécutables multiples",
                Weight = 0.15,
                ScoreContribution = 0.12,
                RawValue = features.ExecutableSectionCount,
                Impact = FactorImpact.IncreasesRisk,
                Explanation = $"Le binaire contient {features.ExecutableSectionCount} sections marquées comme exécutables, ce qui est inhabituel pour les applications légitimes standards."
            });
        }

        // 6. Entropie maximale par section
        if (features.MaxSectionEntropy > 7.5)
        {
            factors.Add(new ContributingFactor
            {
                Name = "Section hautement chiffrée",
                Weight = 0.20,
                ScoreContribution = 0.18,
                RawValue = features.MaxSectionEntropy,
                Impact = FactorImpact.IncreasesRisk,
                Explanation = $"La section la plus dense atteint une entropie de {features.MaxSectionEntropy:F2}/8.0, suggérant une charge utile chiffrée embarquée."
            });
        }

        // Tri par magnitude du facteur heuristique, pas par attribution de modèle.
        return factors.OrderByDescending(f => Math.Abs(f.ScoreContribution)).ToList();
    }

    /// <summary>
    /// Explique les composantes d'un contexte de risque composite (moteurs multiples).
    /// </summary>
    public IReadOnlyList<ContributingFactor> ExplainRiskContext(RiskEvaluationContext context)
    {
        var factors = new List<ContributingFactor>();

        if (context.SignatureScore.HasValue && context.SignatureScore.Value > 0)
        {
            factors.Add(new ContributingFactor
            {
                Name = "Détection par signature / réputation",
                Weight = 0.40,
                ScoreContribution = context.SignatureScore.Value * 0.40,
                RawValue = context.SignatureScore.Value,
                Impact = FactorImpact.IncreasesRisk,
                Explanation = $"La base de signatures locale a identifié une correspondance avec un score de {context.SignatureScore.Value:F2}."
            });
        }

        if (context.AiClassifierScore.HasValue)
        {
            double aiScore = context.AiClassifierScore.Value;
            factors.Add(new ContributingFactor
            {
                Name = "Score du classifieur IA",
                Weight = 0.30,
                ScoreContribution = (aiScore - 0.5) * 0.30 * 2,
                RawValue = aiScore,
                Impact = aiScore >= 0.5 ? FactorImpact.IncreasesRisk : FactorImpact.DecreasesRisk,
                Explanation = $"Le modèle d'apprentissage automatique estime la probabilité de malveillance à {aiScore:P1}."
            });
        }

        if (context.HeuristicScore.HasValue && context.HeuristicScore.Value > 0)
        {
            factors.Add(new ContributingFactor
            {
                Name = "Règles heuristiques statiques",
                Weight = 0.20,
                ScoreContribution = context.HeuristicScore.Value * 0.20,
                RawValue = context.HeuristicScore.Value,
                Impact = FactorImpact.IncreasesRisk,
                Explanation = $"Les règles heuristiques ont accumulé un score de suspicion de {context.HeuristicScore.Value:F2}."
            });
        }

        if (context.BehavioralScore.HasValue && context.BehavioralScore.Value > 0)
        {
            factors.Add(new ContributingFactor
            {
                Name = "Activité comportementale dynamique",
                Weight = 0.30,
                ScoreContribution = context.BehavioralScore.Value * 0.30,
                RawValue = context.BehavioralScore.Value,
                Impact = FactorImpact.IncreasesRisk,
                Explanation = $"Des signaux comportementaux suspects (processus/fichiers/registre) ont été observés (score: {context.BehavioralScore.Value:F2})."
            });
        }

        if (context.HasValidDigitalSignature)
        {
            factors.Add(new ContributingFactor
            {
                Name = "Signature numérique vérifiée (contexte)",
                Weight = 0.25,
                ScoreContribution = 0.0,
                RawValue = 1.0,
                Impact = FactorImpact.Neutral,
                Explanation = "Une signature a été déclarée valide en amont. Cela ne réduit pas, à lui seul, les signaux de menace."
            });
        }

        if (context.IsKnownSystemComponent)
        {
            factors.Add(new ContributingFactor
            {
                Name = "Composant système (contexte)",
                Weight = 0.35,
                ScoreContribution = 0.0,
                RawValue = 1.0,
                Impact = FactorImpact.Neutral,
                Explanation = "Le contexte système est conservé pour exiger une confirmation humaine si une remédiation est envisagée."
            });
        }

        return factors.OrderByDescending(f => Math.Abs(f.ScoreContribution)).ToList();
    }
}
