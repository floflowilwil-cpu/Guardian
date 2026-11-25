namespace Guardian.Contracts.AI.Models;

/// <summary>
/// Verdict rendu par le classifieur d'intelligence artificielle.
/// </summary>
public enum ThreatVerdict
{
    /// <summary>
    /// Fichier ou entité évalué comme sain.
    /// </summary>
    Clean,

    /// <summary>
    /// Entité suspecte nécessitant une analyse approfondie ou une confirmation.
    /// </summary>
    Suspicious,

    /// <summary>
    /// Menace malveillante confirmée par les modèles probabilistes.
    /// </summary>
    Malicious,

    /// <summary>
    /// Score intermédiaire ou signaux insuffisants pour trancher.
    /// </summary>
    Inconclusive,

    /// <summary>
    /// Échec de l'évaluation ou format non supporté, basculement en mode dégradé.
    /// </summary>
    Error
}

/// <summary>
/// Niveau de risque normalisé de 0 à 100.
/// </summary>
public enum RiskLevel
{
    /// <summary>
    /// Risque négligeable (0-19).
    /// </summary>
    Minimal,

    /// <summary>
    /// Risque faible (20-39).
    /// </summary>
    Low,

    /// <summary>
    /// Risque modéré (40-69).
    /// </summary>
    Medium,

    /// <summary>
    /// Risque élevé (70-89).
    /// </summary>
    High,

    /// <summary>
    /// Risque critique (90-100).
    /// </summary>
    Critical
}

/// <summary>
/// Impact d'un facteur explicatif sur le score de risque global.
/// </summary>
public enum FactorImpact
{
    /// <summary>
    /// Le facteur accroît la probabilité de malveillance.
    /// </summary>
    IncreasesRisk,

    /// <summary>
    /// Le facteur diminue la probabilité de malveillance (facteur de confiance).
    /// </summary>
    DecreasesRisk,

    /// <summary>
    /// Le facteur est informatif sans peser significativement sur le score.
    /// </summary>
    Neutral
}

/// <summary>
/// Source d'un signal de sécurité pour le moteur de corrélation.
/// </summary>
public enum SignalSource
{
    /// <summary>
    /// Système de fichiers (création, modification, entropie, exécutable).
    /// </summary>
    File,

    /// <summary>
    /// Processus (création, injection, mémoire, arbre de processus).
    /// </summary>
    Process,

    /// <summary>
    /// Registre Windows (persistance, run keys, autorun).
    /// </summary>
    Registry,

    /// <summary>
    /// Flux et connexions réseau (DNS, C2, ports inhabituels, volumétrie).
    /// </summary>
    Network,

    /// <summary>
    /// Mémoire système (pages privées exécutables, modules suspects).
    /// </summary>
    Memory,

    /// <summary>
    /// Intégrité système et démarrage (Secure Boot, intégrité composants).
    /// </summary>
    System
}

/// <summary>
/// Sévérité d'un signal de sécurité.
/// </summary>
public enum SignalSeverity
{
    Informational,
    Low,
    Medium,
    High,
    Critical
}

/// <summary>
/// Type d'attaque détectée contre le système d'intelligence artificielle.
/// </summary>
public enum AiAttackType
{
    None,
    PromptInjection,
    DataPoisoning,
    AdversarialPerturbation,
    ModelExtraction,
    JailbreakAttempt
}

/// <summary>
/// État d'observabilité et de santé du sous-système d'intelligence artificielle.
/// </summary>
public enum EngineHealthState
{
    Healthy,
    Degraded,
    Stopped,
    OutOfDate,
    Unknown
}
