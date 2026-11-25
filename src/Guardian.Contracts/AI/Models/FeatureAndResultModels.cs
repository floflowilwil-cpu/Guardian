namespace Guardian.Contracts.AI.Models;

/// <summary>
/// Vecteur de caractéristiques normalisées extrait d'un fichier binaire ou script.
/// </summary>
public sealed record FileFeatureVector
{
    public required string FilePath { get; init; }
    public required string Sha256 { get; init; }
    public long FileSizeBytes { get; init; }
    public double ShannonEntropy { get; init; }
    public bool HasPeHeader { get; init; }
    public int SectionCount { get; init; }
    public int ExecutableSectionCount { get; init; }
    public int AnomalousSectionNameCount { get; init; }
    public double MaxSectionEntropy { get; init; }
    public int ImportedLibrariesCount { get; init; }
    public int ImportedFunctionsCount { get; init; }
    public int SuspiciousApiCallCount { get; init; }
    public bool HasValidDigitalSignature { get; init; }
    public bool HasTlsCallback { get; init; }
    public bool HasResources { get; init; }
    public bool HasDebugInfo { get; init; }
    public bool IsPackedOrObfuscated { get; init; }
    public double SuspiciousStringRatio { get; init; }
    public double ByteDistributionVariance { get; init; }
    public IReadOnlyDictionary<string, double> CustomFeatures { get; init; } = new Dictionary<string, double>();
}

/// <summary>
/// Facteur explicatif unitaire justifiant un score ou une décision IA (Explicabilité).
/// </summary>
public sealed record ContributingFactor
{
    public required string Name { get; init; }
    public required double Weight { get; init; }
    public required double ScoreContribution { get; init; }
    public required double RawValue { get; init; }
    public required FactorImpact Impact { get; init; }
    public required string Explanation { get; init; }
}

/// <summary>
/// Résultat complet de classification d'une menace par l'IA.
/// </summary>
public sealed record ThreatClassificationResult
{
    public required ThreatVerdict Verdict { get; init; }
    public required double Probability { get; init; }
    public required double CalibratedProbability { get; init; }
    public required double Confidence { get; init; }
    public double AnomalyScore { get; init; }
    public string? ThreatFamily { get; init; }
    public required string ModelVersion { get; init; }
    public double LatencyMs { get; init; }
    public required IReadOnlyList<ContributingFactor> ContributingFactors { get; init; }
    public required IReadOnlyList<string> Limitations { get; init; }
    public DateTime EvaluatedAtUtc { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Contexte d'évaluation composite pour le calcul du score de risque.
/// </summary>
public sealed record RiskEvaluationContext
{
    public required string EntityId { get; init; }
    public string? FilePath { get; init; }
    public double? SignatureScore { get; init; }
    public double? HeuristicScore { get; init; }
    public double? AiClassifierScore { get; init; }
    public double? BehavioralScore { get; init; }
    public double? AnomalyScore { get; init; }
    public bool HasValidDigitalSignature { get; init; }
    public bool IsKnownSystemComponent { get; init; }
    public int AssociatedNetworkEventCount { get; init; }
    public int AssociatedProcessEventCount { get; init; }
    public int AssociatedRegistryEventCount { get; init; }
    public IReadOnlyDictionary<string, string> ContextualMetadata { get; init; } = new Dictionary<string, string>();
}

/// <summary>
/// Résultat du moteur de calcul du score de risque composite calibré.
/// </summary>
public sealed record RiskScoreResult
{
    public required string EntityId { get; init; }
    public required double Score { get; init; }
    public required RiskLevel Level { get; init; }
    public required double CalibratedProbability { get; init; }
    public required double Confidence { get; init; }
    public required IReadOnlyList<ContributingFactor> ContributingFactors { get; init; }
    public required string RecommendedPolicyAction { get; init; }
    public required string ModelVersion { get; init; }
    public required IReadOnlyList<string> Caveats { get; init; }
    public DateTime CalculatedAtUtc { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Contexte pour l'analyse d'anomalie.
/// </summary>
public sealed record AnomalyEvaluationContext
{
    public required string EntityId { get; init; }
    public required double[] FeatureVector { get; init; }
    public IReadOnlyDictionary<string, string> Attributes { get; init; } = new Dictionary<string, string>();
}

/// <summary>
/// Résultat de la détection d'anomalie.
/// </summary>
public sealed record AnomalyDetectionResult
{
    public required string EntityId { get; init; }
    public required bool IsAnomaly { get; init; }
    public required double AnomalyScore { get; init; }
    public required double Confidence { get; init; }
    public required string Explanation { get; init; }
    public DateTime EvaluatedAtUtc { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Signal de sécurité unifié collecté depuis une source (fichier, processus, registre, réseau, mémoire).
/// </summary>
public sealed record SecuritySignal
{
    public required string SignalId { get; init; }
    public required SignalSource Source { get; init; }
    public required SignalSeverity Severity { get; init; }
    public required string Category { get; init; }
    public required string EntityId { get; init; }
    public required string Description { get; init; }
    public required DateTime TimestampUtc { get; init; }
    public IReadOnlyDictionary<string, string> Metadata { get; init; } = new Dictionary<string, string>();
}

/// <summary>
/// Nœud dans le graphe d'incident de sécurité.
/// </summary>
public sealed record ThreatGraphNode
{
    public required string NodeId { get; init; }
    public required string Label { get; init; }
    public required string NodeType { get; init; }
    public required double RiskScore { get; init; }
    public IReadOnlyDictionary<string, string> Properties { get; init; } = new Dictionary<string, string>();
}

/// <summary>
/// Lien directionnel dans le graphe d'incident.
/// </summary>
public sealed record ThreatGraphEdge
{
    public required string SourceNodeId { get; init; }
    public required string TargetNodeId { get; init; }
    public required string RelationType { get; init; }
    public required double Confidence { get; init; }
    public required DateTime TimestampUtc { get; init; }
}

/// <summary>
/// Graphe de corrélation d'une menace reliant fichiers, processus, clés de registre et réseau.
/// </summary>
public sealed record ThreatGraph
{
    public required string IncidentId { get; init; }
    public required string Title { get; init; }
    public required double CompositeRiskScore { get; init; }
    public required IReadOnlyList<ThreatGraphNode> Nodes { get; init; }
    public required IReadOnlyList<ThreatGraphEdge> Edges { get; init; }
    public string? RootCauseNodeId { get; init; }
    public DateTime CreatedAtUtc { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Entrée chronologique dans la timeline forensique assistée.
/// </summary>
public sealed record ThreatTimelineEntry
{
    public required string EventId { get; init; }
    public required DateTime TimestampUtc { get; init; }
    public required SignalSource Source { get; init; }
    public required SignalSeverity Severity { get; init; }
    public required string Description { get; init; }
    public required bool IsMilestone { get; init; }
    public IReadOnlyList<string> RelatedNodeIds { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Requête utilisateur ou système adressée à l'assistant conversationnel local.
/// </summary>
public sealed record AssistantRequest
{
    public required string Query { get; init; }
    public string? SessionId { get; init; }
    public IReadOnlyList<SecuritySignal> RecentSignals { get; init; } = Array.Empty<SecuritySignal>();
    public ThreatGraph? AssociatedThreatGraph { get; init; }
}

/// <summary>
/// Réponse sécurisée émise par l'assistant local (gouverné et sans privilège direct).
/// </summary>
public sealed record AssistantResponse
{
    public required string ResponseText { get; init; }
    public required double Confidence { get; init; }
    public required IReadOnlyList<string> EvidenceItems { get; init; }
    public required IReadOnlyList<string> RecommendedActions { get; init; }
    public required bool HasSecurityWarning { get; init; }
    public string? SecurityWarningDetail { get; init; }
    public DateTime GeneratedAtUtc { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Évaluation de sécurité d'une entrée vis-à-vis des attaques IA.
/// </summary>
public sealed record AiSecurityEvaluation
{
    public required bool IsSafe { get; init; }
    public required AiAttackType DetectedAttackType { get; init; }
    public required double RiskConfidence { get; init; }
    public required string AnalysisDetail { get; init; }
    public IReadOnlyList<string> BlockedPatterns { get; init; } = Array.Empty<string>();
}

/// <summary>
/// Métadonnées et fiche descriptive d'un modèle d'IA.
/// </summary>
public sealed record ModelMetadata
{
    public required string ModelId { get; init; }
    public required string Version { get; init; }
    public required string Architecture { get; init; }
    public required string Sha256Hash { get; init; }
    public required DateTime TrainedAtUtc { get; init; }
    public required double Accuracy { get; init; }
    public required double Precision { get; init; }
    public required double Recall { get; init; }
    public required double F1Score { get; init; }
    public required double BrierScoreCalibration { get; init; }
    public required double FalsePositiveRate { get; init; }
    public required IReadOnlyList<string> InputFeatures { get; init; }
    public required bool IsSigned { get; init; }
}

/// <summary>
/// Rapport d'évaluation statistique d'un modèle sur un jeu de données de référence.
/// </summary>
public sealed record ModelEvaluationReport
{
    public required string ModelId { get; init; }
    public required string ModelVersion { get; init; }
    public required int TotalSamples { get; init; }
    public required int BenignSamples { get; init; }
    public required int MaliciousSamples { get; init; }
    public required double Accuracy { get; init; }
    public required double Precision { get; init; }
    public required double Recall { get; init; }
    public required double F1Score { get; init; }
    public required double BrierScoreCalibration { get; init; }
    public required double FalsePositiveRate { get; init; }
    public required double FalseNegativeRate { get; init; }
    public required double AverageLatencyMs { get; init; }
    public required bool MeetsDeploymentGate { get; init; }
    public DateTime EvaluatedAtUtc { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Résultat d'un rollback vers une version antérieure de modèle.
/// </summary>
public sealed record ModelRollbackResult
{
    public required bool Success { get; init; }
    public required string PreviousVersion { get; init; }
    public required string ActiveVersion { get; init; }
    public required string Reason { get; init; }
    public DateTime RolledBackAtUtc { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Rapport de santé du sous-système IA.
/// </summary>
public sealed record AiHealthStatus
{
    public required EngineHealthState State { get; init; }
    public required string ActiveModelVersion { get; init; }
    public required bool ClassifierOperational { get; init; }
    public required bool AnomalyDetectorOperational { get; init; }
    public required bool AssistantOperational { get; init; }
    public required double AverageInferenceLatencyMs { get; init; }
    public string? DegradedReason { get; init; }
    public DateTime CheckedAtUtc { get; init; } = DateTime.UtcNow;
}
