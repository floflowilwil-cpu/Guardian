using Guardian.Contracts.Common;

namespace Guardian.Contracts.Memory;

/// <summary>
/// Rapport d'analyse défensive des métadonnées mémoire d'un processus.
/// </summary>
/// <remarks>
/// Aucune lecture de contenu mémoire privé, mot de passe, clé ou jeton de session n'est réalisée.
/// </remarks>
/// <param name="ProcessId">Identifiant du processus analysé.</param>
/// <param name="ProcessName">Nom du processus.</param>
/// <param name="AnalyzedAtUtc">Horodatage UTC de l'analyse.</param>
/// <param name="Availability">Disponibilité de l'analyse selon les protections OS et privilèges.</param>
/// <param name="Summary">Résumé de l'analyse et des éventuelles exclusions de sécurité.</param>
/// <param name="Signals">Liste des signaux de métadonnées mémoire relevés.</param>
public sealed record MemoryAnalysisReportDto(
    int ProcessId,
    string ProcessName,
    DateTimeOffset AnalyzedAtUtc,
    FeatureAvailabilityStatus Availability,
    string Summary,
    IReadOnlyList<MemoryRegionSignalDto> Signals);
