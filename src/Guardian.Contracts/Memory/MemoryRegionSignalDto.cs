using Guardian.Contracts.Common;

namespace Guardian.Contracts.Memory;

/// <summary>
/// Signal défensif décrivant une métadonnée d'une plage mémoire sans lecture de contenu privé.
/// </summary>
/// <param name="BaseAddress">Adresse de base de la région mémoire observée.</param>
/// <param name="RegionSizeBytes">Taille de la région mémoire en octets.</param>
/// <param name="Kind">Classification du signal détecté.</param>
/// <param name="Severity">Gravité évaluée du signal.</param>
/// <param name="Description">Explication lisible du signal basé uniquement sur les attributs de protection.</param>
public sealed record MemoryRegionSignalDto(
    long BaseAddress,
    long RegionSizeBytes,
    MemorySignalKind Kind,
    EventSeverity Severity,
    string Description);
