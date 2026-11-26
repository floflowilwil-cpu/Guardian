using Guardian.Contracts.AI.Models;

namespace Guardian.AI.Classification;

/// <summary>
/// Encodage stable des caractéristiques PE pour l'entraînement et l'inférence.
/// Toute modification de l'ordre, du type ou du sens des colonnes exige une nouvelle version.
/// </summary>
public static class StaticPeFeatureSchemaV1
{
    public const string SchemaId = "guardian.static-pe.v1";
    public const int FeatureCount = 9;

    public static IReadOnlyList<string> FeatureNames { get; } = Array.AsReadOnly(new[]
    {
        "file_size_bytes",
        "shannon_entropy",
        "section_count",
        "executable_section_count",
        "anomalous_section_name_count",
        "max_section_entropy",
        "suspicious_api_string_match_count",
        "is_packed_or_obfuscated",
        "byte_distribution_variance"
    });

    /// <summary>Construit le vecteur float32 dans l'ordre exact du contrat v1.</summary>
    public static float[] Encode(FileFeatureVector features)
    {
        ArgumentNullException.ThrowIfNull(features);
        if (!features.HasPeHeader)
        {
            throw new ArgumentException("Le schéma guardian.static-pe.v1 accepte uniquement les fichiers PE.", nameof(features));
        }

        float[] values =
        [
            features.FileSizeBytes,
            (float)features.ShannonEntropy,
            features.SectionCount,
            features.ExecutableSectionCount,
            features.AnomalousSectionNameCount,
            (float)features.MaxSectionEntropy,
            features.SuspiciousApiCallCount,
            features.IsPackedOrObfuscated ? 1f : 0f,
            (float)features.ByteDistributionVariance
        ];

        if (values.Length != FeatureCount || values.Any(value => !float.IsFinite(value)))
        {
            throw new ArgumentOutOfRangeException(nameof(features), "Les caractéristiques encodées doivent être finies et contenir exactement neuf valeurs.");
        }

        return values;
    }
}
