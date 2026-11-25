namespace Guardian.AI.FeatureExtraction;

/// <summary>
/// Calcule l'entropie de Shannon et les métriques statistiques de distribution des octets.
/// </summary>
public static class EntropyCalculator
{
    /// <summary>
    /// Calcule l'entropie de Shannon (en bits par octet, valeur comprise entre 0.0 et 8.0).
    /// Une valeur proche de 8.0 indique une forte probabilité de compression, de chiffrement ou d'obfuscation.
    /// </summary>
    public static double CalculateShannonEntropy(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return 0.0;
        }

        Span<int> frequencies = stackalloc int[256];
        frequencies.Clear();

        for (int i = 0; i < data.Length; i++)
        {
            frequencies[data[i]]++;
        }

        double entropy = 0.0;
        double length = data.Length;

        for (int i = 0; i < 256; i++)
        {
            int count = frequencies[i];
            if (count > 0)
            {
                double probability = count / length;
                entropy -= probability * Math.Log2(probability);
            }
        }

        return Math.Round(entropy, 4);
    }

    /// <summary>
    /// Calcule la variance de la distribution des octets (uniformité).
    /// </summary>
    public static double CalculateByteDistributionVariance(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return 0.0;
        }

        Span<int> frequencies = stackalloc int[256];
        frequencies.Clear();

        for (int i = 0; i < data.Length; i++)
        {
            frequencies[data[i]]++;
        }

        double expected = data.Length / 256.0;
        double sumSquaredDiffs = 0.0;

        for (int i = 0; i < 256; i++)
        {
            double diff = frequencies[i] - expected;
            sumSquaredDiffs += diff * diff;
        }

        return Math.Round(sumSquaredDiffs / 256.0, 4);
    }

    /// <summary>
    /// Calcule la proportion de chaînes imprimables (ASCII/UTF-8) dans le flux.
    /// </summary>
    public static double CalculatePrintableCharacterRatio(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
        {
            return 0.0;
        }

        int printableCount = 0;
        for (int i = 0; i < data.Length; i++)
        {
            byte b = data[i];
            if ((b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13)
            {
                printableCount++;
            }
        }

        return Math.Round((double)printableCount / data.Length, 4);
    }
}
