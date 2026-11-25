using System.Text;
using Guardian.AI.FeatureExtraction;

namespace Guardian.UnitTests.AI;

public class FeatureExtractionTests
{
    [Fact]
    public void CalculateShannonEntropy_ZeroEntropyForUniformBytes()
    {
        // 1000 octets identiques = entropie nulle
        byte[] uniformData = new byte[1000];
        Array.Fill(uniformData, (byte)0x41);

        double entropy = EntropyCalculator.CalculateShannonEntropy(uniformData);
        Assert.Equal(0.0, entropy);
    }

    [Fact]
    public void CalculateShannonEntropy_HighEntropyForRandomBytes()
    {
        // Octets pseudo-aléatoires couvrant tout l'espace = entropie proche de 8.0
        byte[] randomData = new byte[25600];
        var rand = new Random(42);
        rand.NextBytes(randomData);

        double entropy = EntropyCalculator.CalculateShannonEntropy(randomData);
        Assert.InRange(entropy, 7.8, 8.0);
    }

    [Fact]
    public void CalculatePrintableCharacterRatio_DetectsAsciiText()
    {
        byte[] textData = Encoding.ASCII.GetBytes("This is a clean ASCII string representing normal text data.");
        double ratio = EntropyCalculator.CalculatePrintableCharacterRatio(textData);
        Assert.True(ratio > 0.95);
    }

    [Fact]
    public void PeFeatureExtractor_ExtractsNonPeFileGracefully()
    {
        byte[] scriptBytes = Encoding.UTF8.GetBytes("#!/bin/bash\necho 'hello world'");
        var extractor = new PeFeatureExtractor();

        var vector = extractor.ExtractFromBytes(scriptBytes, "test_script.sh");

        Assert.False(vector.HasPeHeader);
        Assert.Equal(0, vector.SectionCount);
        Assert.NotNull(vector.Sha256);
        Assert.True(vector.ShannonEntropy > 0);
    }

    [Fact]
    public void PeFeatureExtractor_ExtractsValidPeHeaders()
    {
        // Binaire synthétique minimal contenant en-tête DOS ("MZ") et PE ("PE\0\0")
        byte[] peBytes = new byte[1024];
        peBytes[0] = 0x4D; // M
        peBytes[1] = 0x5A; // Z
        peBytes[0x3C] = 0x80; // Offset vers PE header = 128
        peBytes[0x80] = 0x50; // P
        peBytes[0x81] = 0x45; // E
        peBytes[0x82] = 0x00;
        peBytes[0x83] = 0x00;

        var extractor = new PeFeatureExtractor();
        var vector = extractor.ExtractFromBytes(peBytes, "sample.exe");

        Assert.True(vector.HasPeHeader);
        Assert.NotNull(vector.Sha256);
        Assert.Equal(1024, vector.FileSizeBytes);
    }
}
