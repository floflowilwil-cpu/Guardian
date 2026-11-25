using Guardian.AI.Classification;
using Guardian.Contracts.AI.Models;

namespace Guardian.UnitTests.AI;

public class ThreatClassifierTests
{
    [Fact]
    public async Task ClassifyFeaturesAsync_CleanSignedFile_ReturnsCleanVerdict()
    {
        var classifier = new ThreatClassifier();
        var cleanVector = new FileFeatureVector
        {
            FilePath = @"C:\Windows\System32\notepad.exe",
            Sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            FileSizeBytes = 250000,
            ShannonEntropy = 5.8,
            HasPeHeader = true,
            SectionCount = 4,
            ExecutableSectionCount = 1,
            AnomalousSectionNameCount = 0,
            MaxSectionEntropy = 6.1,
            ImportedLibrariesCount = 6,
            ImportedFunctionsCount = 45,
            SuspiciousApiCallCount = 0,
            HasValidDigitalSignature = true,
            HasTlsCallback = false,
            HasResources = true,
            HasDebugInfo = true,
            IsPackedOrObfuscated = false,
            SuspiciousStringRatio = 0.01,
            ByteDistributionVariance = 15000.0
        };

        var result = await classifier.ClassifyFeaturesAsync(cleanVector);

        Assert.Equal(ThreatVerdict.Clean, result.Verdict);
        Assert.True(result.CalibratedProbability < 0.40);
        Assert.True(result.Confidence >= 0.50);
        Assert.NotEmpty(result.ContributingFactors);
        Assert.Contains(result.ContributingFactors, f => f.Impact == FactorImpact.DecreasesRisk);
    }

    [Fact]
    public async Task ClassifyFeaturesAsync_PackedMalware_ReturnsMaliciousVerdict()
    {
        var classifier = new ThreatClassifier();
        var malwareVector = new FileFeatureVector
        {
            FilePath = @"C:\Users\USER\Downloads\suspicious_payload.exe",
            Sha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            FileSizeBytes = 120000,
            ShannonEntropy = 7.85, // Entropie très élevée
            HasPeHeader = true,
            SectionCount = 3,
            ExecutableSectionCount = 2,
            AnomalousSectionNameCount = 2, // Sections anormales (.upx)
            MaxSectionEntropy = 7.92,
            ImportedLibrariesCount = 2,
            ImportedFunctionsCount = 12,
            SuspiciousApiCallCount = 6, // VirtualAlloc, WriteProcessMemory, CreateRemoteThread...
            HasValidDigitalSignature = false,
            HasTlsCallback = true,
            HasResources = false,
            HasDebugInfo = false,
            IsPackedOrObfuscated = true,
            SuspiciousStringRatio = 0.45,
            ByteDistributionVariance = 2500.0
        };

        var result = await classifier.ClassifyFeaturesAsync(malwareVector);

        Assert.Equal(ThreatVerdict.Malicious, result.Verdict);
        Assert.True(result.CalibratedProbability >= 0.70);
        Assert.NotNull(result.ThreatFamily);
        Assert.True(result.AnomalyScore > 0.5);
        Assert.Contains(result.ContributingFactors, f => f.Impact == FactorImpact.IncreasesRisk);
    }

    [Fact]
    public async Task ClassifyFileAsync_MissingFile_ReturnsErrorVerdictWithoutThrowing()
    {
        var classifier = new ThreatClassifier();
        var result = await classifier.ClassifyFileAsync(@"C:\NonExistentDirectory\definitely_missing_file_12345.exe");

        Assert.Equal(ThreatVerdict.Error, result.Verdict);
        Assert.NotEmpty(result.Limitations);
    }
}
