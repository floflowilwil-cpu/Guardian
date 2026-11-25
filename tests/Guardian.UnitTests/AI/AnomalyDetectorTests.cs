using Guardian.AI.Anomaly;
using Guardian.Contracts.AI.Models;

namespace Guardian.UnitTests.AI;

public class AnomalyDetectorTests
{
    [Fact]
    public async Task DetectAnomalyAsync_NormalVector_IdentifiedAsNonAnomaly()
    {
        var detector = new IsolationForestAnomalyDetector(treeCount: 32, subSampleSize: 64);
        
        // Vecteur conforme aux valeurs normales (Taille standard, entropie moyenne, signature valide)
        var normalContext = new AnomalyEvaluationContext
        {
            EntityId = "normal-app-1",
            FeatureVector = [250000.0, 5.5, 4.0, 0.0, 1.0, 0.0]
        };

        var result = await detector.DetectAnomalyAsync(normalContext);

        Assert.False(result.IsAnomaly);
        Assert.True(result.AnomalyScore < 0.65);
        Assert.NotNull(result.Explanation);
    }

    [Fact]
    public async Task DetectAnomalyAsync_ExtremeOutlierVector_IdentifiedAsAnomaly()
    {
        var detector = new IsolationForestAnomalyDetector(treeCount: 32, subSampleSize: 64);

        // Vecteur extrême totalement hors distribution (entropie 8.0, 15 API suspectes, packer)
        var outlierContext = new AnomalyEvaluationContext
        {
            EntityId = "outlier-malware",
            FeatureVector = [15000000.0, 7.98, 12.0, 18.0, 0.0, 1.0]
        };

        var result = await detector.DetectAnomalyAsync(outlierContext);

        Assert.True(result.AnomalyScore > 0.60);
        Assert.NotNull(result.Explanation);
    }
}
