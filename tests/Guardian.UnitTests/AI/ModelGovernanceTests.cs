using Guardian.AI.Governance;
using Guardian.Contracts.AI.Models;

namespace Guardian.UnitTests.AI;

public class ModelGovernanceTests
{
    [Fact]
    public void ModelGovernancePipeline_CalculatesEvaluationMetricsCorrectly()
    {
        var pipeline = new ModelGovernancePipeline();

        var predictions = new List<(ThreatClassificationResult Prediction, ThreatVerdict TrueLabel)>();

        // 90 vrais positifs
        for (int i = 0; i < 90; i++)
        {
            predictions.Add((
                CreateDummyResult(ThreatVerdict.Malicious, 0.95),
                ThreatVerdict.Malicious
            ));
        }

        // 10 faux négatifs (menaces non détectées)
        for (int i = 0; i < 10; i++)
        {
            predictions.Add((
                CreateDummyResult(ThreatVerdict.Clean, 0.15),
                ThreatVerdict.Malicious
            ));
        }

        // 98 vrais négatifs (fichiers sains correctement identifiés)
        for (int i = 0; i < 98; i++)
        {
            predictions.Add((
                CreateDummyResult(ThreatVerdict.Clean, 0.05),
                ThreatVerdict.Clean
            ));
        }

        // 2 faux positifs (fichiers sains signalés à tort)
        for (int i = 0; i < 2; i++)
        {
            predictions.Add((
                CreateDummyResult(ThreatVerdict.Malicious, 0.85),
                ThreatVerdict.Clean
            ));
        }

        var report = pipeline.Evaluate("test-model", "v1.4.0", predictions, averageLatencyMs: 1.5);

        Assert.Equal(200, report.TotalSamples);
        Assert.Equal(100, report.BenignSamples);
        Assert.Equal(100, report.MaliciousSamples);

        // Accuracy = (90 + 98) / 200 = 0.94
        Assert.InRange(report.Accuracy, 0.93, 0.95);

        // Precision = 90 / (90 + 2) = 0.978
        Assert.True(report.Precision > 0.95);

        // Recall = 90 / (90 + 10) = 0.90
        Assert.Equal(0.90, report.Recall);

        // FPR = 2 / 100 = 0.02 (2%)
        Assert.Equal(0.02, report.FalsePositiveRate);

        // Brier score calibration
        Assert.True(report.BrierScoreCalibration < 0.10);

        Assert.True(report.MeetsDeploymentGate);
    }

    [Fact]
    public async Task ModelRegistry_DoesNotClaimUnavailableHistoricalVersions()
    {
        var registry = new ModelRegistry();

        var initialActive = await registry.GetActiveModelAsync();
        Assert.Equal("v1.5.0-static-rules", initialActive.Version);
        Assert.False(initialActive.IsSigned);
        Assert.Equal(string.Empty, initialActive.Sha256Hash);

        var rollbackResult = await registry.RollbackToVersionAsync("v1.3.0-stable", "Dérive détectée sur faux positifs");

        Assert.False(rollbackResult.Success);
        Assert.Equal(initialActive.Version, rollbackResult.ActiveVersion);

        var currentActive = await registry.GetActiveModelAsync();
        Assert.Equal(initialActive.Version, currentActive.Version);
    }

    [Fact]
    public async Task ContinuousLearningEngine_RejectsUnconsentedFeedback()
    {
        var engine = new ContinuousLearningEngine();
        var sample = new FileFeatureVector
        {
            FilePath = "test.exe",
            Sha256 = "123456",
            FileSizeBytes = 1000,
            ShannonEntropy = 5.0
        };

        bool accepted = await engine.SubmitFeedbackSampleAsync(sample, ThreatVerdict.Clean, userConsentGiven: false);
        Assert.False(accepted);
    }

    private static ThreatClassificationResult CreateDummyResult(ThreatVerdict verdict, double probability)
    {
        return new ThreatClassificationResult
        {
            Verdict = verdict,
            Probability = probability,
            CalibratedProbability = probability,
            Confidence = 0.90,
            ModelVersion = "v1.4.0",
            ContributingFactors = [],
            Limitations = []
        };
    }
}
