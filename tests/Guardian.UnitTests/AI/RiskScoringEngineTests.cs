using Guardian.AI.Risk;
using Guardian.Contracts.AI.Models;

namespace Guardian.UnitTests.AI;

public class RiskScoringEngineTests
{
    [Fact]
    public async Task CalculateRiskScoreAsync_HighThreat_ReturnsCriticalScoreAndQuarantineRecommendation()
    {
        var scorer = new RiskScoringEngine();
        var context = new RiskEvaluationContext
        {
            EntityId = "sha256-malware-test-sample",
            SignatureScore = 0.95,
            AiClassifierScore = 0.90,
            HeuristicScore = 0.85,
            BehavioralScore = 0.92,
            HasValidDigitalSignature = false,
            IsKnownSystemComponent = false,
            AssociatedNetworkEventCount = 3,
            AssociatedProcessEventCount = 2
        };

        var result = await scorer.CalculateRiskScoreAsync(context);

        Assert.True(result.Score >= 80.0);
        Assert.True(result.Level == RiskLevel.High || result.Level == RiskLevel.Critical);
        Assert.Equal("Quarantine", result.RecommendedPolicyAction);
        Assert.NotEmpty(result.ContributingFactors);
    }

    [Fact]
    public async Task CalculateRiskScoreAsync_CriticalScoreOnSystemComponent_RequiresHumanConfirmation()
    {
        var scorer = new RiskScoringEngine();
        var context = new RiskEvaluationContext
        {
            EntityId = "system32-kernel32-dll",
            SignatureScore = 0.85,
            AiClassifierScore = 0.80,
            IsKnownSystemComponent = true,
            HasValidDigitalSignature = true
        };

        var result = await scorer.CalculateRiskScoreAsync(context);

        // Même en cas de score élevé, les composants système ne doivent jamais être automatiquement supprimés
        if (result.Level >= RiskLevel.High)
        {
            Assert.Equal("RequireUserConfirmation", result.RecommendedPolicyAction);
            Assert.Contains(result.Caveats, c => c.Contains("Composant système ciblé"));
        }
    }

    [Fact]
    public void ProbabilityCalibrator_CalibratesReliably()
    {
        var calibrator = new ProbabilityCalibrator();

        double probLow = calibrator.Calibrate(0.05);
        double probMid = calibrator.Calibrate(0.50);
        double probHigh = calibrator.Calibrate(0.95);

        Assert.True(probLow < probMid);
        Assert.True(probMid < probHigh);
        Assert.InRange(probLow, 0.0, 0.25);
        Assert.InRange(probHigh, 0.75, 1.0);
    }

    [Fact]
    public void ProbabilityCalibrator_BrierScoreCalculatedAccurately()
    {
        // 2 prédictions parfaites
        var perfectEvals = new List<(double CalibratedProb, bool ActualPositive)>
        {
            (1.0, true),
            (0.0, false)
        };

        double brierPerfect = ProbabilityCalibrator.CalculateBrierScore(perfectEvals);
        Assert.Equal(0.0, brierPerfect);

        // 2 prédictions totalement erronées
        var wrongEvals = new List<(double CalibratedProb, bool ActualPositive)>
        {
            (1.0, false),
            (0.0, true)
        };

        double brierWrong = ProbabilityCalibrator.CalculateBrierScore(wrongEvals);
        Assert.Equal(1.0, brierWrong);
    }
}
