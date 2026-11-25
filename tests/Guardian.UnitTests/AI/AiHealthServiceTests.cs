using Guardian.AI.Anomaly;
using Guardian.AI.Assistant;
using Guardian.AI.Classification;
using Guardian.AI.Governance;
using Guardian.AI.Health;
using Guardian.Contracts.AI.Models;

namespace Guardian.UnitTests.AI;

public class AiHealthServiceTests
{
    [Fact]
    public async Task CheckHealthAsync_WhenEnginesReady_ReturnsHealthyStatus()
    {
        var classifier = new ThreatClassifier();
        var anomaly = new IsolationForestAnomalyDetector();
        var assistant = new LocalAssistantService();
        var registry = new ModelRegistry();

        var healthService = new AiHealthService(classifier, anomaly, assistant, registry);

        var status = await healthService.CheckHealthAsync();

        Assert.Equal(EngineHealthState.Healthy, status.State);
        Assert.True(status.ClassifierOperational);
        Assert.True(status.AnomalyDetectorOperational);
        Assert.True(status.AssistantOperational);
        Assert.NotNull(status.ActiveModelVersion);
        Assert.True(status.AverageInferenceLatencyMs >= 0);
    }
}
