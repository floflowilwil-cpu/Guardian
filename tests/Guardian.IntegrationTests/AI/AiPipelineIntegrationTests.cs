using System.Diagnostics;
using Guardian.AI.Assistant;
using Guardian.AI.Classification;
using Guardian.AI.Correlation;
using Guardian.AI.Governance;
using Guardian.Contracts.AI.Models;

namespace Guardian.IntegrationTests.AI;

public class AiPipelineIntegrationTests
{
    [Fact]
    public async Task EndToEnd_DatasetBenchmark_MeetsProductionQualityGatesAndLatency()
    {
        var classifier = new ThreatClassifier();
        var governance = new ModelGovernancePipeline();

        var dataset = GenerateSyntheticBenchmarkCorpus();
        var predictions = new List<(ThreatClassificationResult Prediction, ThreatVerdict TrueLabel)>();

        var stopwatch = Stopwatch.StartNew();

        foreach (var (sample, trueLabel) in dataset)
        {
            var result = await classifier.ClassifyFeaturesAsync(sample);
            predictions.Add((result, trueLabel));
        }

        stopwatch.Stop();
        double avgLatencyMs = stopwatch.Elapsed.TotalMilliseconds / dataset.Count;

        var report = governance.Evaluate(
            "guardian-classifier-gbt",
            TreeBasedMalwareClassifier.DefaultModelVersion,
            predictions,
            avgLatencyMs
        );

        // Vérifications de performance et de qualité
        Assert.True(avgLatencyMs < 10.0, $"La latence moyenne d'inférence ({avgLatencyMs:F2} ms) doit être inférieure à 10 ms.");
        Assert.True(report.Accuracy >= ModelGovernancePipeline.MinimumAccuracy, $"Accuracy ({report.Accuracy:P1}) sous le seuil.");
        Assert.True(report.Precision >= ModelGovernancePipeline.MinimumPrecision, $"Precision ({report.Precision:P1}) sous le seuil.");
        Assert.True(report.Recall >= ModelGovernancePipeline.MinimumRecall, $"Recall ({report.Recall:P1}) sous le seuil.");
        Assert.True(report.FalsePositiveRate <= ModelGovernancePipeline.MaximumFalsePositiveRate, $"FPR ({report.FalsePositiveRate:P1}) dépasse le seuil.");
        Assert.True(report.MeetsDeploymentGate, "Le modèle évalué doit franchir tous les critères de déploiement en production.");
    }

    [Fact]
    public async Task EndToEnd_MultiSignalIncident_ConstructsGraphAndAssistsUser()
    {
        var correlator = new ThreatCorrelator();
        var assistant = new LocalAssistantService();

        var now = DateTime.UtcNow;
        var signals = new List<SecuritySignal>
        {
            new()
            {
                SignalId = "sig-drop",
                Source = SignalSource.File,
                Severity = SignalSeverity.High,
                Category = "TrojanDrop",
                EntityId = "invoice_update.exe",
                Description = "Binaire non signé avec entropie élevée détecté dans %TEMP%",
                TimestampUtc = now.AddMinutes(-10)
            },
            new()
            {
                SignalId = "sig-proc",
                Source = SignalSource.Process,
                Severity = SignalSeverity.Critical,
                Category = "ProcessInjection",
                EntityId = "explorer.exe",
                Description = "Tentative d'écriture interprocessus suspecte détectée",
                TimestampUtc = now.AddMinutes(-8)
            },
            new()
            {
                SignalId = "sig-net",
                Source = SignalSource.Network,
                Severity = SignalSeverity.Critical,
                Category = "C2Connection",
                EntityId = "203.0.113.88:8080",
                Description = "Flux périodique vers IP de commande et contrôle connue",
                TimestampUtc = now.AddMinutes(-5)
            }
        };

        // 1. Corrélation
        var graph = await correlator.CorrelateSignalsAsync(signals);
        Assert.Equal(3, graph.Nodes.Count);
        Assert.Equal(2, graph.Edges.Count);
        Assert.True(graph.CompositeRiskScore >= 90.0);

        // 2. Timeline
        var timeline = await correlator.GenerateTimelineAsync(graph);
        Assert.Equal(3, timeline.Count);

        // 3. Consultation de l'assistant local par l'UI
        var request = new AssistantRequest
        {
            Query = "Explique l'origine de cette menace",
            AssociatedThreatGraph = graph,
            RecentSignals = signals
        };

        var response = await assistant.AskAssistantAsync(request);

        Assert.False(response.HasSecurityWarning);
        Assert.Contains(graph.IncidentId, response.ResponseText);
        Assert.NotEmpty(response.RecommendedActions);
    }

    private static List<(FileFeatureVector Sample, ThreatVerdict TrueLabel)> GenerateSyntheticBenchmarkCorpus()
    {
        var corpus = new List<(FileFeatureVector, ThreatVerdict)>();
        var rand = new Random(1337);

        // 50 échantillons sains
        for (int i = 0; i < 50; i++)
        {
            corpus.Add((
                new FileFeatureVector
                {
                    FilePath = $@"C:\Program Files\App{i}\app_{i}.exe",
                    Sha256 = $"benign_sha256_{i}",
                    FileSizeBytes = rand.Next(100000, 5000000),
                    ShannonEntropy = 4.5 + (rand.NextDouble() * 1.5), // 4.5 - 6.0
                    HasPeHeader = true,
                    SectionCount = rand.Next(3, 6),
                    ExecutableSectionCount = 1,
                    AnomalousSectionNameCount = 0,
                    MaxSectionEntropy = 5.5 + (rand.NextDouble() * 1.0),
                    ImportedLibrariesCount = rand.Next(5, 15),
                    ImportedFunctionsCount = rand.Next(30, 100),
                    SuspiciousApiCallCount = 0,
                    HasValidDigitalSignature = true,
                    HasTlsCallback = false,
                    HasResources = true,
                    HasDebugInfo = true,
                    IsPackedOrObfuscated = false,
                    SuspiciousStringRatio = 0.01,
                    ByteDistributionVariance = 12000.0
                },
                ThreatVerdict.Clean
            ));
        }

        // 50 échantillons malveillants
        for (int i = 0; i < 50; i++)
        {
            corpus.Add((
                new FileFeatureVector
                {
                    FilePath = $@"C:\Users\USER\AppData\Local\Temp\malware_{i}.exe",
                    Sha256 = $"malware_sha256_{i}",
                    FileSizeBytes = rand.Next(50000, 800000),
                    ShannonEntropy = 7.4 + (rand.NextDouble() * 0.55), // 7.4 - 7.95
                    HasPeHeader = true,
                    SectionCount = rand.Next(2, 5),
                    ExecutableSectionCount = rand.Next(1, 3),
                    AnomalousSectionNameCount = rand.Next(1, 3),
                    MaxSectionEntropy = 7.6 + (rand.NextDouble() * 0.38),
                    ImportedLibrariesCount = rand.Next(1, 4),
                    ImportedFunctionsCount = rand.Next(5, 20),
                    SuspiciousApiCallCount = rand.Next(3, 8),
                    HasValidDigitalSignature = false,
                    HasTlsCallback = true,
                    HasResources = false,
                    HasDebugInfo = false,
                    IsPackedOrObfuscated = true,
                    SuspiciousStringRatio = 0.35,
                    ByteDistributionVariance = 2800.0
                },
                ThreatVerdict.Malicious
            ));
        }

        return corpus;
    }
}
