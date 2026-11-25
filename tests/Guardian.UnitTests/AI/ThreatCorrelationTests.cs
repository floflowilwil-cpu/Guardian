using Guardian.AI.Correlation;
using Guardian.Contracts.AI.Models;

namespace Guardian.UnitTests.AI;

public class ThreatCorrelationTests
{
    [Fact]
    public async Task CorrelateSignalsAsync_BuildsIncidentGraphAndLinksEntities()
    {
        var correlator = new ThreatCorrelator();
        var now = DateTime.UtcNow;

        var signals = new List<SecuritySignal>
        {
            new()
            {
                SignalId = "sig-1",
                Source = SignalSource.File,
                Severity = SignalSeverity.Medium,
                Category = "FileDropped",
                EntityId = "invoice_exploit.pdf.exe",
                Description = "Exécutable suspect déposé dans Temp",
                TimestampUtc = now.AddMinutes(-5)
            },
            new()
            {
                SignalId = "sig-2",
                Source = SignalSource.Process,
                Severity = SignalSeverity.High,
                Category = "SuspiciousProcessSpawn",
                EntityId = "powershell_hidden.exe",
                Description = "Processus powershell lancé avec fenêtre masquée",
                TimestampUtc = now.AddMinutes(-4)
            },
            new()
            {
                SignalId = "sig-3",
                Source = SignalSource.Registry,
                Severity = SignalSeverity.High,
                Category = "PersistenceRunKey",
                EntityId = @"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                Description = "Ajout d'une clé de démarrage",
                TimestampUtc = now.AddMinutes(-3)
            },
            new()
            {
                SignalId = "sig-4",
                Source = SignalSource.Network,
                Severity = SignalSeverity.Critical,
                Category = "C2OutboundBeacon",
                EntityId = "198.51.100.42:4444",
                Description = "Connexion sortante vers destination suspecte",
                TimestampUtc = now.AddMinutes(-2)
            }
        };

        var graph = await correlator.CorrelateSignalsAsync(signals);

        Assert.NotNull(graph.IncidentId);
        Assert.Equal(4, graph.Nodes.Count);
        Assert.Equal(3, graph.Edges.Count);
        Assert.Equal("file_invoice_exploit.pdf.exe", graph.RootCauseNodeId);
        Assert.True(graph.CompositeRiskScore >= 90.0);

        var timeline = await correlator.GenerateTimelineAsync(graph);
        Assert.Equal(4, timeline.Count);
        Assert.True(timeline[0].TimestampUtc <= timeline[1].TimestampUtc);
        Assert.Contains(timeline, t => t.IsMilestone);
    }
}
