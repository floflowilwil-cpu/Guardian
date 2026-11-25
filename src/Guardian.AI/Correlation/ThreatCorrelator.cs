using Guardian.Contracts.AI;
using Guardian.Contracts.AI.Models;

namespace Guardian.AI.Correlation;

/// <summary>
/// Moteur de corrélation multi-signaux (ISignalCorrelator).
/// Relie les événements épars (fichiers, processus, registre, réseau, mémoire) pour former un graphe causal
/// d'incident et une timeline forensique ordonnée.
/// </summary>
public sealed class ThreatCorrelator : ISignalCorrelator
{
    /// <inheritdoc />
    public Task<ThreatGraph> CorrelateSignalsAsync(
        IEnumerable<SecuritySignal> signals, 
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var signalList = signals.OrderBy(s => s.TimestampUtc).ToList();
        if (signalList.Count == 0)
        {
            return Task.FromResult(new ThreatGraph
            {
                IncidentId = Guid.NewGuid().ToString("N")[..8],
                Title = "Aucun signal à corréler",
                CompositeRiskScore = 0.0,
                Nodes = [],
                Edges = []
            });
        }

        var nodesDict = new Dictionary<string, ThreatGraphNode>();
        var edges = new List<ThreatGraphEdge>();
        double maxRisk = 0.0;
        string? rootCauseNodeId = null;

        foreach (var signal in signalList)
        {
            double signalRisk = signal.Severity switch
            {
                SignalSeverity.Critical => 95.0,
                SignalSeverity.High => 75.0,
                SignalSeverity.Medium => 45.0,
                SignalSeverity.Low => 20.0,
                _ => 5.0
            };

            if (signalRisk > maxRisk)
            {
                maxRisk = signalRisk;
            }

            string nodeId = $"{signal.Source}_{signal.EntityId}".ToLowerInvariant();
            if (!nodesDict.TryGetValue(nodeId, out var existingNode))
            {
                var newNode = new ThreatGraphNode
                {
                    NodeId = nodeId,
                    Label = $"{signal.Source}: {signal.EntityId}",
                    NodeType = signal.Source.ToString(),
                    RiskScore = signalRisk,
                    Properties = new Dictionary<string, string>(signal.Metadata)
                    {
                        ["Description"] = signal.Description,
                        ["FirstSeen"] = signal.TimestampUtc.ToString("o")
                    }
                };
                nodesDict[nodeId] = newNode;

                rootCauseNodeId ??= nodeId;
            }
            else
            {
                // Mettre à jour avec le score le plus sévère
                if (signalRisk > existingNode.RiskScore)
                {
                    nodesDict[nodeId] = existingNode with { RiskScore = signalRisk };
                }
            }
        }

        // Établir les relations causales entre nœuds consécutifs ou corrélés
        var nodeList = nodesDict.Values.ToList();
        for (int i = 0; i < signalList.Count - 1; i++)
        {
            var s1 = signalList[i];
            var s2 = signalList[i + 1];

            string srcId = $"{s1.Source}_{s1.EntityId}".ToLowerInvariant();
            string tgtId = $"{s2.Source}_{s2.EntityId}".ToLowerInvariant();

            if (srcId != tgtId)
            {
                string relation = DetermineRelation(s1.Source, s2.Source);
                edges.Add(new ThreatGraphEdge
                {
                    SourceNodeId = srcId,
                    TargetNodeId = tgtId,
                    RelationType = relation,
                    Confidence = 0.85,
                    TimestampUtc = s2.TimestampUtc
                });
            }
        }

        string incidentId = $"INC-{DateTime.UtcNow:yyyyMMdd}-{Guid.NewGuid().ToString("N")[..6]}";
        string title = $"Corrélation multi-signaux : {signalList.Count} événements ({maxRisk:F0}% risque)";

        var graph = new ThreatGraph
        {
            IncidentId = incidentId,
            Title = title,
            CompositeRiskScore = maxRisk,
            Nodes = nodeList,
            Edges = edges,
            RootCauseNodeId = rootCauseNodeId
        };

        return Task.FromResult(graph);
    }

    /// <inheritdoc />
    public Task<IReadOnlyList<ThreatTimelineEntry>> GenerateTimelineAsync(
        ThreatGraph graph, 
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var timeline = new List<ThreatTimelineEntry>();

        foreach (var node in graph.Nodes)
        {
            DateTime timestamp = DateTime.UtcNow;
            if (node.Properties.TryGetValue("FirstSeen", out string? timeStr) &&
                DateTime.TryParse(timeStr, out var parsed))
            {
                timestamp = parsed;
            }

            bool isMilestone = node.RiskScore >= 70.0 || node.NodeId == graph.RootCauseNodeId;
            var severity = node.RiskScore switch
            {
                >= 90.0 => SignalSeverity.Critical,
                >= 70.0 => SignalSeverity.High,
                >= 40.0 => SignalSeverity.Medium,
                >= 20.0 => SignalSeverity.Low,
                _ => SignalSeverity.Informational
            };

            Enum.TryParse<SignalSource>(node.NodeType, true, out var source);

            timeline.Add(new ThreatTimelineEntry
            {
                EventId = $"EVT-{Guid.NewGuid().ToString("N")[..6]}",
                TimestampUtc = timestamp,
                Source = source,
                Severity = severity,
                Description = node.Properties.GetValueOrDefault("Description", node.Label),
                IsMilestone = isMilestone,
                RelatedNodeIds = [node.NodeId]
            });
        }

        return Task.FromResult<IReadOnlyList<ThreatTimelineEntry>>(
            timeline.OrderBy(e => e.TimestampUtc).ToList()
        );
    }

    private static string DetermineRelation(SignalSource from, SignalSource to)
    {
        return (from, to) switch
        {
            (SignalSource.File, SignalSource.Process) => "SpawnsProcess",
            (SignalSource.Process, SignalSource.File) => "DropsFile",
            (SignalSource.Process, SignalSource.Registry) => "ModifiesRegistryKey",
            (SignalSource.Process, SignalSource.Network) => "EstablishesOutboundConnection",
            (SignalSource.Process, SignalSource.Memory) => "InjectsPayloadIntoProcess",
            (SignalSource.Network, SignalSource.File) => "DownloadsPayload",
            _ => "CorrelatedWith"
        };
    }
}
