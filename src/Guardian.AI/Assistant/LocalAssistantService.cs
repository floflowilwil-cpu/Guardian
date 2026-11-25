using System.Text;
using Guardian.Contracts.AI;
using Guardian.Contracts.AI.Models;

namespace Guardian.AI.Assistant;

/// <summary>
/// Service d'assistant local conversationnel de sécurité (ILocalAiAssistant).
/// Conçu pour être consommé par l'interface WPF d'Alexia.
/// Totalement gouverné, sans privilèges directs, et protégé contre les injections de prompt.
/// </summary>
public sealed class LocalAssistantService : ILocalAiAssistant
{
    private readonly IAiSecurityGuard _securityGuard;

    public LocalAssistantService(IAiSecurityGuard? securityGuard = null)
    {
        _securityGuard = securityGuard ?? new SecurityDefense.AiSecurityGuard();
    }

    /// <inheritdoc />
    public async Task<AssistantResponse> AskAssistantAsync(
        AssistantRequest request, 
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // 1. Contrôle de sécurité systématique contre les injections de prompt et jailbreaks
        var securityEvaluation = await _securityGuard.InspectTextAsync(request.Query, cancellationToken);
        if (!securityEvaluation.IsSafe)
        {
            return new AssistantResponse
            {
                ResponseText = "Requête bloquée par les garde-fous de sécurité IA de Guardian. L'instruction soumise contient des motifs non autorisés ou une tentative de contournement des politiques.",
                Confidence = 1.0,
                EvidenceItems = securityEvaluation.BlockedPatterns,
                RecommendedActions = ["Consulter les règles de Guardian.Policy.", "Ne pas soumettre de commandes système à l'assistant."],
                HasSecurityWarning = true,
                SecurityWarningDetail = securityEvaluation.AnalysisDetail
            };
        }

        // 2. Analyse et synthèse contextuelle
        var evidence = new List<string>();
        var recommendations = new List<string>();
        var responseBuilder = new StringBuilder();

        string queryLower = request.Query.ToLowerInvariant();

        // Question portant sur un incident ou graphe de menaces
        if (request.AssociatedThreatGraph != null)
        {
            var graph = request.AssociatedThreatGraph;
            evidence.Add($"Incident: {graph.IncidentId}");
            evidence.Add($"Score composite de risque: {graph.CompositeRiskScore:F0}%");
            evidence.Add($"Nombre d'entités impliquées: {graph.Nodes.Count}");

            if (queryLower.Contains("cause") || queryLower.Contains("origine") || queryLower.Contains("pourquoi"))
            {
                responseBuilder.AppendLine($"L'incident '{graph.IncidentId}' a débuté à la suite de signaux sur le nœud racine suspecté : '{graph.RootCauseNodeId}'.");
                responseBuilder.AppendLine($"Le score de risque global est évalué à {graph.CompositeRiskScore:F0}%.");

                recommendations.Add("Inspecter les fichiers déposés et vérifier les clés de registre associées.");
                recommendations.Add("Isoler les connexions réseau sortantes suspectes si recommandées par Guardian.Policy.");
            }
            else
            {
                responseBuilder.AppendLine($"L'incident en cours implique {graph.Nodes.Count} entités corrélées et {graph.Edges.Count} liens causaux.");
                responseBuilder.AppendLine($"Niveau de menace globale : {(graph.CompositeRiskScore >= 70.0 ? "Élevé" : "Modéré")}.");
            }
        }
        else if (request.RecentSignals.Count > 0)
        {
            var criticalSignals = request.RecentSignals.Where(s => s.Severity >= SignalSeverity.High).ToList();
            evidence.Add($"{request.RecentSignals.Count} signaux récents analysés ({criticalSignals.Count} prioritaires).");

            responseBuilder.AppendLine($"J'ai analysé les {request.RecentSignals.Count} derniers événements système.");
            if (criticalSignals.Count > 0)
            {
                responseBuilder.AppendLine($"Attention : {criticalSignals.Count} signal(aux) de sévérité élevée ou critique nécessite(nt) votre attention :");
                foreach (var sig in criticalSignals.Take(3))
                {
                    responseBuilder.AppendLine($"- [{sig.Source}] {sig.Description}");
                }
                recommendations.Add("Lancer une analyse rapide ou personnalisée via l'onglet Scans.");
                recommendations.Add("Vérifier les alertes dans le Centre de Menaces.");
            }
            else
            {
                responseBuilder.AppendLine("Aucune anomalie critique immédiate n'a été détectée dans les signaux récents.");
                recommendations.Add("Maintenir la surveillance active et les définitions à jour.");
                recommendations.Add("Consulter le centre de notifications en cas d'activité inhabituelle.");
            }
        }
        else
        {
            responseBuilder.AppendLine("Guardian opère en surveillance active. Vous pouvez me poser des questions sur les menaces détectées, les résultats d'analyses ou les explications de scores.");
            recommendations.Add("Effectuer un scan rapide pour actualiser l'état du poste.");
        }

        // Garde-fou d'explication : l'assistant rappelle son rôle
        responseBuilder.AppendLine();
        responseBuilder.AppendLine("Note : L'assistant fournit des explications et des recommandations. Toute remédiation effective est validée par Guardian.Policy.");

        return new AssistantResponse
        {
            ResponseText = responseBuilder.ToString().Trim(),
            Confidence = 0.92,
            EvidenceItems = evidence,
            RecommendedActions = recommendations,
            HasSecurityWarning = false,
            SecurityWarningDetail = null
        };
    }
}
