using Guardian.Contracts.AI.Models;

namespace Guardian.Contracts.AI;

/// <summary>
/// Contrat du service d'assistant conversationnel local de sécurité, en coordination avec l'interface graphique (Alexia).
/// Fonctionne sous contrôle strict de Guardian.Policy : n'exécute aucune action système directe.
/// </summary>
public interface ILocalAiAssistant
{
    /// <summary>
    /// Traite une demande formulée en langage naturel par l'utilisateur ou l'analyste.
    /// Analyse la requête, valide l'absence d'attaque (prompt injection, jailbreak), synthétise les preuves et formule des recommandations.
    /// </summary>
    /// <param name="request">Requête contenant la question et le contexte de sécurité.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Réponse sécurisée avec explications, preuves et suggestions d'actions conformes à la politique.</returns>
    Task<AssistantResponse> AskAssistantAsync(
        AssistantRequest request, 
        CancellationToken cancellationToken = default);
}
