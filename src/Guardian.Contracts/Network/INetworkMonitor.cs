namespace Guardian.Contracts.Network;

/// <summary>
/// Contrat de la surveillance réseau : inventaire des connexions, DNS, métadonnées TLS, anomalies et pare-feu.
/// </summary>
/// <remarks>
/// <para><b>Privilèges :</b> la surveillance fonctionne en utilisateur standard avec dégradation explicite (association connexion-processus, lecture de certaines règles) ; la création ou la suppression de règle de pare-feu exige une autorisation administrateur.</para>
/// <para><b>Vie privée :</b> métadonnées uniquement (processus, adresses, ports, DNS, volumes, certificats visibles). Aucun contenu, aucun déchiffrement TLS généralisé, aucune interception silencieuse.</para>
/// <para><b>Pare-feu :</b> Guardian ne désactive jamais le pare-feu Windows. Toute règle est temporaire, créée après décision de politique, avec expiration, et journalisée (création, expiration, suppression) via <see cref="Common.AuditEventDto"/>.</para>
/// <para><b>Résilience :</b> une source indisponible produit un état dégradé explicite, jamais une exception globale ni un faux « tout va bien ».</para>
/// </remarks>
public interface INetworkMonitor
{
    /// <summary>
    /// Se produit lorsqu'un événement réseau notable est détecté.
    /// </summary>
    event EventHandler<NetworkEventDto>? EventDetected;

    /// <summary>
    /// Démarre la surveillance réseau passive.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    Task StartAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Arrête proprement la surveillance réseau.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    Task StopAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Inventorie les connexions actives avec leur processus lorsqu'il est identifiable.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Connexions observées, avec statut explicite d'association au processus.</returns>
    Task<IReadOnlyList<NetworkConnectionDto>> GetActiveConnectionsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Retourne les derniers événements réseau en mémoire, du plus récent au plus ancien.
    /// </summary>
    /// <param name="maxCount">Nombre maximal d'événements à retourner.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Liste bornée d'événements réseau récents.</returns>
    Task<IReadOnlyList<NetworkEventDto>> GetRecentEventsAsync(int maxCount = 100, CancellationToken cancellationToken = default);

    /// <summary>
    /// Lit l'état du pare-feu Windows sans le modifier.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>État des profils et recommandations éventuelles.</returns>
    Task<FirewallStatusDto> GetFirewallStatusAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Liste les règles de pare-feu actuellement gérées par Guardian.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Règles gérées par Guardian, avec leur expiration.</returns>
    Task<IReadOnlyList<FirewallRuleDto>> GetManagedFirewallRulesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Crée une règle de blocage temporaire après décision de politique et selon l'autorisation de l'appelant.
    /// </summary>
    /// <param name="request">Demande de blocage, référençant la décision de politique.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Résultat de l'opération ; un refus ou une indisponibilité est exprimé par une erreur de diagnostic.</returns>
    Task<FirewallRuleResultDto> ApplyTemporaryBlockAsync(TemporaryBlockRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Supprime une règle gérée par Guardian avant son expiration.
    /// </summary>
    /// <param name="ruleId">Identifiant de la règle à supprimer.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Résultat de l'opération ; seules les règles gérées par Guardian peuvent être supprimées.</returns>
    Task<FirewallRuleResultDto> RemoveManagedRuleAsync(Guid ruleId, CancellationToken cancellationToken = default);
}
