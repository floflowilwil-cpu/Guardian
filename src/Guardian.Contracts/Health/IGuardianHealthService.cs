namespace Guardian.Contracts.Health;

/// <summary>
/// Contrat central d'observation et de publication de la santé des composants Guardian.
/// </summary>
/// <remarks>
/// <para><b>Privilèges :</b> lecture accessible aux clients IPC autorisés ; mise à jour réservée aux composants du service.</para>
/// <para><b>Résilience :</b> toute absence ou panne d'un composant requis doit produire un état dégradé explicite.</para>
/// <para><b>Vie privée :</b> les rapports exposent uniquement des statuts techniques et ne contiennent aucun secret.</para>
/// </remarks>
public interface IGuardianHealthService
{
    /// <summary>
    /// Calcule et retourne l'instantané agrégé de santé de l'ensemble des composants Guardian.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation de l'opération.</param>
    /// <returns>Instantané consolidé de la santé du service.</returns>
    Task<GuardianHealthSnapshot> GetOverallHealthAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Retourne le dernier rapport de santé connu pour un composant donné.
    /// </summary>
    /// <param name="componentName">Nom canonique du composant recherché.</param>
    /// <param name="cancellationToken">Jeton d'annulation de l'opération.</param>
    /// <returns>Le rapport du composant ou <see langword="null"/> s'il n'a pas encore été enregistré.</returns>
    Task<ComponentHealthReport?> GetComponentHealthAsync(string componentName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Enregistre ou met à jour le rapport de santé d'un composant.
    /// </summary>
    /// <param name="report">Rapport de santé vérifiable du composant.</param>
    /// <param name="cancellationToken">Jeton d'annulation de l'opération.</param>
    Task ReportComponentHealthAsync(ComponentHealthReport report, CancellationToken cancellationToken = default);

    /// <summary>
    /// Enregistre un battement (heartbeat) horodaté pour un composant actif.
    /// </summary>
    /// <param name="componentName">Nom canonique du composant émetteur.</param>
    /// <param name="timestampUtc">Horodatage UTC du battement.</param>
    /// <param name="cancellationToken">Jeton d'annulation de l'opération.</param>
    Task RecordHeartbeatAsync(string componentName, DateTimeOffset timestampUtc, CancellationToken cancellationToken = default);
}
