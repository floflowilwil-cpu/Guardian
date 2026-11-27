using Guardian.Contracts.System;

namespace Guardian.Windows.Tasks;

/// <summary>
/// Contrat d'inventaire en lecture seule des tâches planifiées Windows.
/// </summary>
public interface IWindowsScheduledTaskAdapter
{
    /// <summary>
    /// Collecte les tâches planifiées configurées sur la machine à partir des descripteurs XML en lecture seule.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Liste des tâches planifiées observables sous forme d'entrées de persistance.</returns>
    Task<IReadOnlyList<StartupEntryDto>> GetScheduledTasksAsync(CancellationToken cancellationToken = default);
}
