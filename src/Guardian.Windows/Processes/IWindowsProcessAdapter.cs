using Guardian.Contracts.System;

namespace Guardian.Windows.Processes;

/// <summary>
/// Contrat d'inventaire défensif et en lecture seule des processus Windows actifs.
/// </summary>
public interface IWindowsProcessAdapter
{
    /// <summary>
    /// Liste les processus actifs sur la machine locale avec leur PID parent, chemin exécutable accessible et modules optionnels.
    /// </summary>
    /// <param name="includeModules">Indique s'il faut tenter d'inventorier les modules chargés.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Liste des processus observés et statut d'accessibilité associé.</returns>
    Task<IReadOnlyList<ProcessInfoDto>> GetProcessesAsync(
        bool includeModules = false,
        CancellationToken cancellationToken = default);
}
