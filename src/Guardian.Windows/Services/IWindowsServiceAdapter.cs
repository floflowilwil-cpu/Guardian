using Guardian.Contracts.System;

namespace Guardian.Windows.Services;

/// <summary>
/// Contrat d'inventaire strictement en lecture seule des services Windows via le gestionnaire SCM.
/// </summary>
public interface IWindowsServiceAdapter
{
    /// <summary>
    /// Énumère les services Win32 enregistrés sur la machine locale avec leur état et configuration accessibles.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Liste des services Windows observés.</returns>
    Task<IReadOnlyList<WindowsServiceInfoDto>> GetServicesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Recherche un service Windows spécifique par son nom interne SCM.
    /// </summary>
    /// <param name="serviceName">Nom interne du service (ex. <c>WinDefend</c>, <c>mpssvc</c>).</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Informations sur le service ou <see langword="null"/> s'il est absent ou inaccessible.</returns>
    Task<WindowsServiceInfoDto?> GetServiceByNameAsync(string serviceName, CancellationToken cancellationToken = default);
}
