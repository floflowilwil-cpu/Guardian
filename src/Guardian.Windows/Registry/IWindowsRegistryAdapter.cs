using Guardian.Contracts.Common;
using Guardian.Contracts.System;
using Microsoft.Win32;

namespace Guardian.Windows.Registry;

/// <summary>
/// Contrat d'accès strictement en lecture seule au registre Windows et aux emplacements de démarrage.
/// </summary>
public interface IWindowsRegistryAdapter
{
    /// <summary>
    /// Lit une valeur entière 32 bits (<c>REG_DWORD</c>) dans une clé du registre Windows.
    /// </summary>
    /// <param name="hive">Ruche registre cible.</param>
    /// <param name="subKeyPath">Chemin relatif de la sous-clé.</param>
    /// <param name="valueName">Nom de la valeur à lire.</param>
    /// <returns>Résultat typé précisant l'existence et l'accessibilité.</returns>
    RegistryReadResult<int> TryReadDword(RegistryHive hive, string subKeyPath, string valueName);

    /// <summary>
    /// Lit une valeur textuelle dans une clé du registre Windows.
    /// </summary>
    /// <param name="hive">Ruche registre cible.</param>
    /// <param name="subKeyPath">Chemin relatif de la sous-clé.</param>
    /// <param name="valueName">Nom de la valeur à lire.</param>
    /// <returns>Résultat typé contenant la chaîne lue si présente.</returns>
    RegistryReadResult<string> TryReadString(RegistryHive hive, string subKeyPath, string valueName);

    /// <summary>
    /// Énumère les paires nom/valeur d'une sous-clé du registre Windows.
    /// </summary>
    /// <param name="hive">Ruche registre cible.</param>
    /// <param name="subKeyPath">Chemin relatif de la sous-clé.</param>
    /// <returns>Statut de disponibilité, dictionnaire des valeurs lues et éventuel message d'erreur.</returns>
    (FeatureAvailabilityStatus Availability, IReadOnlyDictionary<string, string> Values, string? ErrorMessage) EnumerateValuePairs(
        RegistryHive hive,
        string subKeyPath);

    /// <summary>
    /// Inventorie en lecture seule les points de démarrage et mécanismes de persistance observables.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Liste des entrées de démarrage détectées.</returns>
    Task<IReadOnlyList<StartupEntryDto>> GetStartupEntriesAsync(CancellationToken cancellationToken = default);
}
