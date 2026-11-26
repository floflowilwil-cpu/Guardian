using Guardian.Contracts.Common;

namespace Guardian.Contracts.System;

/// <summary>
/// Représente une entrée de démarrage ou de persistance détectée en lecture seule.
/// </summary>
/// <param name="Name">Nom de l'entrée ou de la valeur.</param>
/// <param name="Kind">Catégorie de mécanisme de persistance.</param>
/// <param name="Location">Emplacement registre ou dossier complet.</param>
/// <param name="CommandOrPath">Commande ou chemin cible configuré.</param>
/// <param name="Scope">Portée (<c>Machine</c>, <c>MachineWow64</c>, <c>User</c>, etc.).</param>
/// <param name="AccessStatus">Disponibilité de lecture pour cette entrée.</param>
public sealed record StartupEntryDto(
    string Name,
    PersistenceEntryKind Kind,
    string Location,
    string CommandOrPath,
    string Scope,
    FeatureAvailabilityStatus AccessStatus);
