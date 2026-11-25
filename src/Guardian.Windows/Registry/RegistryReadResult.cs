using Guardian.Contracts.Common;

namespace Guardian.Windows.Registry;

/// <summary>
/// Représente le résultat typé d'une lecture en lecture seule du registre Windows.
/// </summary>
/// <typeparam name="T">Type de la valeur lue.</typeparam>
/// <param name="Found">Indique si la clé et la valeur demandées existent.</param>
/// <param name="Value">Valeur lue si trouvée, sinon valeur par défaut.</param>
/// <param name="Availability">Statut d'accessibilité de la clé registre.</param>
/// <param name="ErrorMessage">Détail non sensible en cas d'accès refusé ou d'indisponibilité.</param>
public sealed record RegistryReadResult<T>(
    bool Found,
    T? Value,
    FeatureAvailabilityStatus Availability,
    string? ErrorMessage = null);
