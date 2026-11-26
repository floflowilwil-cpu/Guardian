using Guardian.Contracts.Common;

namespace Guardian.Windows.Security;

/// <summary>
/// Résultat d'audit des listes de contrôle d'accès (ACL) d'un fichier ou répertoire.
/// </summary>
/// <param name="Path">Chemin inspecté.</param>
/// <param name="Exists">Indique si la cible existe sur le système de fichiers.</param>
/// <param name="IsRestrictive">Indique si aucune permission d'écriture ou modification trop large n'a été détectée.</param>
/// <param name="Availability">Statut d'accessibilité de l'audit ACL.</param>
/// <param name="Findings">Liste explicite des règles ACL jugées trop permissives.</param>
public sealed record AclAuditResult(
    string Path,
    bool Exists,
    bool IsRestrictive,
    FeatureAvailabilityStatus Availability,
    IReadOnlyList<string> Findings);
