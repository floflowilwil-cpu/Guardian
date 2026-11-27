using Guardian.Contracts.Common;
using Guardian.Windows.Security;

namespace Guardian.Service.Security;

/// <summary>
/// Résultat complet d'un contrôle d'auto-intégrité des binaires et permissions de Guardian.
/// </summary>
/// <param name="CheckedAtUtc">Horodatage UTC de l'inspection.</param>
/// <param name="Status">État de santé résultant (<c>Healthy</c> ou <c>Degraded</c>).</param>
/// <param name="BaselineFileCount">Nombre de binaires enregistrés dans la baseline de référence.</param>
/// <param name="VerifiedFileCount">Nombre de binaires vérifiés avec succès.</param>
/// <param name="Anomalies">Liste explicite des anomalies détectées (hash modifié, absence, binaire non signé, ACL permissive).</param>
/// <param name="DataDirectoryAclAudit">Résultat de l'audit ACL du dossier de données s'il existe sur disque.</param>
public sealed record SelfIntegrityReportDto(
    DateTimeOffset CheckedAtUtc,
    GuardianHealthStatus Status,
    int BaselineFileCount,
    int VerifiedFileCount,
    IReadOnlyList<string> Anomalies,
    AclAuditResult? DataDirectoryAclAudit);
