namespace Guardian.Service.Security;

/// <summary>
/// Contrat de surveillance de l'auto-intégrité des binaires et des ACL du service Guardian.
/// </summary>
public interface ISelfIntegrityMonitor
{
    /// <summary>
    /// Capture la baseline SHA-256 initiale des binaires surveillés et évalue leur état courant.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Rapport initial d'auto-intégrité.</returns>
    Task<SelfIntegrityReportDto> InitializeBaselineAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Recalcule les empreintes SHA-256, contrôle les ajouts/suppressions, vérifie les signatures si exigé
    /// et audite les ACL du répertoire de données.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Rapport détaillé d'auto-intégrité.</returns>
    Task<SelfIntegrityReportDto> VerifyIntegrityAsync(CancellationToken cancellationToken = default);
}
