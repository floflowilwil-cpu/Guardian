using Guardian.Desktop.Models;

namespace Guardian.Desktop.Services;

/// <summary>
/// Accès de l'interface au service Guardian. L'UI n'effectue aucune opération privilégiée :
/// elle émet des demandes, le service (via Guardian.Policy) décide. L'implémentation réelle
/// utilisera les Named Pipes authentifiés (doc technique §14) et les contrats de Guardian.Contracts.
/// </summary>
public interface IGuardianClient
{
    /// <summary>Vrai si une partie des données affichées est fictive (modules pas encore branchés).</summary>
    bool IsDemo { get; }

    Task<GuardianSnapshot> GetSnapshotAsync(CancellationToken ct = default);

    Task<bool> StartScanAsync(ScanKind kind, string? customPath, IProgress<ScanProgress> progress, CancellationToken ct = default);

    Task<bool> QuarantineThreatAsync(Guid threatId, CancellationToken ct = default);

    Task<bool> RestoreAsync(IEnumerable<Guid> ids, CancellationToken ct = default);

    Task<bool> DeleteAsync(IEnumerable<Guid> ids, CancellationToken ct = default);

    Task<string?> AskAssistantAsync(string prompt, CancellationToken ct = default);
}
