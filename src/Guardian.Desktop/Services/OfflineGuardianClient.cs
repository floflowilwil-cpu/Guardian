using Guardian.Desktop.Models;

namespace Guardian.Desktop.Services;

/// <summary>
/// Client par défaut tant que l'IPC n'est pas branché : le service est considéré injoignable,
/// l'interface affiche donc "État inconnu" et ne simule jamais une protection active.
/// </summary>
public sealed class OfflineGuardianClient : IGuardianClient
{
    public bool IsDemo => false;

    public Task<GuardianSnapshot> GetSnapshotAsync(CancellationToken ct = default) =>
        Task.FromResult(GuardianSnapshot.Unknown);

    public Task<bool> StartScanAsync(ScanKind kind, string? customPath, IProgress<ScanProgress> progress, CancellationToken ct = default) =>
        Task.FromResult(false);

    public Task<bool> QuarantineThreatAsync(Guid threatId, CancellationToken ct = default) => Task.FromResult(false);

    public Task<bool> RestoreAsync(IEnumerable<Guid> ids, CancellationToken ct = default) => Task.FromResult(false);

    public Task<bool> DeleteAsync(IEnumerable<Guid> ids, CancellationToken ct = default) => Task.FromResult(false);

    public Task<string?> AskAssistantAsync(string prompt, CancellationToken ct = default) =>
        Task.FromResult<string?>(null);
}
