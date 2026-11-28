using System.IO;
using Guardian.Desktop.Infrastructure;
using Guardian.Desktop.Models;
using Guardian.Quarantine;
using ContractQuarantineItem = Guardian.Contracts.Quarantine.QuarantineItem;
using ContractQuarantineRequest = Guardian.Contracts.Quarantine.QuarantineRequest;
using IQuarantineService = Guardian.Contracts.Quarantine.IQuarantineService;

namespace Guardian.Desktop.Services;

/// <summary>
/// Branche les écrans Menaces et Quarantaine sur la vraie quarantaine (<see cref="FileQuarantineService"/> :
/// AES-256-GCM, clé protégée par DPAPI, intégrité vérifiée à la restauration).
/// Se place au-dessus du client IPC : il lit les menaces qu'il renvoie, les met en quarantaine,
/// puis remplace la liste de quarantaine par le contenu réel du disque.
///
/// Transitoire : le service n'expose pas encore de commande IPC de quarantaine.
/// Quand elle existera, ce client pourra être retiré et IpcGuardianClient appellera le service.
/// </summary>
public sealed class QuarantineGuardianClient : IGuardianClient
{
    private readonly IGuardianClient _inner;
    private readonly Lazy<IQuarantineService?> _service;
    private IReadOnlyDictionary<Guid, ThreatItem> _knownThreats = new Dictionary<Guid, ThreatItem>();
    private string? _lastError;
    private string? _initError;

    public QuarantineGuardianClient(IGuardianClient inner, Func<IQuarantineService>? factory = null)
    {
        _inner = inner;
        _service = new Lazy<IQuarantineService?>(() =>
        {
            try
            {
                return (factory ?? CreateDefault)();
            }
            catch (Exception ex)
            {
                AppLog.Write(ex, "Initialisation de la quarantaine");
                _initError = ex.Message;
                _lastError = _initError;
                return null;
            }
        });
    }

    public bool IsDemo => _inner.IsDemo;

    public string? LastError => _lastError;

    public async Task<GuardianSnapshot> GetSnapshotAsync(CancellationToken ct = default)
    {
        var snapshot = await _inner.GetSnapshotAsync(ct);

        // Mémorise les menaces affichées : c'est d'elles que viennent le chemin, le motif et le nom à mettre en quarantaine.
        _knownThreats = snapshot.Threats
            .GroupBy(t => t.Id)
            .ToDictionary(g => g.Key, g => g.First());

        var service = _service.Value;
        if (service is null)
        {
            return snapshot;
        }

        try
        {
            var items = await service.ListAsync(ct);
            var quarantinedPaths = items
                .Select(i => NormalizePath(i.OriginalPath))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            // Une menace déjà isolée n'a plus à apparaître dans la liste des menaces actives.
            var activeThreats = snapshot.Threats
                .Where(t => !quarantinedPaths.Contains(NormalizePath(t.Path)))
                .ToList();

            return snapshot with
            {
                Threats = activeThreats,
                Quarantine = items.Select(ToUiItem).ToList(),
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            AppLog.Write(ex, "Lecture de la quarantaine");
            return snapshot;
        }
    }

    public async Task<bool> QuarantineThreatAsync(Guid threatId, CancellationToken ct = default)
    {
        _lastError = null;
        var service = _service.Value;
        if (service is null)
        {
            _lastError = _initError;
            return false;
        }

        if (!_knownThreats.TryGetValue(threatId, out var threat))
        {
            _lastError = "Menace introuvable : actualisez la liste.";
            return false;
        }

        try
        {
            await service.QuarantineAsync(
                new ContractQuarantineRequest
                {
                    FilePath = threat.Path,
                    Reason = string.IsNullOrWhiteSpace(threat.Behavior) ? threat.Name : threat.Behavior,
                    DetectionEngine = "Guardian.Scanner",
                    ThreatName = threat.Name,
                },
                ct);
            return true;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            AppLog.Write(ex, "Mise en quarantaine");
            _lastError = ex.Message;
            return false;
        }
    }

    public Task<bool> RestoreAsync(IEnumerable<Guid> ids, CancellationToken ct = default) =>
        RunForEachAsync(ids, (service, id) => service.RestoreAsync(id, null, ct), "Restauration de la quarantaine");

    public Task<bool> DeleteAsync(IEnumerable<Guid> ids, CancellationToken ct = default) =>
        RunForEachAsync(ids, (service, id) => service.DeleteAsync(id, ct), "Suppression de la quarantaine");

    public Task<bool> StartScanAsync(ScanKind kind, string? customPath, IProgress<ScanProgress> progress, CancellationToken ct = default) =>
        _inner.StartScanAsync(kind, customPath, progress, ct);

    public Task<string?> AskAssistantAsync(string prompt, CancellationToken ct = default) =>
        _inner.AskAssistantAsync(prompt, ct);

    private async Task<bool> RunForEachAsync(IEnumerable<Guid> ids, Func<IQuarantineService, Guid, Task> action, string context)
    {
        _lastError = null;
        var service = _service.Value;
        if (service is null)
        {
            _lastError = _initError;
            return false;
        }

        var allOk = true;
        foreach (var id in ids)
        {
            try
            {
                await action(service, id);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                AppLog.Write(ex, context);
                _lastError = ex.Message;
                allOk = false;
            }
        }

        return allOk;
    }

    private static IQuarantineService CreateDefault()
    {
        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var journalPath = Path.Combine(programData, "Guardian", "logs", "quarantine-journal.log");
        return new FileQuarantineService(
            FileQuarantineService.DefaultRoot,
            new DpapiKeyProtector(),
            new FileQuarantineJournal(journalPath));
    }

    // Le niveau de risque n'est pas stocké par la quarantaine : « Élevé » par défaut (convention convenue avec Iness).
    private static Models.QuarantineItem ToUiItem(ContractQuarantineItem i) => new(
        i.Id,
        string.IsNullOrWhiteSpace(i.ThreatName) ? Path.GetFileName(i.OriginalPath) : i.ThreatName,
        i.QuarantinedAtUtc.ToLocalTime(),
        RiskLevel.High);

    private static string NormalizePath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return string.Empty;
        }

        try
        {
            return Path.GetFullPath(path);
        }
        catch (Exception)
        {
            return path;
        }
    }
}
