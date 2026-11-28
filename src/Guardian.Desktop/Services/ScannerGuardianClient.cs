using System.IO;
using Guardian.Contracts.Scanning;
using Guardian.Contracts.Signatures;
using Guardian.Desktop.Models;
using Guardian.Scanner;
using Guardian.Scanner.Heuristics;
using Guardian.Signatures;
using ContractVerdict = Guardian.Contracts.AI.Models.ThreatVerdict;
using ContractSeverity = Guardian.Contracts.AI.Models.SignalSeverity;

namespace Guardian.Desktop.Services;

/// <summary>
/// Branche l'écran Analyse sur le vrai moteur de scan (<see cref="IScanOrchestrator"/>, Guardian.Scanner).
/// Le reste (santé des moteurs, quarantaine, réseau, assistant) est délégué au client interne
/// tant que les modules correspondants ne sont pas fusionnés.
///
/// Transitoire : en production l'interface passera par le service via IPC (commande StartScan de John).
/// Il suffira alors de remplacer ce client par un IpcGuardianClient dans App.xaml.cs.
/// </summary>
public sealed class ScannerGuardianClient : IGuardianClient
{
    // Signature de test EICAR (fichier de test antivirus standard, inoffensif) pour vérifier la détection.
    private const string EicarSha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

    private readonly IGuardianClient _inner;
    private readonly IScanOrchestrator _orchestrator;
    private IReadOnlyList<ThreatItem>? _scanFindings;
    private DateTime? _lastScan;

    public ScannerGuardianClient(IGuardianClient inner)
    {
        _inner = inner;

        var signatures = new InMemorySignatureProvider(
        [
            new SignatureMatch
            {
                SignatureId = "TEST-EICAR",
                Sha256 = EicarSha256,
                ThreatName = "EICAR-Test-File",
                ThreatFamily = "Test",
                Severity = ContractSeverity.High,
            },
        ]);

        var fileScanner = new FileScanner(signatures, new HeuristicAnalyzer());
        _orchestrator = new ScanOrchestrator(fileScanner, new DefaultScanTargetResolver());
    }

    public bool IsDemo => _inner.IsDemo;

    public async Task<GuardianSnapshot> GetSnapshotAsync(CancellationToken ct = default)
    {
        var snapshot = await _inner.GetSnapshotAsync(ct);

        // Dès qu'une vraie analyse a eu lieu, ses résultats remplacent les menaces d'exemple.
        return _scanFindings is null
            ? snapshot
            : snapshot with
            {
                Threats = _scanFindings,
                BlockedThreats = _scanFindings.Count,
                LastCheck = _lastScan ?? snapshot.LastCheck,
            };
    }

    public async Task<bool> StartScanAsync(ScanKind kind, string? customPath, IProgress<ScanProgress> progress, CancellationToken ct = default)
    {
        if (kind == ScanKind.Custom && string.IsNullOrWhiteSpace(customPath))
        {
            return false;
        }

        var request = new ScanJobRequest
        {
            Scope = kind switch
            {
                ScanKind.Full => ScanScope.Full,
                ScanKind.Custom => ScanScope.Custom,
                _ => ScanScope.Quick,
            },
            CustomPath = kind == ScanKind.Custom ? customPath : null,
        };

        var relay = new ProgressRelay(i => progress.Report(
            new ScanProgress(i.Percent, i.CurrentPath, i.FilesProcessed, i.FilesTotal, i.ThreatsFound)));

        // Task.Run : le parcours des fichiers ne doit jamais tourner sur le thread de l'interface.
        ScanSummary summary = await Task.Run(() => _orchestrator.RunAsync(request, relay, ct), ct);

        _scanFindings = summary.Findings.Select(ToThreat).ToList();
        _lastScan = DateTime.Now;

        progress.Report(new ScanProgress(
            100, string.Empty,
            summary.FilesScanned + summary.FilesSkipped,
            summary.FilesScanned + summary.FilesSkipped,
            summary.Findings.Count,
            summary.FilesSkipped));
        return true;
    }

    public Task<bool> QuarantineThreatAsync(Guid threatId, CancellationToken ct = default) =>
        _inner.QuarantineThreatAsync(threatId, ct);

    public Task<bool> RestoreAsync(IEnumerable<Guid> ids, CancellationToken ct = default) =>
        _inner.RestoreAsync(ids, ct);

    public Task<bool> DeleteAsync(IEnumerable<Guid> ids, CancellationToken ct = default) =>
        _inner.DeleteAsync(ids, ct);

    public Task<string?> AskAssistantAsync(string prompt, CancellationToken ct = default) =>
        _inner.AskAssistantAsync(prompt, ct);

    private static ThreatItem ToThreat(FileScanResult r) => new(
        ThreatId.From(r.Sha256, r.FilePath),
        r.Signature?.ThreatName ?? Path.GetFileName(r.FilePath),
        r.Verdict == ContractVerdict.Malicious ? RiskLevel.High : RiskLevel.Medium,
        r.ScannedAtUtc.ToLocalTime(),
        r.FilePath,
        string.Join(" ", r.Reasons));

    /// <summary>IProgress sans file d'attente : appelle directement le rappel (le VM marshalle vers l'UI).</summary>
    private sealed class ProgressRelay(Action<ScanProgressInfo> report) : IProgress<ScanProgressInfo>
    {
        public void Report(ScanProgressInfo value) => report(value);
    }
}
