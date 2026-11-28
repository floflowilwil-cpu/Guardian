using Guardian.Desktop.Models;

using Guardian.Desktop.Infrastructure;

namespace Guardian.Desktop.Services;

/// <summary>
/// Données fictives pour prévisualiser l'interface (lancer avec l'argument --demo).
/// Un bandeau "Mode démonstration" est affiché en permanence : rien ici n'est une vraie détection.
/// </summary>
public sealed class DemoGuardianClient : IGuardianClient
{
    private readonly List<QuarantineItem> _quarantine =
    [
        new(Guid.NewGuid(), "malware.exe", new DateTime(2025, 5, 14, 14, 20, 0), RiskLevel.High),
        new(Guid.NewGuid(), "script.suspicious.js", new DateTime(2025, 5, 13, 18, 45, 0), RiskLevel.Medium),
        new(Guid.NewGuid(), "virus.dll", new DateTime(2025, 5, 12, 9, 12, 0), RiskLevel.High),
    ];

    private readonly List<ThreatItem> _threats =
    [
        new(Guid.NewGuid(), "Cheval de Troie détecté", RiskLevel.High, new DateTime(2025, 5, 14, 14, 20, 0),
            @"C:\Users\Public\malware.exe",
            "Comportement suspect : tentative de connexion à un serveur externe."),
    ];

    public bool IsDemo => true;

    public Task<GuardianSnapshot> GetSnapshotAsync(CancellationToken ct = default) =>
        Task.FromResult(new GuardianSnapshot(
            ProtectionState.Healthy, true, true, true,
            [
                new EngineStatus(Loc.T("Analyse des fichiers"), ProtectionState.Healthy),
                new EngineStatus(Loc.T("Protection réseau"), ProtectionState.Healthy),
                new EngineStatus(Loc.T("Surveillance système"), ProtectionState.Healthy),
                new EngineStatus(Loc.T("Protection comportementale"), ProtectionState.Healthy),
                new EngineStatus(Loc.T("IA locale"), ProtectionState.Healthy),
            ],
            _threats.ToList(), 3, _quarantine.ToList(), 12, 12, 1,
            [
                new NetworkDestination("Microsoft (safe)", 42, true),
                new NetworkDestination("Google (safe)", 34, true),
                new NetworkDestination(Loc.T("Autres"), 24, false),
            ],
            DateTime.Now,
            BuildSystemOverview()));

    /// <summary>Exemple de posture Windows pour prévisualiser l'écran Système.</summary>
    private static SystemOverview BuildSystemOverview()
    {
        var now = DateTime.Now;
        return new SystemOverview(
            now,
            "10.0.22631",
            "Windows 11 Pro",
            PrivilegeKind.Standard,
            [
                new(SecurityControlKind.Defender, ProtectionState.Healthy, Loc.T("Protection en temps réel activée.")),
                new(SecurityControlKind.Firewall, ProtectionState.Healthy, Loc.T("Profils domaine, privé et public actifs.")),
                new(SecurityControlKind.Uac, ProtectionState.Healthy, Loc.T("Contrôle de compte utilisateur activé.")),
                new(SecurityControlKind.SecureBoot, ProtectionState.Healthy, Loc.T("Démarrage sécurisé activé.")),
                new(SecurityControlKind.Tpm, ProtectionState.Healthy, Loc.T("TPM 2.0 présent et prêt.")),
                new(SecurityControlKind.VirtualizationSecurity, ProtectionState.Stopped, Loc.T("Non activée sur cet appareil."),
                    Recommendation: Loc.T("Activez l'intégrité de la mémoire dans Sécurité Windows.")),
                new(SecurityControlKind.CredentialGuard, ProtectionState.Unknown, Loc.T("État non lisible sans droits élevés."),
                    NeedsElevation: true),
                new(SecurityControlKind.Lsass, ProtectionState.Healthy, Loc.T("Processus LSASS protégé.")),
            ],
            [Loc.T("Activez l'intégrité de la mémoire (VBS) pour renforcer la protection du noyau.")],
            [
                new(now.AddMinutes(-2), SystemEventKind.Process, EventLevel.Info, "Guardian.SystemMonitor", "chrome.exe",
                    Loc.T("Nouveau processus démarré.")),
                new(now.AddMinutes(-9), SystemEventKind.Persistence, EventLevel.Medium, "Guardian.SystemMonitor", "setup.exe",
                    Loc.T("Nouvelle entrée de démarrage ajoutée.")),
                new(now.AddMinutes(-26), SystemEventKind.Usb, EventLevel.Low, "Guardian.SystemMonitor", null,
                    Loc.T("Périphérique USB connecté.")),
                new(now.AddHours(-2), SystemEventKind.PostureChange, EventLevel.High, "Guardian.SystemMonitor", null,
                    Loc.T("Le pare-feu a été désactivé puis réactivé.")),
            ]);
    }

    public async Task<bool> StartScanAsync(ScanKind kind, string? customPath, IProgress<ScanProgress> progress, CancellationToken ct = default)
    {
        string[] paths =
        [
            @"C:\Windows\System32\kernel32.dll",
            @"C:\Windows\System32\ntdll.dll",
            @"C:\Program Files\Common Files\shared.dll",
            @"C:\Users\Public\Documents\rapport.docx",
        ];

        for (var i = 0; i <= 100; i += 4)
        {
            ct.ThrowIfCancellationRequested();
            progress.Report(new ScanProgress(i, paths[i / 26 % paths.Length]));
            await Task.Delay(120, ct);
        }

        return true;
    }

    public Task<bool> QuarantineThreatAsync(Guid threatId, CancellationToken ct = default) => Task.FromResult(true);

    public Task<bool> RestoreAsync(IEnumerable<Guid> ids, CancellationToken ct = default) => Task.FromResult(true);

    public Task<bool> DeleteAsync(IEnumerable<Guid> ids, CancellationToken ct = default) => Task.FromResult(true);

    public async Task<string?> AskAssistantAsync(string prompt, CancellationToken ct = default)
    {
        await Task.Delay(500, ct);
        return "(Démo) Je suis l'assistant Guardian. Dans la version réelle, je répondrai à partir des preuves collectées par le service.";
    }
}
