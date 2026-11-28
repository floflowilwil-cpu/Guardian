using Guardian.Contracts.AI.Models;
using Guardian.Contracts.Sandbox;

namespace Guardian.Sandbox;

/// <summary>
/// Orchestrateur de repli : l'analyse dynamique est indisponible. Il n'ouvre, ne lit
/// et n'exécute jamais le fichier, et retourne un verdict inconclusif (jamais « sain »).
/// </summary>
public sealed class UnavailableSandboxOrchestrator : ISandboxOrchestrator
{
    private readonly IHyperVDetector _detector;

    public UnavailableSandboxOrchestrator(IHyperVDetector detector)
    {
        ArgumentNullException.ThrowIfNull(detector);
        _detector = detector;
    }

    public Task<SandboxAvailability> GetAvailabilityAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(Evaluate());
    }

    public Task<SandboxAnalysisResult> AnalyzeAsync(
        SandboxAnalysisRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.FilePath);
        ValidateLimits(request.Limits);
        cancellationToken.ThrowIfCancellationRequested();

        SandboxAvailability availability = Evaluate();
        DateTime now = DateTime.UtcNow;

        return Task.FromResult(new SandboxAnalysisResult
        {
            RunId = Guid.NewGuid(),
            Status = SandboxRunStatus.Unavailable,
            Verdict = ThreatVerdict.Inconclusive,
            Summary = availability.Message,
            StartedAtUtc = now,
            CompletedAtUtc = now
        });
    }

    private SandboxAvailability Evaluate()
    {
        return _detector.Detect() switch
        {
            HyperVState.NotWindows => Unavailable(
                SandboxUnavailableReason.UnsupportedPlatform,
                "Analyse dynamique indisponible : plateforme non supportée (Windows requis)."),

            HyperVState.NotInstalled => Unavailable(
                SandboxUnavailableReason.HyperVNotInstalled,
                "Analyse dynamique indisponible : Hyper-V n'est pas installé ou pas activé."),

            _ => Unavailable(
                SandboxUnavailableReason.NotImplemented,
                "Analyse dynamique indisponible : l'orchestrateur de machine virtuelle n'est pas encore implémenté.")
        };
    }

    private static SandboxAvailability Unavailable(SandboxUnavailableReason reason, string message) =>
        new(false, reason, message);

    private static void ValidateLimits(SandboxLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);

        if (limits.Timeout <= TimeSpan.Zero
            || limits.MaxMemoryMegabytes <= 0
            || limits.MaxCpuCores <= 0
            || limits.MaxDiskMegabytes <= 0
            || limits.MaxProcesses <= 0)
        {
            throw new ArgumentException(
                "Les limites de la sandbox doivent toutes être strictement positives.",
                nameof(limits));
        }
    }
}
