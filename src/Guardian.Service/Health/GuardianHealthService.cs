using System.Collections.Concurrent;
using Guardian.Contracts.Common;
using Guardian.Contracts.Health;
using Guardian.Service.Configuration;
using Microsoft.Extensions.Options;

namespace Guardian.Service.Health;

/// <summary>
/// Agrège et expose de façon vérifiable et transparente l'état de santé du service Guardian et de ses modules.
/// </summary>
public sealed class GuardianHealthService : IGuardianHealthService
{
    private readonly ConcurrentDictionary<string, ComponentHealthReport> _reports = new(StringComparer.OrdinalIgnoreCase);
    private readonly IOptions<GuardianServiceOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly string _serviceVersion;
    private Func<WatchdogSnapshot>? _watchdogSnapshotProvider;

    /// <summary>
    /// Initialise le service d'agrégation de santé Guardian.
    /// </summary>
    /// <param name="options">Options de configuration validées du service.</param>
    /// <param name="timeProvider">Fournisseur d'horloge optionnel (par défaut <see cref="TimeProvider.System"/>).</param>
    public GuardianHealthService(
        IOptions<GuardianServiceOptions> options,
        TimeProvider? timeProvider = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? TimeProvider.System;
        _serviceVersion = typeof(GuardianHealthService).Assembly.GetName().Version?.ToString() ?? "1.0.0";
    }

    /// <summary>
    /// Enregistre un fournisseur optionnel permettant d'inclure l'état du watchdog dans l'instantané global.
    /// </summary>
    /// <param name="provider">Fonction retournant l'instantané courant du watchdog.</param>
    public void SetWatchdogSnapshotProvider(Func<WatchdogSnapshot>? provider)
    {
        _watchdogSnapshotProvider = provider;
    }

    /// <inheritdoc />
    public Task<GuardianHealthSnapshot> GetOverallHealthAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var now = _timeProvider.GetUtcNow();
        var options = _options.Value;
        var staleThreshold = TimeSpan.FromSeconds(options.HeartbeatStaleThresholdSeconds);
        var requiredComponents = options.RequiredComponents ?? [];
        var watchdogSnapshot = _watchdogSnapshotProvider?.Invoke();

        if (_reports.IsEmpty)
        {
            var initialReasons = requiredComponents.Count > 0
                ? new[] { "No components have reported health yet." }
                : Array.Empty<string>();

            return Task.FromResult(new GuardianHealthSnapshot(
                OverallStatus: GuardianHealthStatus.Unknown,
                CapturedAtUtc: now,
                ServiceVersion: _serviceVersion,
                Components: [],
                DegradedReasons: initialReasons,
                Watchdog: watchdogSnapshot));
        }

        var evaluatedComponents = new List<ComponentHealthReport>(_reports.Count);
        var degradedReasons = new List<string>();
        var hostStopped = false;
        var hasDegraded = false;
        var hasOutOfDate = false;
        var hasUnknownRequired = false;

        var requiredSet = new HashSet<string>(requiredComponents, StringComparer.OrdinalIgnoreCase);

        foreach (var entry in _reports.Values.OrderBy(r => r.ComponentName, StringComparer.OrdinalIgnoreCase))
        {
            var effectiveReport = EvaluateReportFreshness(entry, now, staleThreshold);
            evaluatedComponents.Add(effectiveReport);

            if (string.Equals(effectiveReport.ComponentName, GuardianServiceConstants.HostComponentName, StringComparison.OrdinalIgnoreCase) &&
                effectiveReport.Status == GuardianHealthStatus.Stopped)
            {
                hostStopped = true;
                AppendReasons(degradedReasons, effectiveReport);
                continue;
            }

            switch (effectiveReport.Status)
            {
                case GuardianHealthStatus.Degraded:
                case GuardianHealthStatus.Stopped:
                    hasDegraded = true;
                    AppendReasons(degradedReasons, effectiveReport);
                    break;

                case GuardianHealthStatus.OutOfDate:
                    hasOutOfDate = true;
                    AppendReasons(degradedReasons, effectiveReport);
                    break;

                case GuardianHealthStatus.Unknown when requiredSet.Contains(effectiveReport.ComponentName):
                    hasUnknownRequired = true;
                    AppendReasons(degradedReasons, effectiveReport);
                    break;
            }
        }

        foreach (var requiredName in requiredComponents.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (!_reports.ContainsKey(requiredName))
            {
                hasDegraded = true;
                degradedReasons.Add($"Required component '{requiredName}' has not reported health.");
            }
        }

        var overallStatus = hostStopped
            ? GuardianHealthStatus.Stopped
            : hasDegraded
                ? GuardianHealthStatus.Degraded
                : hasOutOfDate
                    ? GuardianHealthStatus.OutOfDate
                    : hasUnknownRequired
                        ? GuardianHealthStatus.Unknown
                        : GuardianHealthStatus.Healthy;

        return Task.FromResult(new GuardianHealthSnapshot(
            OverallStatus: overallStatus,
            CapturedAtUtc: now,
            ServiceVersion: _serviceVersion,
            Components: evaluatedComponents,
            DegradedReasons: degradedReasons,
            Watchdog: watchdogSnapshot));
    }

    /// <inheritdoc />
    public Task<ComponentHealthReport?> GetComponentHealthAsync(string componentName, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(componentName);
        cancellationToken.ThrowIfCancellationRequested();

        if (!_reports.TryGetValue(componentName, out var report))
        {
            return Task.FromResult<ComponentHealthReport?>(null);
        }

        var now = _timeProvider.GetUtcNow();
        var staleThreshold = TimeSpan.FromSeconds(_options.Value.HeartbeatStaleThresholdSeconds);
        return Task.FromResult<ComponentHealthReport?>(EvaluateReportFreshness(report, now, staleThreshold));
    }

    /// <inheritdoc />
    public Task ReportComponentHealthAsync(ComponentHealthReport report, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentException.ThrowIfNullOrWhiteSpace(report.ComponentName);
        cancellationToken.ThrowIfCancellationRequested();

        _reports[report.ComponentName] = report;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task RecordHeartbeatAsync(string componentName, DateTimeOffset timestampUtc, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(componentName);
        cancellationToken.ThrowIfCancellationRequested();

        _reports.AddOrUpdate(
            componentName,
            static (name, ts) => new ComponentHealthReport(
                ComponentName: name,
                Status: GuardianHealthStatus.Unknown,
                Summary: "Heartbeat received before initial status report.",
                LastUpdatedUtc: ts,
                LastHeartbeatUtc: ts,
                Availability: FeatureAvailabilityStatus.Available,
                Reasons: []),
            static (_, existing, ts) => existing with
            {
                LastUpdatedUtc = ts,
                LastHeartbeatUtc = ts
            },
            timestampUtc);

        return Task.CompletedTask;
    }

    private static ComponentHealthReport EvaluateReportFreshness(
        ComponentHealthReport report,
        DateTimeOffset now,
        TimeSpan staleThreshold)
    {
        if (report.Status == GuardianHealthStatus.Stopped || !report.LastHeartbeatUtc.HasValue)
        {
            return report;
        }

        var age = now - report.LastHeartbeatUtc.Value;
        if (age <= staleThreshold)
        {
            return report;
        }

        var staleMessage = $"Component '{report.ComponentName}' heartbeat is stale ({age.TotalSeconds:F0}s > {staleThreshold.TotalSeconds:F0}s).";
        var updatedReasons = report.Reasons.Contains(staleMessage, StringComparer.Ordinal)
            ? report.Reasons
            : [.. report.Reasons, staleMessage];

        return report with
        {
            Status = GuardianHealthStatus.Degraded,
            Availability = report.Availability == FeatureAvailabilityStatus.Available
                ? FeatureAvailabilityStatus.Degraded
                : report.Availability,
            Summary = staleMessage,
            Reasons = updatedReasons
        };
    }

    private static void AppendReasons(List<string> target, ComponentHealthReport report)
    {
        if (report.Reasons.Count > 0)
        {
            foreach (var reason in report.Reasons)
            {
                if (!string.IsNullOrWhiteSpace(reason))
                {
                    target.Add(reason);
                }
            }
        }
        else if (!string.IsNullOrWhiteSpace(report.Summary))
        {
            target.Add($"{report.ComponentName}: {report.Summary}");
        }
    }
}
