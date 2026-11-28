using System.Buffers.Binary;
using System.IO;
using System.IO.Pipes;
using System.Text.Json;
using Guardian.Contracts.Common;
using Guardian.Contracts.Health;
using Guardian.Contracts.Ipc;
using Guardian.Contracts.Scanning;
using Guardian.Contracts.System;
using Guardian.Desktop.Models;
using ContractVerdict = Guardian.Contracts.AI.Models.ThreatVerdict;

namespace Guardian.Desktop.Services;

/// <summary>
/// Client IPC Named Pipes reliant l'interface WPF <c>Guardian.Desktop</c> au service résident
/// <c>Guardian.Service</c> via les contrats publics de <c>Guardian.Contracts</c>.
/// En l'absence de connexion pour les modules non encore exposés par IPC, délègue proprement
/// au client de repli sans jamais masquer un arrêt du service.
/// </summary>
public sealed class IpcGuardianClient : IGuardianClient
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly IGuardianClient _fallback;
    private readonly string _pipeName;
    private readonly TimeSpan _connectTimeout;
    private readonly TimeSpan _requestTimeout;
    private volatile bool _serviceConnected;

    /// <summary>
    /// Initialise le client IPC Named Pipes de l'interface desktop.
    /// </summary>
    /// <param name="fallback">Client utilisé pour les modules pas encore exposés via IPC ou lorsque le service est arrêté.</param>
    /// <param name="pipeName">Nom du Named Pipe local (par défaut <see cref="IpcProtocolConstants.DefaultPipeName"/>).</param>
    /// <param name="connectTimeout">Délai maximal d'établissement de connexion au pipe.</param>
    /// <param name="requestTimeout">Délai maximal d'échange d'une requête/réponse IPC.</param>
    public IpcGuardianClient(
        IGuardianClient fallback,
        string? pipeName = null,
        TimeSpan? connectTimeout = null,
        TimeSpan? requestTimeout = null)
    {
        _fallback = fallback ?? throw new ArgumentNullException(nameof(fallback));
        _pipeName = string.IsNullOrWhiteSpace(pipeName) ? IpcProtocolConstants.DefaultPipeName : pipeName;
        _connectTimeout = connectTimeout ?? TimeSpan.FromMilliseconds(800);
        _requestTimeout = requestTimeout ?? TimeSpan.FromSeconds(5);
    }

    /// <inheritdoc />
    public bool IsDemo => !_serviceConnected && _fallback.IsDemo;

    /// <inheritdoc />
    public async Task<GuardianSnapshot> GetSnapshotAsync(CancellationToken ct = default)
    {
        var fallbackSnapshot = await _fallback.GetSnapshotAsync(ct).ConfigureAwait(false);

        GuardianHealthSnapshot? health;
        try
        {
            var healthResp = await SendCommandAsync(IpcCommandType.GetHealth, null, ct).ConfigureAwait(false);
            if (!healthResp.Success || string.IsNullOrWhiteSpace(healthResp.PayloadJson))
            {
                _serviceConnected = false;
                return BuildDisconnectedSnapshot(fallbackSnapshot);
            }

            health = JsonSerializer.Deserialize<GuardianHealthSnapshot>(healthResp.PayloadJson, JsonOptions);
            if (health is null)
            {
                _serviceConnected = false;
                return BuildDisconnectedSnapshot(fallbackSnapshot);
            }
        }
        catch (Exception ex) when (IsPipeUnavailable(ex, ct))
        {
            _serviceConnected = false;
            return BuildDisconnectedSnapshot(fallbackSnapshot);
        }

        _serviceConnected = true;

        var scanStatus = await TrySendOptionalAsync<IpcScanStatusDto>(IpcCommandType.GetScanStatus, null, ct).ConfigureAwait(false);
        var posture = await TrySendOptionalAsync<WindowsSecurityPostureDto>(IpcCommandType.GetSecurityPosture, null, ct).ConfigureAwait(false);
        var recentEvents = await TrySendOptionalAsync<IReadOnlyList<SystemSecurityEventDto>>(
            IpcCommandType.GetRecentSystemEvents,
            JsonSerializer.Serialize(50, JsonOptions),
            ct).ConfigureAwait(false);

        var engines = BuildEngineStatuses(health, posture);
        var threats = scanStatus?.LastCompletedSummary?.Findings is { } findings
            ? findings.Select(ToThreatItem).ToArray()
            : Array.Empty<ThreatItem>();

        var systemMonitorReport = health.Components.FirstOrDefault(
            c => string.Equals(c.ComponentName, "Guardian.SystemMonitor", StringComparison.OrdinalIgnoreCase));
        var aiReport = health.Components.FirstOrDefault(
            c => string.Equals(c.ComponentName, "Guardian.AI", StringComparison.OrdinalIgnoreCase));

        var overallState = MapHealthStatus(health.OverallStatus);
        var realtimeActive = systemMonitorReport?.Status == GuardianHealthStatus.Healthy;
        var aiActive = aiReport?.Status == GuardianHealthStatus.Healthy;
        var definitionsUpToDate = health.OverallStatus is GuardianHealthStatus.Healthy or GuardianHealthStatus.Degraded;

        var lastCheck = scanStatus?.LastCompletedSummary?.StartedAtUtc.ToLocalTime()
            ?? health.CapturedAtUtc.ToLocalTime().DateTime;

        return new GuardianSnapshot(
            State: overallState,
            AiEngineActive: aiActive,
            DefinitionsUpToDate: definitionsUpToDate,
            RealtimeActive: realtimeActive,
            Engines: engines,
            Threats: threats,
            BlockedThreats: threats.Length,
            Quarantine: fallbackSnapshot.Quarantine,
            EventCount: recentEvents?.Count ?? 0,
            ActiveConnections: fallbackSnapshot.ActiveConnections,
            SuspiciousConnections: fallbackSnapshot.SuspiciousConnections,
            Destinations: fallbackSnapshot.Destinations,
            LastCheck: lastCheck,
            SystemInfo: BuildSystemOverview(posture, recentEvents));
    }

    /// <inheritdoc />
    public async Task<bool> StartScanAsync(
        ScanKind kind,
        string? customPath,
        IProgress<ScanProgress> progress,
        CancellationToken ct = default)
    {
        if (kind == ScanKind.Custom && string.IsNullOrWhiteSpace(customPath))
        {
            return false;
        }

        var scope = kind switch
        {
            ScanKind.Full => ScanScope.Full,
            ScanKind.Custom => ScanScope.Custom,
            _ => ScanScope.Quick
        };

        IpcResponse startResp;
        try
        {
            var payload = JsonSerializer.Serialize(new IpcStartScanPayload(scope, kind == ScanKind.Custom ? customPath : null), JsonOptions);
            startResp = await SendCommandAsync(IpcCommandType.StartScan, payload, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsPipeUnavailable(ex, ct))
        {
            _serviceConnected = false;
            return await _fallback.StartScanAsync(kind, customPath, progress, ct).ConfigureAwait(false);
        }

        _serviceConnected = true;

        if (!startResp.Success)
        {
            return false;
        }

        IpcScanStatusDto? latestStatus = null;

        try
        {
            while (true)
            {
                ct.ThrowIfCancellationRequested();

                var statusResp = await SendCommandAsync(IpcCommandType.GetScanStatus, null, ct).ConfigureAwait(false);
                if (statusResp.Success && !string.IsNullOrWhiteSpace(statusResp.PayloadJson))
                {
                    latestStatus = JsonSerializer.Deserialize<IpcScanStatusDto>(statusResp.PayloadJson, JsonOptions);
                }

                if (latestStatus is not null)
                {
                    progress.Report(new ScanProgress(
                        latestStatus.Percent,
                        latestStatus.CurrentPath,
                        latestStatus.FilesProcessed,
                        latestStatus.TotalFiles,
                        latestStatus.FindingsCount,
                        latestStatus.LastCompletedSummary?.FilesSkipped ?? 0));

                    if (!latestStatus.IsRunning)
                    {
                        break;
                    }
                }

                await Task.Delay(150, ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            await TryCancelScanQuietlyAsync().ConfigureAwait(false);
            throw;
        }

        if (latestStatus is not null &&
            latestStatus.StatusMessage.Contains("canceled", StringComparison.OrdinalIgnoreCase))
        {
            throw new OperationCanceledException(latestStatus.StatusMessage);
        }

        if (latestStatus is not null &&
            latestStatus.LastCompletedSummary is null &&
            latestStatus.StatusMessage.StartsWith("Scan failed:", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(latestStatus.StatusMessage);
        }

        if (latestStatus?.LastCompletedSummary is { } summary)
        {
            var total = summary.FilesScanned + summary.FilesSkipped;
            progress.Report(new ScanProgress(
                Percent: 100,
                CurrentPath: string.Empty,
                FilesProcessed: total,
                FilesTotal: total,
                ThreatsFound: summary.Findings.Count,
                FilesSkipped: summary.FilesSkipped));
        }

        return true;
    }

    /// <inheritdoc />
    public Task<bool> QuarantineThreatAsync(Guid threatId, CancellationToken ct = default) =>
        _fallback.QuarantineThreatAsync(threatId, ct);

    /// <inheritdoc />
    public Task<bool> RestoreAsync(IEnumerable<Guid> ids, CancellationToken ct = default) =>
        _fallback.RestoreAsync(ids, ct);

    /// <inheritdoc />
    public Task<bool> DeleteAsync(IEnumerable<Guid> ids, CancellationToken ct = default) =>
        _fallback.DeleteAsync(ids, ct);

    /// <inheritdoc />
    public Task<string?> AskAssistantAsync(string prompt, CancellationToken ct = default) =>
        _fallback.AskAssistantAsync(prompt, ct);

    private async Task<T?> TrySendOptionalAsync<T>(
        IpcCommandType command,
        string? payloadJson,
        CancellationToken ct)
    {
        try
        {
            var response = await SendCommandAsync(command, payloadJson, ct).ConfigureAwait(false);
            if (!response.Success || string.IsNullOrWhiteSpace(response.PayloadJson))
            {
                return default;
            }

            return JsonSerializer.Deserialize<T>(response.PayloadJson, JsonOptions);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            return default;
        }
    }

    private async Task TryCancelScanQuietlyAsync()
    {
        try
        {
            using var cancelTimeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(1500));
            _ = await SendCommandAsync(IpcCommandType.CancelScan, null, cancelTimeout.Token).ConfigureAwait(false);
        }
        catch
        {
            // Meilleur effort d'annulation côté service lors de la fermeture UI.
        }
    }

    private async Task<IpcResponse> SendCommandAsync(
        IpcCommandType command,
        string? payloadJson,
        CancellationToken cancellationToken)
    {
        var request = new IpcRequest(
            ProtocolVersion: IpcProtocolConstants.ProtocolVersion,
            RequestId: Guid.NewGuid().ToString("N"),
            Command: command,
            TimestampUtc: DateTimeOffset.UtcNow,
            Nonce: Guid.NewGuid().ToString("N"),
            PayloadJson: payloadJson);

        using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        connectCts.CancelAfter(_connectTimeout);

        await using var client = new NamedPipeClientStream(
            ".",
            _pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous);

        await client.ConnectAsync(connectCts.Token).ConfigureAwait(false);

        using var requestCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        requestCts.CancelAfter(_requestTimeout);

        var requestBytes = JsonSerializer.SerializeToUtf8Bytes(request, JsonOptions);
        await WriteFrameAsync(client, requestBytes, requestCts.Token).ConfigureAwait(false);

        var responseBytes = await ReadFrameAsync(client, requestCts.Token).ConfigureAwait(false);
        return JsonSerializer.Deserialize<IpcResponse>(responseBytes, JsonOptions)
            ?? throw new InvalidDataException("La réponse IPC du service est vide.");
    }

    private static async Task WriteFrameAsync(Stream stream, byte[] payload, CancellationToken cancellationToken)
    {
        if (payload.Length == 0 || payload.Length > IpcProtocolConstants.DefaultMaxMessageBytes)
        {
            throw new InvalidOperationException($"Taille de trame IPC invalide : {payload.Length} octets.");
        }

        var buffer = new byte[sizeof(int) + payload.Length];
        BinaryPrimitives.WriteInt32LittleEndian(buffer.AsSpan(0, sizeof(int)), payload.Length);
        payload.AsSpan().CopyTo(buffer.AsSpan(sizeof(int)));

        await stream.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<byte[]> ReadFrameAsync(Stream stream, CancellationToken cancellationToken)
    {
        var header = new byte[sizeof(int)];
        await stream.ReadExactlyAsync(header, cancellationToken).ConfigureAwait(false);

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > IpcProtocolConstants.DefaultMaxMessageBytes)
        {
            throw new IOException($"Longueur de trame IPC hors limites : {length}.");
        }

        var payload = new byte[length];
        await stream.ReadExactlyAsync(payload, cancellationToken).ConfigureAwait(false);
        return payload;
    }

    private static bool IsPipeUnavailable(Exception ex, CancellationToken callerToken) =>
        !callerToken.IsCancellationRequested &&
        ex is IOException or TimeoutException or UnauthorizedAccessException or OperationCanceledException;

    private static GuardianSnapshot BuildDisconnectedSnapshot(GuardianSnapshot fallbackSnapshot) =>
        new(
            State: ProtectionState.Stopped,
            AiEngineActive: false,
            DefinitionsUpToDate: false,
            RealtimeActive: false,
            Engines: [new EngineStatus("Guardian.Service (IPC Named Pipe)", ProtectionState.Stopped)],
            Threats: Array.Empty<ThreatItem>(),
            BlockedThreats: 0,
            Quarantine: fallbackSnapshot.Quarantine,
            EventCount: 0,
            ActiveConnections: fallbackSnapshot.ActiveConnections,
            SuspiciousConnections: fallbackSnapshot.SuspiciousConnections,
            Destinations: fallbackSnapshot.Destinations,
            LastCheck: null,
            SystemInfo: fallbackSnapshot.SystemInfo);

    private static IReadOnlyList<EngineStatus> BuildEngineStatuses(
        GuardianHealthSnapshot health,
        WindowsSecurityPostureDto? posture)
    {
        var list = new List<EngineStatus>(health.Components.Count + 4);

        foreach (var component in health.Components)
        {
            var label = component.ComponentName switch
            {
                "Guardian.Service.Host" => "Service Guardian (Hôte)",
                "Guardian.Service.Watchdog" => "Watchdog anti-boucle",
                "Guardian.Service.SelfIntegrity" => "Auto-intégrité (SHA-256 / ACL)",
                "Guardian.SystemMonitor" => "Surveillance système",
                "Guardian.Service.Ipc" => "Serveur IPC (Named Pipe)",
                _ => component.ComponentName
            };

            list.Add(new EngineStatus(label, MapHealthStatus(component.Status)));
        }

        if (posture is not null)
        {
            list.Add(new EngineStatus("Microsoft Defender", MapControlStatus(posture.Defender)));
            list.Add(new EngineStatus("Pare-feu Windows", MapControlStatus(posture.Firewall)));
            list.Add(new EngineStatus("Contrôle UAC", MapControlStatus(posture.Uac)));
            list.Add(new EngineStatus("Protection LSASS", MapControlStatus(posture.LsassProtection)));
        }

        return list;
    }

    private static ProtectionState MapHealthStatus(GuardianHealthStatus status) => status switch
    {
        GuardianHealthStatus.Healthy => ProtectionState.Healthy,
        GuardianHealthStatus.Degraded => ProtectionState.Degraded,
        GuardianHealthStatus.Stopped => ProtectionState.Stopped,
        GuardianHealthStatus.OutOfDate => ProtectionState.OutOfDate,
        _ => ProtectionState.Unknown
    };

    private static ProtectionState MapControlStatus(SecurityControlStatusDto control) =>
        control.IsEnabled switch
        {
            true => ProtectionState.Healthy,
            false => ProtectionState.Stopped,
            null => ProtectionState.Unknown
        };

    /// <summary>Convertit la posture de sécurité Windows et les événements récents du service pour l'écran Système.</summary>
    private static SystemOverview? BuildSystemOverview(
        WindowsSecurityPostureDto? posture,
        IReadOnlyList<SystemSecurityEventDto>? events)
    {
        if (posture is null)
        {
            return null;
        }

        static SecurityControlRow Row(SecurityControlKind kind, SecurityControlStatusDto c) => new(
            kind,
            MapControlStatus(c),
            c.Summary,
            c.Availability == FeatureAvailabilityStatus.RequiresElevation,
            string.IsNullOrWhiteSpace(c.Recommendation) ? null : c.Recommendation);

        var controls = new[]
        {
            Row(SecurityControlKind.Defender, posture.Defender),
            Row(SecurityControlKind.Firewall, posture.Firewall),
            Row(SecurityControlKind.Uac, posture.Uac),
            Row(SecurityControlKind.SecureBoot, posture.SecureBoot),
            Row(SecurityControlKind.Tpm, posture.Tpm),
            Row(SecurityControlKind.VirtualizationSecurity, posture.VirtualizationBasedSecurity),
            Row(SecurityControlKind.CredentialGuard, posture.CredentialGuard),
            Row(SecurityControlKind.Lsass, posture.LsassProtection),
        };

        var rows = (events ?? Array.Empty<SystemSecurityEventDto>())
            .Select(e => new SystemEventRow(
                e.TimestampUtc.ToLocalTime().DateTime,
                MapEventKind(e.Category),
                MapEventLevel(e.Severity),
                e.Source,
                e.ProcessName,
                e.Summary))
            .ToArray();

        return new SystemOverview(
            posture.CapturedAtUtc.ToLocalTime().DateTime,
            posture.OsVersion,
            posture.WindowsEdition,
            MapPrivilege(posture.CurrentPrivilege),
            controls,
            posture.Recommendations,
            rows);
    }

    private static PrivilegeKind MapPrivilege(PrivilegeLevel level) => level switch
    {
        PrivilegeLevel.StandardUser => PrivilegeKind.Standard,
        PrivilegeLevel.Administrator => PrivilegeKind.Administrator,
        PrivilegeLevel.LocalService or PrivilegeLevel.NetworkService or PrivilegeLevel.LocalSystem => PrivilegeKind.System,
        _ => PrivilegeKind.Unknown,
    };

    private static SystemEventKind MapEventKind(SystemEventCategory category) => category switch
    {
        SystemEventCategory.ProcessLifecycle => SystemEventKind.Process,
        SystemEventCategory.RegistryModification => SystemEventKind.Registry,
        SystemEventCategory.PersistenceChange => SystemEventKind.Persistence,
        SystemEventCategory.FileBurstAnomaly => SystemEventKind.FileBurst,
        SystemEventCategory.UsbDeviceEvent => SystemEventKind.Usb,
        SystemEventCategory.InterProcessAccess => SystemEventKind.InterProcess,
        SystemEventCategory.SecurityPostureChange => SystemEventKind.PostureChange,
        _ => SystemEventKind.SelfIntegrity,
    };

    private static EventLevel MapEventLevel(EventSeverity severity) => severity switch
    {
        EventSeverity.Low => EventLevel.Low,
        EventSeverity.Medium => EventLevel.Medium,
        EventSeverity.High => EventLevel.High,
        EventSeverity.Critical => EventLevel.Critical,
        _ => EventLevel.Info,
    };

    private static ThreatItem ToThreatItem(FileScanResult r) => new(
        Guid.NewGuid(),
        r.Signature?.ThreatName ?? System.IO.Path.GetFileName(r.FilePath),
        r.Verdict == ContractVerdict.Malicious ? RiskLevel.High : RiskLevel.Medium,
        r.ScannedAtUtc.ToLocalTime(),
        r.FilePath,
        string.Join(" ", r.Reasons));
}
