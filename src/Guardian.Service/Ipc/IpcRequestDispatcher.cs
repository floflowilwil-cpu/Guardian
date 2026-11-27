using System.Text;
using System.Text.Json;
using Guardian.Contracts.Health;
using Guardian.Contracts.Ipc;
using Guardian.Contracts.Memory;
using Guardian.Contracts.System;
using Guardian.Service.Configuration;
using Guardian.Service.Scanning;
using Guardian.Service.Security;
using Guardian.Service.Watchdog;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Guardian.Service.Ipc;

/// <summary>
/// Valide, autorise, journalise (sans fuite de données sensibles) et exécute les commandes IPC typées.
/// </summary>
public sealed class IpcRequestDispatcher : IIpcRequestDispatcher
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly IGuardianHealthService _healthService;
    private readonly WatchdogTracker _watchdogTracker;
    private readonly ISystemMonitor _systemMonitor;
    private readonly IBehaviorMonitor _behaviorMonitor;
    private readonly IMemoryAnalyzer _memoryAnalyzer;
    private readonly ISelfIntegrityMonitor _selfIntegrityMonitor;
    private readonly IScanExecutionCoordinator _scanCoordinator;
    private readonly IpcReplayGuard _replayGuard;
    private readonly IOptions<GuardianServiceOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<IpcRequestDispatcher> _logger;

    /// <summary>
    /// Initialise le répartiteur de commandes IPC locales.
    /// </summary>
    /// <param name="healthService">Service central de santé Guardian.</param>
    /// <param name="watchdogTracker">Suivi d'état du watchdog.</param>
    /// <param name="systemMonitor">Moniteur système en lecture seule (processus, services, persistance, posture).</param>
    /// <param name="behaviorMonitor">Moniteur comportemental temps réel en mémoire bornée.</param>
    /// <param name="memoryAnalyzer">Analyseur défensif des métadonnées mémoire.</param>
    /// <param name="selfIntegrityMonitor">Moniteur d'auto-intégrité.</param>
    /// <param name="scanCoordinator">Coordinateur d'analyses de fichiers.</param>
    /// <param name="replayGuard">Protection anti-rejeu IPC.</param>
    /// <param name="options">Options validées du service.</param>
    /// <param name="timeProvider">Fournisseur d'horloge injecté.</param>
    /// <param name="logger">Journaliseur d'audit structuré.</param>
    public IpcRequestDispatcher(
        IGuardianHealthService healthService,
        WatchdogTracker watchdogTracker,
        ISystemMonitor systemMonitor,
        IBehaviorMonitor behaviorMonitor,
        IMemoryAnalyzer memoryAnalyzer,
        ISelfIntegrityMonitor selfIntegrityMonitor,
        IScanExecutionCoordinator scanCoordinator,
        IpcReplayGuard replayGuard,
        IOptions<GuardianServiceOptions> options,
        TimeProvider timeProvider,
        ILogger<IpcRequestDispatcher> logger)
    {
        _healthService = healthService ?? throw new ArgumentNullException(nameof(healthService));
        _watchdogTracker = watchdogTracker ?? throw new ArgumentNullException(nameof(watchdogTracker));
        _systemMonitor = systemMonitor ?? throw new ArgumentNullException(nameof(systemMonitor));
        _behaviorMonitor = behaviorMonitor ?? throw new ArgumentNullException(nameof(behaviorMonitor));
        _memoryAnalyzer = memoryAnalyzer ?? throw new ArgumentNullException(nameof(memoryAnalyzer));
        _selfIntegrityMonitor = selfIntegrityMonitor ?? throw new ArgumentNullException(nameof(selfIntegrityMonitor));
        _scanCoordinator = scanCoordinator ?? throw new ArgumentNullException(nameof(scanCoordinator));
        _replayGuard = replayGuard ?? throw new ArgumentNullException(nameof(replayGuard));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public async Task<IpcResponse> DispatchAsync(
        IpcRequest request,
        IpcClientContext clientContext,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(clientContext);
        cancellationToken.ThrowIfCancellationRequested();

        var now = _timeProvider.GetUtcNow();

        if (!string.Equals(request.ProtocolVersion, IpcProtocolConstants.ProtocolVersion, StringComparison.Ordinal))
        {
            return Failure(
                request.RequestId,
                IpcErrorCode.InvalidProtocolVersion,
                $"Unsupported IPC protocol version '{request.ProtocolVersion}'.",
                now);
        }

        if (string.IsNullOrWhiteSpace(request.RequestId))
        {
            return Failure(
                string.Empty,
                IpcErrorCode.InvalidRequest,
                "RequestId must not be empty.",
                now);
        }

        if (!Enum.IsDefined(request.Command) || request.Command == IpcCommandType.Unknown)
        {
            return Failure(
                request.RequestId,
                IpcErrorCode.UnknownCommand,
                $"Command '{request.Command}' is not allowed.",
                now);
        }

        if (!_replayGuard.TryValidate(request, out var replayReason))
        {
            _logger.LogWarning(
                "IPC replay check rejected request {RequestId} ({Command}) from {Identity}.",
                request.RequestId,
                request.Command,
                clientContext.IdentityName);

            return Failure(
                request.RequestId,
                IpcErrorCode.ReplayDetected,
                replayReason ?? "Replay detected.",
                now);
        }

        if (!_options.Value.AllowNonAdminInteractiveIpc && !clientContext.IsAdministrator)
        {
            _logger.LogWarning(
                "IPC authorization denied command {Command} for non-admin client {Identity} (PID {Pid}).",
                request.Command,
                clientContext.IdentityName,
                clientContext.ClientProcessId);

            return Failure(
                request.RequestId,
                IpcErrorCode.Unauthorized,
                "Administrator privileges are required for IPC access by current policy.",
                now);
        }

        _logger.LogInformation(
            "IPC audit: executing {Command} (RequestId={RequestId}, Client={Identity}, Pid={Pid}, IsAdmin={IsAdmin}).",
            request.Command,
            request.RequestId,
            clientContext.IdentityName,
            clientContext.ClientProcessId,
            clientContext.IsAdministrator);

        try
        {
            return await ExecuteCommandAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return Failure(
                request.RequestId,
                IpcErrorCode.Timeout,
                "The IPC command timed out or was canceled.",
                _timeProvider.GetUtcNow());
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "IPC command {Command} failed for request {RequestId}.", request.Command, request.RequestId);
            return Failure(
                request.RequestId,
                IpcErrorCode.InternalError,
                "An internal error occurred while executing the IPC command.",
                _timeProvider.GetUtcNow());
        }
    }

    private async Task<IpcResponse> ExecuteCommandAsync(IpcRequest request, CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();

        switch (request.Command)
        {
            case IpcCommandType.Ping:
                return Success(request.RequestId, JsonSerializer.Serialize("pong", JsonOptions), now);

            case IpcCommandType.GetHealth:
            {
                var snapshot = await _healthService.GetOverallHealthAsync(cancellationToken).ConfigureAwait(false);
                return Success(request.RequestId, JsonSerializer.Serialize(snapshot, JsonOptions), _timeProvider.GetUtcNow());
            }

            case IpcCommandType.GetComponentHealth:
            {
                if (!TryDeserialize<string>(request.PayloadJson, out var componentName) ||
                    string.IsNullOrWhiteSpace(componentName))
                {
                    return Failure(request.RequestId, IpcErrorCode.InvalidRequest, "A valid JSON string component name is required.", now);
                }

                var report = await _healthService.GetComponentHealthAsync(componentName, cancellationToken).ConfigureAwait(false);
                var payload = report is null ? null : JsonSerializer.Serialize(report, JsonOptions);
                return Success(request.RequestId, payload, _timeProvider.GetUtcNow());
            }

            case IpcCommandType.GetWatchdogStatus:
            {
                var snapshot = _watchdogTracker.CaptureSnapshot();
                return Success(request.RequestId, JsonSerializer.Serialize(snapshot, JsonOptions), now);
            }

            case IpcCommandType.GetSecurityPosture:
            {
                var posture = await _systemMonitor.GetSecurityPostureAsync(cancellationToken).ConfigureAwait(false);
                return Success(request.RequestId, JsonSerializer.Serialize(posture, JsonOptions), _timeProvider.GetUtcNow());
            }

            case IpcCommandType.GetProcesses:
            {
                var processes = await _systemMonitor.GetProcessesAsync(includeModules: false, cancellationToken).ConfigureAwait(false);
                return Success(request.RequestId, JsonSerializer.Serialize(processes, JsonOptions), _timeProvider.GetUtcNow());
            }

            case IpcCommandType.GetServices:
            {
                var services = await _systemMonitor.GetServicesAsync(cancellationToken).ConfigureAwait(false);
                return Success(request.RequestId, JsonSerializer.Serialize(services, JsonOptions), _timeProvider.GetUtcNow());
            }

            case IpcCommandType.GetStartupEntries:
            {
                var entries = await _systemMonitor.GetStartupEntriesAsync(cancellationToken).ConfigureAwait(false);
                return Success(request.RequestId, JsonSerializer.Serialize(entries, JsonOptions), _timeProvider.GetUtcNow());
            }

            case IpcCommandType.RequestSelfIntegrityCheck:
            {
                var report = await _selfIntegrityMonitor.VerifyIntegrityAsync(cancellationToken).ConfigureAwait(false);
                return Success(request.RequestId, JsonSerializer.Serialize(report, JsonOptions), _timeProvider.GetUtcNow());
            }

            case IpcCommandType.StartScan:
            {
                if (!TryDeserialize<IpcStartScanPayload>(request.PayloadJson, out var scanPayload) || scanPayload is null)
                {
                    return Failure(request.RequestId, IpcErrorCode.InvalidRequest, "A valid IpcStartScanPayload JSON object is required.", now);
                }

                var (accepted, message, status) = await _scanCoordinator
                    .StartScanAsync(scanPayload.Scope, scanPayload.CustomPath, CancellationToken.None)
                    .ConfigureAwait(false);

                var statusJson = JsonSerializer.Serialize(status, JsonOptions);
                return accepted
                    ? Success(request.RequestId, statusJson, _timeProvider.GetUtcNow())
                    : new IpcResponse(
                        ProtocolVersion: IpcProtocolConstants.ProtocolVersion,
                        RequestId: request.RequestId,
                        Success: false,
                        ErrorCode: IpcErrorCode.InvalidRequest,
                        ErrorMessage: message,
                        TimestampUtc: _timeProvider.GetUtcNow(),
                        PayloadJson: statusJson);
            }

            case IpcCommandType.GetScanStatus:
            {
                var status = _scanCoordinator.GetStatus();
                return Success(request.RequestId, JsonSerializer.Serialize(status, JsonOptions), now);
            }

            case IpcCommandType.CancelScan:
            {
                _ = _scanCoordinator.CancelActiveScan();
                var status = _scanCoordinator.GetStatus();
                return Success(request.RequestId, JsonSerializer.Serialize(status, JsonOptions), now);
            }

            case IpcCommandType.GetRecentSystemEvents:
            {
                var maxCount = 50;
                if (!string.IsNullOrWhiteSpace(request.PayloadJson))
                {
                    if (!TryDeserialize<int>(request.PayloadJson, out var requestedCount))
                    {
                        return Failure(request.RequestId, IpcErrorCode.InvalidRequest, "PayloadJson must be empty or a valid integer count.", now);
                    }

                    maxCount = requestedCount;
                }

                var clampedCount = Math.Clamp(maxCount, 1, 100);
                var events = await _behaviorMonitor.GetRecentEventsAsync(clampedCount, cancellationToken).ConfigureAwait(false);
                return Success(request.RequestId, JsonSerializer.Serialize(events, JsonOptions), _timeProvider.GetUtcNow());
            }

            case IpcCommandType.RunMemoryAnalysis:
            {
                if (!string.IsNullOrWhiteSpace(request.PayloadJson))
                {
                    if (!TryDeserialize<int>(request.PayloadJson, out var processId) || processId <= 0)
                    {
                        return Failure(request.RequestId, IpcErrorCode.InvalidRequest, "PayloadJson must be empty or a positive integer process ID.", now);
                    }

                    var singleReport = await _memoryAnalyzer.AnalyzeProcessAsync(processId, cancellationToken).ConfigureAwait(false);
                    return Success(request.RequestId, JsonSerializer.Serialize(new[] { singleReport }, JsonOptions), _timeProvider.GetUtcNow());
                }

                var allReports = await _memoryAnalyzer.ScanAllAccessibleProcessesAsync(cancellationToken).ConfigureAwait(false);
                var ordered = allReports
                    .OrderByDescending(r => r.Signals.Count > 0)
                    .ThenBy(r => r.ProcessId)
                    .ToArray();

                var payloadJson = SerializeWithinIpcBudget(ordered, maxInitialItems: 80);
                return Success(request.RequestId, payloadJson, _timeProvider.GetUtcNow());
            }

            default:
                return Failure(request.RequestId, IpcErrorCode.UnknownCommand, $"Unsupported command '{request.Command}'.", now);
        }
    }

    private static bool TryDeserialize<T>(string? json, out T? value)
    {
        value = default;
        if (string.IsNullOrWhiteSpace(json))
        {
            return false;
        }

        try
        {
            value = JsonSerializer.Deserialize<T>(json, JsonOptions);
            return value is not null;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private string SerializeWithinIpcBudget(IReadOnlyList<MemoryAnalysisReportDto> reports, int maxInitialItems)
    {
        var maxBudgetBytes = Math.Max(4096, _options.Value.IpcMaxMessageBytes - 2048);
        var limit = Math.Min(reports.Count, maxInitialItems);

        while (limit > 0)
        {
            var slice = reports.Take(limit).ToArray();
            var json = JsonSerializer.Serialize(slice, JsonOptions);
            if (Encoding.UTF8.GetByteCount(json) <= maxBudgetBytes)
            {
                return json;
            }

            limit = Math.Max(0, limit / 2);
        }

        return "[]";
    }

    private static IpcResponse Success(string requestId, string? payloadJson, DateTimeOffset timestampUtc) =>
        new(
            ProtocolVersion: IpcProtocolConstants.ProtocolVersion,
            RequestId: requestId,
            Success: true,
            ErrorCode: IpcErrorCode.None,
            ErrorMessage: null,
            TimestampUtc: timestampUtc,
            PayloadJson: payloadJson);

    private static IpcResponse Failure(string requestId, IpcErrorCode errorCode, string errorMessage, DateTimeOffset timestampUtc) =>
        new(
            ProtocolVersion: IpcProtocolConstants.ProtocolVersion,
            RequestId: requestId,
            Success: false,
            ErrorCode: errorCode,
            ErrorMessage: errorMessage,
            TimestampUtc: timestampUtc,
            PayloadJson: null);
}
