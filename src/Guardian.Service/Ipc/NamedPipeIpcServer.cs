using System.IO.Pipes;
using System.Runtime.Versioning;
using System.Text.Json;
using Guardian.Contracts.Common;
using Guardian.Contracts.Health;
using Guardian.Contracts.Ipc;
using Guardian.Service.Configuration;
using Guardian.Service.Watchdog;
using Guardian.Windows.Security;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Guardian.Service.Ipc;

/// <summary>
/// Serveur Named Pipes local authentifié et protégé par ACL exposant le répartiteur IPC du service Guardian.
/// </summary>
public sealed class NamedPipeIpcServer : BackgroundService, IMonitoredComponent
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly IIpcRequestDispatcher _dispatcher;
    private readonly IWindowsAclInspector _aclInspector;
    private readonly IGuardianHealthService _healthService;
    private readonly IOptions<GuardianServiceOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<NamedPipeIpcServer> _logger;
    private readonly SemaphoreSlim _connectionLimiter;
    private readonly object _lifecycleGate = new();

    private CancellationTokenSource? _acceptCts;
    private Task? _acceptLoopTask;
    private volatile bool _isHealthy;
    private DateTimeOffset? _lastHeartbeatUtc;

    /// <summary>
    /// Initialise le serveur Named Pipes local Guardian.
    /// </summary>
    /// <param name="dispatcher">Répartiteur de commandes IPC authentifiées.</param>
    /// <param name="aclInspector">Inspecteur et générateur d'ACL restrictives.</param>
    /// <param name="healthService">Service central de santé Guardian.</param>
    /// <param name="options">Options validées du service.</param>
    /// <param name="timeProvider">Fournisseur d'horloge injecté.</param>
    /// <param name="logger">Journaliseur structuré.</param>
    public NamedPipeIpcServer(
        IIpcRequestDispatcher dispatcher,
        IWindowsAclInspector aclInspector,
        IGuardianHealthService healthService,
        IOptions<GuardianServiceOptions> options,
        TimeProvider timeProvider,
        ILogger<NamedPipeIpcServer> logger)
    {
        _dispatcher = dispatcher ?? throw new ArgumentNullException(nameof(dispatcher));
        _aclInspector = aclInspector ?? throw new ArgumentNullException(nameof(aclInspector));
        _healthService = healthService ?? throw new ArgumentNullException(nameof(healthService));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        var maxConnections = Math.Max(1, _options.Value.IpcMaxConcurrentConnections);
        _connectionLimiter = new SemaphoreSlim(maxConnections, maxConnections);
    }

    /// <inheritdoc />
    public string ComponentName => GuardianServiceConstants.IpcComponentName;

    /// <inheritdoc />
    public bool IsHealthy => _isHealthy;

    /// <inheritdoc />
    public DateTimeOffset? LastHeartbeatUtc => _lastHeartbeatUtc;

    /// <inheritdoc />
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        var now = _timeProvider.GetUtcNow();
        _isHealthy = true;
        _lastHeartbeatUtc = now;

        await _healthService.ReportComponentHealthAsync(
            new ComponentHealthReport(
                ComponentName: ComponentName,
                Status: GuardianHealthStatus.Healthy,
                Summary: $"IPC Named Pipe server listening on '{_options.Value.IpcPipeName}'.",
                LastUpdatedUtc: now,
                LastHeartbeatUtc: now,
                Availability: FeatureAvailabilityStatus.Available,
                Reasons: []),
            cancellationToken).ConfigureAwait(false);

        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await RunServerLoopAsync(stoppingToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task RestartAsync(CancellationToken cancellationToken = default)
    {
        _logger.LogWarning("Restarting IPC Named Pipe server '{PipeName}'.", _options.Value.IpcPipeName);
        CancellationTokenSource? previousCts;
        Task? previousTask;

        lock (_lifecycleGate)
        {
            previousCts = _acceptCts;
            previousTask = _acceptLoopTask;
        }

        if (previousCts is not null)
        {
            await previousCts.CancelAsync().ConfigureAwait(false);
        }

        if (previousTask is not null)
        {
            try
            {
                await previousTask.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Ignorer l'annulation attendue lors du redémarrage.
            }
        }

        _ = Task.Run(() => RunServerLoopAsync(cancellationToken), CancellationToken.None);
        var now = _timeProvider.GetUtcNow();
        _isHealthy = true;
        _lastHeartbeatUtc = now;
    }

    /// <inheritdoc />
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _isHealthy = false;
        CancellationTokenSource? currentCts;
        lock (_lifecycleGate)
        {
            currentCts = _acceptCts;
        }

        if (currentCts is not null)
        {
            await currentCts.CancelAsync().ConfigureAwait(false);
        }

        await base.StopAsync(cancellationToken).ConfigureAwait(false);

        var now = _timeProvider.GetUtcNow();
        _lastHeartbeatUtc = now;

        await _healthService.ReportComponentHealthAsync(
            new ComponentHealthReport(
                ComponentName: ComponentName,
                Status: GuardianHealthStatus.Stopped,
                Summary: "IPC Named Pipe server stopped cleanly.",
                LastUpdatedUtc: now,
                LastHeartbeatUtc: now,
                Availability: FeatureAvailabilityStatus.Unavailable,
                Reasons: ["IPC server stopped."]),
            cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public override void Dispose()
    {
        _connectionLimiter.Dispose();
        base.Dispose();
    }

    private async Task RunServerLoopAsync(CancellationToken stoppingToken)
    {
        var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        Task acceptTask;

        lock (_lifecycleGate)
        {
            _acceptCts?.Dispose();
            _acceptCts = linkedCts;
            acceptTask = AcceptConnectionsAsync(linkedCts.Token);
            _acceptLoopTask = acceptTask;
        }

        using var heartbeatTimer = new PeriodicTimer(
            TimeSpan.FromSeconds(_options.Value.HeartbeatIntervalSeconds),
            _timeProvider);

        var heartbeatTask = Task.Run(async () =>
        {
            try
            {
                while (await heartbeatTimer.WaitForNextTickAsync(linkedCts.Token).ConfigureAwait(false))
                {
                    if (_isHealthy)
                    {
                        var now = _timeProvider.GetUtcNow();
                        _lastHeartbeatUtc = now;
                        await _healthService.RecordHeartbeatAsync(ComponentName, now, linkedCts.Token).ConfigureAwait(false);
                    }
                }
            }
            catch (OperationCanceledException) when (linkedCts.IsCancellationRequested)
            {
                // Arrêt normal.
            }
        }, CancellationToken.None);

        try
        {
            await acceptTask.ConfigureAwait(false);
        }
        finally
        {
            await linkedCts.CancelAsync().ConfigureAwait(false);
            try
            {
                await heartbeatTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                // Arrêt normal.
            }
        }
    }

    private async Task AcceptConnectionsAsync(CancellationToken cancellationToken)
    {
        var pipeName = _options.Value.IpcPipeName;
        var allowInteractive = _options.Value.AllowNonAdminInteractiveIpc;

        while (!cancellationToken.IsCancellationRequested)
        {
            var limiterAcquired = false;
            NamedPipeServerStream? serverStream = null;

            try
            {
                await _connectionLimiter.WaitAsync(cancellationToken).ConfigureAwait(false);
                limiterAcquired = true;

                serverStream = CreatePipeServerStream(pipeName, allowInteractive);
                await serverStream.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);

                var connectedPipe = serverStream;
                serverStream = null;
                limiterAcquired = false;

                _ = Task.Run(
                    async () => await HandleClientConnectionAsync(connectedPipe, cancellationToken).ConfigureAwait(false),
                    CancellationToken.None);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error accepting Named Pipe client connection on '{PipeName}'.", pipeName);
                await Task.Delay(TimeSpan.FromMilliseconds(200), cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                serverStream?.Dispose();
                if (limiterAcquired)
                {
                    _connectionLimiter.Release();
                }
            }
        }
    }

    private async Task HandleClientConnectionAsync(NamedPipeServerStream pipeStream, CancellationToken serverToken)
    {
        try
        {
            IpcClientContext? clientContext = null;
            var options = _options.Value;
            var readTimeout = TimeSpan.FromSeconds(options.IpcReadTimeoutSeconds);

            while (!serverToken.IsCancellationRequested && pipeStream.IsConnected)
            {
                using var readCts = CancellationTokenSource.CreateLinkedTokenSource(serverToken);
                readCts.CancelAfter(readTimeout);

                FrameReadResult frame;
                try
                {
                    frame = await IpcFraming
                        .ReadFrameAsync(pipeStream, options.IpcMaxMessageBytes, readCts.Token)
                        .ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (!serverToken.IsCancellationRequested)
                {
                    var timeoutResponse = CreateErrorResponse(string.Empty, IpcErrorCode.Timeout, "IPC read timed out.");
                    await TryWriteResponseAsync(pipeStream, timeoutResponse, options.IpcMaxMessageBytes, serverToken)
                        .ConfigureAwait(false);
                    break;
                }

                if (frame.Status == FrameReadStatus.Disconnected)
                {
                    break;
                }

                if (frame.Status == FrameReadStatus.PayloadTooLarge)
                {
                    var tooLarge = CreateErrorResponse(
                        string.Empty,
                        IpcErrorCode.PayloadTooLarge,
                        $"IPC message exceeds maximum allowed size of {options.IpcMaxMessageBytes} bytes.");
                    await TryWriteResponseAsync(pipeStream, tooLarge, options.IpcMaxMessageBytes, serverToken)
                        .ConfigureAwait(false);
                    break;
                }

                if (frame.Status == FrameReadStatus.InvalidLength || frame.Payload is null)
                {
                    var invalidLength = CreateErrorResponse(
                        string.Empty,
                        IpcErrorCode.InvalidRequest,
                        "Invalid IPC frame length.");
                    await TryWriteResponseAsync(pipeStream, invalidLength, options.IpcMaxMessageBytes, serverToken)
                        .ConfigureAwait(false);
                    break;
                }

                IpcRequest? request;
                try
                {
                    request = JsonSerializer.Deserialize<IpcRequest>(frame.Payload, JsonOptions);
                }
                catch (JsonException)
                {
                    var malformed = CreateErrorResponse(
                        string.Empty,
                        IpcErrorCode.InvalidRequest,
                        "Malformed JSON IPC request.");
                    await TryWriteResponseAsync(pipeStream, malformed, options.IpcMaxMessageBytes, serverToken)
                        .ConfigureAwait(false);
                    continue;
                }

                if (request is null)
                {
                    var nullRequest = CreateErrorResponse(
                        string.Empty,
                        IpcErrorCode.InvalidRequest,
                        "IPC request deserialized to null.");
                    await TryWriteResponseAsync(pipeStream, nullRequest, options.IpcMaxMessageBytes, serverToken)
                        .ConfigureAwait(false);
                    continue;
                }

                using var dispatchCts = CancellationTokenSource.CreateLinkedTokenSource(serverToken);
                dispatchCts.CancelAfter(readTimeout);

                clientContext ??= IpcClientIdentityReader.ReadClientContext(pipeStream);
                var response = await _dispatcher
                    .DispatchAsync(request, clientContext, dispatchCts.Token)
                    .ConfigureAwait(false);

                _lastHeartbeatUtc = _timeProvider.GetUtcNow();
                await TryWriteResponseAsync(pipeStream, response, options.IpcMaxMessageBytes, serverToken)
                    .ConfigureAwait(false);
            }
        }
        catch (IOException)
        {
            // Déconnexion brutale du client gérée proprement sans affecter le serveur.
        }
        catch (OperationCanceledException) when (serverToken.IsCancellationRequested)
        {
            // Arrêt du serveur.
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected failure in IPC client session.");
        }
        finally
        {
            pipeStream.Dispose();
            _connectionLimiter.Release();
        }
    }

    private NamedPipeServerStream CreatePipeServerStream(string pipeName, bool allowInteractive)
    {
        if (OperatingSystem.IsWindows())
        {
            return CreateWindowsPipeServerStream(pipeName, allowInteractive);
        }

        return new NamedPipeServerStream(
            pipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous);
    }

    [SupportedOSPlatform("windows")]
    private NamedPipeServerStream CreateWindowsPipeServerStream(string pipeName, bool allowInteractive)
    {
        var pipeSecurity = _aclInspector.CreateRestrictedPipeSecurity(
            allowCurrentUser: true,
            allowAuthenticatedUsers: allowInteractive);

        return NamedPipeServerStreamAcl.Create(
            pipeName: pipeName,
            direction: PipeDirection.InOut,
            maxNumberOfServerInstances: NamedPipeServerStream.MaxAllowedServerInstances,
            transmissionMode: PipeTransmissionMode.Byte,
            options: PipeOptions.Asynchronous,
            inBufferSize: 0,
            outBufferSize: 0,
            pipeSecurity: pipeSecurity);
    }

    private IpcResponse CreateErrorResponse(string requestId, IpcErrorCode errorCode, string message) =>
        new(
            ProtocolVersion: IpcProtocolConstants.ProtocolVersion,
            RequestId: requestId,
            Success: false,
            ErrorCode: errorCode,
            ErrorMessage: message,
            TimestampUtc: _timeProvider.GetUtcNow(),
            PayloadJson: null);

    private static async Task TryWriteResponseAsync(
        Stream stream,
        IpcResponse response,
        int maxMessageBytes,
        CancellationToken cancellationToken)
    {
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(response, JsonOptions);
            await IpcFraming.WriteFrameAsync(stream, bytes, maxMessageBytes, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or OperationCanceledException)
        {
            // Le pair s'est déconnecté avant l'écriture de la réponse.
        }
    }
}
