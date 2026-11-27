using System.IO.Pipes;
using System.Text.Json;
using Guardian.Contracts.Health;
using Guardian.Contracts.Ipc;
using Guardian.Contracts.Memory;
using Guardian.Contracts.Scanning;
using Guardian.Contracts.System;

namespace Guardian.Service.Ipc;

/// <summary>
/// Client local typé communiquant avec le serveur Named Pipes du service Guardian.
/// </summary>
public sealed class NamedPipeIpcClient
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    private readonly string _pipeName;
    private readonly int _maxMessageBytes;
    private readonly TimeSpan _timeout;

    /// <summary>
    /// Initialise un client IPC ciblant le Named Pipe local Guardian.
    /// </summary>
    /// <param name="pipeName">Nom du pipe local (par défaut <see cref="IpcProtocolConstants.DefaultPipeName"/>).</param>
    /// <param name="maxMessageBytes">Taille maximale de trame autorisée.</param>
    /// <param name="timeout">Délai maximal par requête.</param>
    public NamedPipeIpcClient(
        string? pipeName = null,
        int maxMessageBytes = IpcProtocolConstants.DefaultMaxMessageBytes,
        TimeSpan? timeout = null)
    {
        _pipeName = string.IsNullOrWhiteSpace(pipeName) ? IpcProtocolConstants.DefaultPipeName : pipeName;
        _maxMessageBytes = maxMessageBytes;
        _timeout = timeout ?? IpcProtocolConstants.DefaultTimeout;
    }

    /// <summary>
    /// Envoie une requête IPC typée et retourne la réponse désérialisée du service.
    /// </summary>
    /// <param name="request">Requête typée et versionnée.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Réponse IPC retournée par le serveur.</returns>
    public async Task<IpcResponse> SendAsync(IpcRequest request, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(_timeout);

        await using var client = new NamedPipeClientStream(
            ".",
            _pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous);

        await client.ConnectAsync(timeoutCts.Token).ConfigureAwait(false);

        var requestBytes = JsonSerializer.SerializeToUtf8Bytes(request, JsonOptions);
        await IpcFraming.WriteFrameAsync(client, requestBytes, _maxMessageBytes, timeoutCts.Token).ConfigureAwait(false);

        var frame = await IpcFraming.ReadFrameAsync(client, _maxMessageBytes, timeoutCts.Token).ConfigureAwait(false);
        if (frame.Status != FrameReadStatus.Success || frame.Payload is null)
        {
            throw new IOException($"Failed to read valid IPC response frame (status={frame.Status}).");
        }

        return JsonSerializer.Deserialize<IpcResponse>(frame.Payload, JsonOptions)
            ?? throw new InvalidDataException("IPC response payload deserialized to null.");
    }

    /// <summary>
    /// Vérifie la disponibilité du service IPC via la commande <see cref="IpcCommandType.Ping"/>.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Réponse brute du serveur.</returns>
    public Task<IpcResponse> PingAsync(CancellationToken cancellationToken = default) =>
        SendCommandAsync(IpcCommandType.Ping, null, cancellationToken);

    /// <summary>
    /// Récupère l'instantané global de santé auprès du service.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Instantané global de santé, ou <see langword="null"/> en cas d'échec.</returns>
    public async Task<GuardianHealthSnapshot?> GetHealthAsync(CancellationToken cancellationToken = default)
    {
        var response = await SendCommandAsync(IpcCommandType.GetHealth, null, cancellationToken).ConfigureAwait(false);
        return DeserializePayload<GuardianHealthSnapshot>(response);
    }

    /// <summary>
    /// Démarre une analyse de fichiers sur le service Guardian.
    /// </summary>
    /// <param name="scope">Portée d'analyse (<c>Quick</c>, <c>Full</c>, <c>Custom</c>).</param>
    /// <param name="customPath">Chemin cible si <paramref name="scope"/> vaut <see cref="ScanScope.Custom"/>.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Réponse IPC et statut initial d'analyse.</returns>
    public async Task<(IpcResponse Response, IpcScanStatusDto? Status)> StartScanAsync(
        ScanScope scope,
        string? customPath = null,
        CancellationToken cancellationToken = default)
    {
        var payloadJson = JsonSerializer.Serialize(new IpcStartScanPayload(scope, customPath), JsonOptions);
        var response = await SendCommandAsync(IpcCommandType.StartScan, payloadJson, cancellationToken).ConfigureAwait(false);
        return (response, DeserializePayload<IpcScanStatusDto>(response));
    }

    /// <summary>
    /// Récupère la progression courante ou le dernier bilan d'analyse auprès du service.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Instantané de progression ou <see langword="null"/>.</returns>
    public async Task<IpcScanStatusDto?> GetScanStatusAsync(CancellationToken cancellationToken = default)
    {
        var response = await SendCommandAsync(IpcCommandType.GetScanStatus, null, cancellationToken).ConfigureAwait(false);
        return DeserializePayload<IpcScanStatusDto>(response);
    }

    /// <summary>
    /// Demande l'annulation de l'analyse en cours auprès du service.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Statut mis à jour après demande d'annulation.</returns>
    public async Task<IpcScanStatusDto?> CancelScanAsync(CancellationToken cancellationToken = default)
    {
        var response = await SendCommandAsync(IpcCommandType.CancelScan, null, cancellationToken).ConfigureAwait(false);
        return DeserializePayload<IpcScanStatusDto>(response);
    }

    /// <summary>
    /// Récupère les événements système et comportementaux récents conservés par le service.
    /// </summary>
    /// <param name="maxCount">Nombre maximal d'événements souhaité (1 à 100).</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Liste des événements récents ou <see langword="null"/> en cas d'échec.</returns>
    public async Task<IReadOnlyList<SystemSecurityEventDto>?> GetRecentSystemEventsAsync(
        int maxCount = 50,
        CancellationToken cancellationToken = default)
    {
        var payloadJson = JsonSerializer.Serialize(Math.Clamp(maxCount, 1, 100), JsonOptions);
        var response = await SendCommandAsync(IpcCommandType.GetRecentSystemEvents, payloadJson, cancellationToken).ConfigureAwait(false);
        return DeserializePayload<IReadOnlyList<SystemSecurityEventDto>>(response);
    }

    /// <summary>
    /// Déclenche une analyse défensive des métadonnées mémoire (sans lecture de secrets) sur un processus ou l'ensemble accessible.
    /// </summary>
    /// <param name="processId">PID cible optionnel, ou <see langword="null"/> pour analyser les processus accessibles.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Rapports d'analyse mémoire ou <see langword="null"/> en cas d'échec.</returns>
    public async Task<IReadOnlyList<MemoryAnalysisReportDto>?> RunMemoryAnalysisAsync(
        int? processId = null,
        CancellationToken cancellationToken = default)
    {
        var payloadJson = processId is > 0 ? JsonSerializer.Serialize(processId.Value, JsonOptions) : null;
        var response = await SendCommandAsync(IpcCommandType.RunMemoryAnalysis, payloadJson, cancellationToken).ConfigureAwait(false);
        return DeserializePayload<IReadOnlyList<MemoryAnalysisReportDto>>(response);
    }

    private Task<IpcResponse> SendCommandAsync(
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

        return SendAsync(request, cancellationToken);
    }

    private static T? DeserializePayload<T>(IpcResponse response)
    {
        if (!response.Success || string.IsNullOrWhiteSpace(response.PayloadJson))
        {
            return default;
        }

        return JsonSerializer.Deserialize<T>(response.PayloadJson, JsonOptions);
    }
}
