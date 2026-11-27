using System.Collections.Concurrent;
using Guardian.Contracts.Ipc;
using Guardian.Service.Configuration;
using Microsoft.Extensions.Options;

namespace Guardian.Service.Ipc;

/// <summary>
/// Protège le canal IPC local contre les attaques par rejeu et les requêtes hors fenêtre temporelle.
/// </summary>
public sealed class IpcReplayGuard
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _seenRequests = new(StringComparer.Ordinal);
    private readonly IOptions<GuardianServiceOptions> _options;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// Initialise le module de protection anti-rejeu IPC.
    /// </summary>
    /// <param name="options">Options validées du service Guardian.</param>
    /// <param name="timeProvider">Fournisseur d'horloge optionnel (par défaut <see cref="TimeProvider.System"/>).</param>
    public IpcReplayGuard(
        IOptions<GuardianServiceOptions> options,
        TimeProvider? timeProvider = null)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    /// <summary>
    /// Vérifie qu'une requête IPC est dans sa fenêtre de validité temporelle et n'a pas déjà été traitée.
    /// </summary>
    /// <param name="request">Requête IPC à valider.</param>
    /// <param name="failureReason">Motif lisible en cas de rejet.</param>
    /// <returns><see langword="true"/> si la requête est acceptée ; <see langword="false"/> en cas de rejeu ou d'horodatage invalide.</returns>
    public bool TryValidate(IpcRequest request, out string? failureReason)
    {
        ArgumentNullException.ThrowIfNull(request);

        var now = _timeProvider.GetUtcNow();
        var windowSeconds = _options.Value.IpcReplayWindowSeconds;
        var window = TimeSpan.FromSeconds(windowSeconds);

        PurgeExpired(now, window);

        var skewSeconds = Math.Abs((now - request.TimestampUtc).TotalSeconds);
        if (skewSeconds > windowSeconds)
        {
            failureReason = $"Request timestamp is outside the allowed {windowSeconds}s replay window.";
            return false;
        }

        var compositeKey = $"{request.RequestId}:{request.Nonce ?? string.Empty}";
        var expiresAtUtc = now.Add(window);

        if (!_seenRequests.TryAdd(compositeKey, expiresAtUtc))
        {
            failureReason = "Duplicate IPC request identifier or nonce detected.";
            return false;
        }

        failureReason = null;
        return true;
    }

    private void PurgeExpired(DateTimeOffset now, TimeSpan window)
    {
        foreach (var entry in _seenRequests)
        {
            if (entry.Value <= now || (entry.Value - now) > window.Add(TimeSpan.FromSeconds(5)))
            {
                _ = _seenRequests.TryRemove(entry.Key, out _);
            }
        }
    }
}
