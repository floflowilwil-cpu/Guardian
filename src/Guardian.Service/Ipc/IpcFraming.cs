using System.Buffers.Binary;

namespace Guardian.Service.Ipc;

/// <summary>
/// Statut de lecture d'une trame IPC préfixée par sa longueur.
/// </summary>
public enum FrameReadStatus
{
    /// <summary>
    /// Trame lue intégralement dans la limite autorisée.
    /// </summary>
    Success = 0,

    /// <summary>
    /// Le pair a fermé la connexion proprement avant l'envoi d'une trame.
    /// </summary>
    Disconnected = 1,

    /// <summary>
    /// L'en-tête de longueur est négatif, nul ou tronqué.
    /// </summary>
    InvalidLength = 2,

    /// <summary>
    /// La longueur annoncée dépasse le plafond autorisé (rejet avant allocation).
    /// </summary>
    PayloadTooLarge = 3
}

/// <summary>
/// Résultat d'une lecture de trame binaire sur flux IPC.
/// </summary>
/// <param name="Status">Statut de la lecture.</param>
/// <param name="Payload">Charge utile UTF-8 en cas de succès, sinon <see langword="null"/>.</param>
public readonly record struct FrameReadResult(FrameReadStatus Status, byte[]? Payload);

/// <summary>
/// Gère le cadrage binaire des messages IPC (préfixe 32 bits little-endian + validation stricte de taille avant allocation).
/// </summary>
public static class IpcFraming
{
    /// <summary>
    /// Lit une trame bornée depuis un flux sans allouer de tampon si la taille annoncée dépasse <paramref name="maxMessageBytes"/>.
    /// </summary>
    /// <param name="stream">Flux connecté.</param>
    /// <param name="maxMessageBytes">Plafond maximal autorisé en octets.</param>
    /// <param name="cancellationToken">Jeton d'annulation et timeout.</param>
    /// <returns>Résultat typé de lecture.</returns>
    public static async Task<FrameReadResult> ReadFrameAsync(
        Stream stream,
        int maxMessageBytes,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maxMessageBytes, 0);

        var header = new byte[sizeof(int)];
        var headerRead = 0;

        while (headerRead < header.Length)
        {
            var bytes = await stream.ReadAsync(header.AsMemory(headerRead), cancellationToken).ConfigureAwait(false);
            if (bytes == 0)
            {
                return headerRead == 0
                    ? new FrameReadResult(FrameReadStatus.Disconnected, null)
                    : new FrameReadResult(FrameReadStatus.InvalidLength, null);
            }

            headerRead += bytes;
        }

        var payloadLength = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (payloadLength <= 0)
        {
            return new FrameReadResult(FrameReadStatus.InvalidLength, null);
        }

        if (payloadLength > maxMessageBytes)
        {
            return new FrameReadResult(FrameReadStatus.PayloadTooLarge, null);
        }

        var buffer = new byte[payloadLength];
        await stream.ReadExactlyAsync(buffer, cancellationToken).ConfigureAwait(false);
        return new FrameReadResult(FrameReadStatus.Success, buffer);
    }

    /// <summary>
    /// Écrit une trame bornée sur un flux en la préfixant de sa longueur sur 4 octets little-endian.
    /// </summary>
    /// <param name="stream">Flux connecté.</param>
    /// <param name="payload">Charge utile à écrire.</param>
    /// <param name="maxMessageBytes">Plafond maximal autorisé en octets.</param>
    /// <param name="cancellationToken">Jeton d'annulation et timeout.</param>
    public static async Task WriteFrameAsync(
        Stream stream,
        ReadOnlyMemory<byte> payload,
        int maxMessageBytes,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(maxMessageBytes, 0);

        if (payload.Length == 0 || payload.Length > maxMessageBytes)
        {
            throw new InvalidOperationException($"IPC payload size {payload.Length} exceeds valid range 1..{maxMessageBytes}.");
        }

        var frameBuffer = new byte[sizeof(int) + payload.Length];
        BinaryPrimitives.WriteInt32LittleEndian(frameBuffer.AsSpan(0, sizeof(int)), payload.Length);
        payload.Span.CopyTo(frameBuffer.AsSpan(sizeof(int)));

        await stream.WriteAsync(frameBuffer, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}
