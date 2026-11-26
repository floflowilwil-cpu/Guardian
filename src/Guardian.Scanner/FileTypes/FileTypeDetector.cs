namespace Guardian.Scanner.FileTypes;

public enum DetectedFileType
{
    Unknown,
    WindowsExecutable,
    Elf,
    Pdf,
    Zip,
    OleCompound,   // anciens .doc / .xls / .ppt
    Rar,
    SevenZip,
    Png,
    Jpeg,
    Gif
}

/// <summary>
/// Identifie le type réel d'un fichier à partir de ses premiers octets,
/// sans se fier à son extension.
/// </summary>
public static class FileTypeDetector
{
    private const int HeaderLength = 16;

    private static readonly (byte[] Magic, DetectedFileType Type)[] Signatures =
    [
        (new byte[] { 0x4D, 0x5A }, DetectedFileType.WindowsExecutable),                         // "MZ"
        (new byte[] { 0x7F, 0x45, 0x4C, 0x46 }, DetectedFileType.Elf),                           // "\x7FELF"
        (new byte[] { 0x25, 0x50, 0x44, 0x46 }, DetectedFileType.Pdf),                           // "%PDF"
        (new byte[] { 0x50, 0x4B, 0x03, 0x04 }, DetectedFileType.Zip),                           // "PK.."
        (new byte[] { 0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1 }, DetectedFileType.OleCompound),
        (new byte[] { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07 }, DetectedFileType.Rar),               // "Rar!"
        (new byte[] { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C }, DetectedFileType.SevenZip),
        (new byte[] { 0x89, 0x50, 0x4E, 0x47 }, DetectedFileType.Png),
        (new byte[] { 0xFF, 0xD8, 0xFF }, DetectedFileType.Jpeg),
        (new byte[] { 0x47, 0x49, 0x46, 0x38 }, DetectedFileType.Gif)                            // "GIF8"
    ];

    private static readonly HashSet<string> ExecutableExtensions =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".drv", ".efi"
        };

    /// <summary>Identifie le type à partir d'un en-tête déjà lu.</summary>
    public static DetectedFileType Detect(ReadOnlySpan<byte> header)
    {
        foreach (var (magic, type) in Signatures)
        {
            if (header.StartsWith((ReadOnlySpan<byte>)magic))
            {
                return type;
            }
        }

        return DetectedFileType.Unknown;
    }

    /// <summary>Lit les premiers octets du fichier puis identifie son type.</summary>
    public static async Task<DetectedFileType> DetectAsync(
        string filePath,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);

        await using var stream = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite,
            bufferSize: 4096,
            useAsync: true);

        byte[] header = new byte[HeaderLength];
        int read = await stream.ReadAtLeastAsync(
            header, HeaderLength, throwOnEndOfStream: false, cancellationToken);

        return Detect(header.AsSpan(0, read));
    }

    /// <summary>
    /// Vrai si le contenu est un exécutable Windows mais que l'extension
    /// ne l'annonce pas (ex. "facture.pdf" qui est en réalité un .exe).
    /// </summary>
    public static bool IsDisguisedExecutable(string filePath, DetectedFileType detectedType)
    {
        return detectedType == DetectedFileType.WindowsExecutable
            && !ExecutableExtensions.Contains(Path.GetExtension(filePath));
    }
}
