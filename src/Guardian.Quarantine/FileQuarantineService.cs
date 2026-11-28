using System.Security.Cryptography;
using System.Text.Json;
using Guardian.Contracts.Common;
using Guardian.Contracts.Quarantine;

namespace Guardian.Quarantine;

/// <summary>
/// Quarantaine sur disque : chiffrement AES-256-GCM, clé par fichier protégée par
/// <see cref="IKeyProtector"/>, vérification d'intégrité avant restauration.
/// </summary>
public sealed class FileQuarantineService : IQuarantineService
{
    /// <summary>Taille maximale d'un fichier (le chiffrement se fait en mémoire).</summary>
    public const long MaxFileSizeBytes = 256L * 1024 * 1024;

    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const string DataExtension = ".gqf";
    private const string MetaSuffix = ".meta.json";
    private const string Actor = "Guardian.Quarantine";
    private const string Category = "Quarantine";

    private readonly string _root;
    private readonly IKeyProtector _keyProtector;
    private readonly IQuarantineJournal _journal;

    public FileQuarantineService(
        string rootDirectory,
        IKeyProtector keyProtector,
        IQuarantineJournal journal)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(rootDirectory);
        ArgumentNullException.ThrowIfNull(keyProtector);
        ArgumentNullException.ThrowIfNull(journal);

        _root = Path.GetFullPath(rootDirectory);
        _keyProtector = keyProtector;
        _journal = journal;
        Directory.CreateDirectory(_root);
    }

    /// <summary>Dossier par défaut : %ProgramData%\Guardian\quarantine.</summary>
    public static string DefaultRoot => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Guardian",
        "quarantine");

    public async Task<QuarantineItem> QuarantineAsync(
        QuarantineRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.FilePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Reason);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.DetectionEngine);

        string source = Path.GetFullPath(request.FilePath);
        var info = new FileInfo(source);

        if (!info.Exists)
        {
            throw new FileNotFoundException("Fichier à mettre en quarantaine introuvable.", source);
        }

        if (info.Length > MaxFileSizeBytes)
        {
            throw new InvalidOperationException("Fichier trop volumineux pour la quarantaine.");
        }

        Guid id = Guid.NewGuid();
        byte[] plain = await File.ReadAllBytesAsync(source, cancellationToken);
        byte[] key = RandomNumberGenerator.GetBytes(KeySize);

        try
        {
            string sha256 = ComputeSha256(plain);
            byte[] blob = Encrypt(plain, key, id);

            var item = new QuarantineItem
            {
                Id = id,
                OriginalPath = source,
                Sha256 = sha256,
                SizeBytes = plain.Length,
                QuarantinedAtUtc = DateTime.UtcNow,
                Reason = request.Reason,
                DetectionEngine = request.DetectionEngine,
                ThreatName = request.ThreatName
            };

            var stored = new StoredMetadata
            {
                Item = item,
                WrappedKey = Convert.ToBase64String(_keyProtector.Protect(key))
            };

            string dataPath = DataPath(id);
            string metaPath = MetaPath(id);

            try
            {
                await File.WriteAllBytesAsync(dataPath, blob, cancellationToken);
                await File.WriteAllTextAsync(metaPath, JsonSerializer.Serialize(stored), cancellationToken);
                File.Delete(source);
            }
            catch
            {
                TryDelete(dataPath);
                TryDelete(metaPath);
                WriteAudit("Quarantine", id, false, "Échec de la mise en quarantaine.");
                throw;
            }

            WriteAudit("Quarantine", id, true, $"sha256={sha256}; engine={request.DetectionEngine}");
            return item;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    public async Task<IReadOnlyList<QuarantineItem>> ListAsync(CancellationToken cancellationToken = default)
    {
        var items = new List<QuarantineItem>();

        foreach (string metaPath in Directory.EnumerateFiles(_root, "*" + MetaSuffix))
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                string json = await File.ReadAllTextAsync(metaPath, cancellationToken);
                StoredMetadata? stored = JsonSerializer.Deserialize<StoredMetadata>(json);

                if (stored is not null)
                {
                    items.Add(stored.Item);
                }
            }
            catch (JsonException)
            {
                // Métadonnées illisibles : l'élément est ignoré dans la liste.
            }
        }

        return items.OrderByDescending(i => i.QuarantinedAtUtc).ToList();
    }

    public async Task<string> RestoreAsync(
        Guid id,
        string? destinationPath = null,
        CancellationToken cancellationToken = default)
    {
        StoredMetadata stored = await ReadMetadataAsync(id, cancellationToken);

        string destination = Path.GetFullPath(
            string.IsNullOrWhiteSpace(destinationPath) ? stored.Item.OriginalPath : destinationPath);

        if (File.Exists(destination) || Directory.Exists(destination))
        {
            WriteAudit("Restore", id, false, "Destination existante : restauration refusée.");
            throw new IOException("La destination existe déjà : restauration refusée pour ne rien écraser.");
        }

        string? directory = Path.GetDirectoryName(destination);
        if (string.IsNullOrEmpty(directory))
        {
            throw new ArgumentException("Destination de restauration invalide.", nameof(destinationPath));
        }

        byte[] blob = await File.ReadAllBytesAsync(DataPath(id), cancellationToken);
        byte[] plain;

        try
        {
            plain = Decrypt(stored, blob);
        }
        catch (InvalidDataException)
        {
            WriteAudit("Restore", id, false, "Intégrité invalide : données altérées.");
            throw;
        }

        try
        {
            if (!string.Equals(ComputeSha256(plain), stored.Item.Sha256, StringComparison.OrdinalIgnoreCase))
            {
                WriteAudit("Restore", id, false, "Intégrité invalide : empreinte différente.");
                throw new InvalidDataException("L'empreinte du fichier restauré ne correspond pas.");
            }

            Directory.CreateDirectory(directory);

            await using (var output = new FileStream(
                destination, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                await output.WriteAsync(plain, cancellationToken);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }

        TryDelete(DataPath(id));
        TryDelete(MetaPath(id));
        WriteAudit("Restore", id, true, $"sha256={stored.Item.Sha256}");
        return destination;
    }

    public async Task DeleteAsync(Guid id, CancellationToken cancellationToken = default)
    {
        await ReadMetadataAsync(id, cancellationToken);

        TryDelete(DataPath(id));
        TryDelete(MetaPath(id));
        WriteAudit("Delete", id, true, null);
    }

    private async Task<StoredMetadata> ReadMetadataAsync(Guid id, CancellationToken cancellationToken)
    {
        string metaPath = MetaPath(id);

        if (!File.Exists(metaPath) || !File.Exists(DataPath(id)))
        {
            throw new FileNotFoundException($"Élément de quarantaine introuvable : {id}.");
        }

        string json = await File.ReadAllTextAsync(metaPath, cancellationToken);

        return JsonSerializer.Deserialize<StoredMetadata>(json)
            ?? throw new InvalidDataException("Métadonnées de quarantaine invalides.");
    }

    private static byte[] Encrypt(byte[] plain, byte[] key, Guid id)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] blob = new byte[NonceSize + TagSize + plain.Length];

        nonce.CopyTo(blob, 0);

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(
            nonce,
            plain,
            blob.AsSpan(NonceSize + TagSize),
            blob.AsSpan(NonceSize, TagSize),
            id.ToByteArray());

        return blob;
    }

    private byte[] Decrypt(StoredMetadata stored, byte[] blob)
    {
        if (blob.Length < NonceSize + TagSize)
        {
            throw new InvalidDataException("Fichier de quarantaine invalide.");
        }

        byte[]? key = null;

        try
        {
            key = _keyProtector.Unprotect(Convert.FromBase64String(stored.WrappedKey));

            byte[] plain = new byte[blob.Length - NonceSize - TagSize];
            ReadOnlySpan<byte> span = blob;

            using var aes = new AesGcm(key, TagSize);
            aes.Decrypt(
                span[..NonceSize],
                span[(NonceSize + TagSize)..],
                span.Slice(NonceSize, TagSize),
                plain,
                stored.Item.Id.ToByteArray());

            return plain;
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            throw new InvalidDataException("Données de quarantaine corrompues ou altérées.", ex);
        }
        finally
        {
            if (key is not null)
            {
                CryptographicOperations.ZeroMemory(key);
            }
        }
    }

    private static string ComputeSha256(byte[] data) =>
        Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    private string DataPath(Guid id) => Path.Combine(_root, id.ToString("N") + DataExtension);

    private string MetaPath(Guid id) => Path.Combine(_root, id.ToString("N") + MetaSuffix);

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
            // Nettoyage au mieux : l'erreur principale est celle à remonter.
        }
        catch (UnauthorizedAccessException)
        {
            // Idem.
        }
    }

    private void WriteAudit(string action, Guid id, bool succeeded, string? details)
    {
        _journal.Write(new AuditEventDto(
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            Category,
            action,
            Actor,
            id.ToString(),
            succeeded,
            details));
    }

    internal sealed record StoredMetadata
    {
        public required QuarantineItem Item { get; init; }
        public required string WrappedKey { get; init; }
    }
}