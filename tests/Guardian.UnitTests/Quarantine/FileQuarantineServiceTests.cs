using Guardian.Contracts.Common;
using Guardian.Contracts.Quarantine;
using Guardian.Quarantine;

namespace Guardian.UnitTests.Quarantine;

public class FileQuarantineServiceTests
{
    private sealed class ReversingKeyProtector : IKeyProtector
    {
        public byte[] Protect(byte[] data)
        {
            byte[] copy = (byte[])data.Clone();
            Array.Reverse(copy);
            return copy;
        }

        public byte[] Unprotect(byte[] protectedData) => Protect(protectedData);
    }

    private sealed class ListJournal : IQuarantineJournal
    {
        public List<AuditEventDto> Entries { get; } = [];

        public void Write(AuditEventDto entry) => Entries.Add(entry);
    }

    private sealed class QuarantineTestEnv : IDisposable
    {
        private readonly DirectoryInfo _temp = Directory.CreateTempSubdirectory("guardian-quarantine-");

        public QuarantineTestEnv()
        {
            WorkDir = Path.Combine(_temp.FullName, "work");
            QuarantineDir = Path.Combine(_temp.FullName, "quarantine");
            Directory.CreateDirectory(WorkDir);

            Journal = new ListJournal();
            Service = new FileQuarantineService(QuarantineDir, new ReversingKeyProtector(), Journal);
        }

        public string WorkDir { get; }

        public string QuarantineDir { get; }

        public ListJournal Journal { get; }

        public FileQuarantineService Service { get; }

        public async Task<string> CreateFileAsync(string name, byte[] content)
        {
            string path = Path.Combine(WorkDir, name);
            await File.WriteAllBytesAsync(path, content);
            return path;
        }

        public Task<QuarantineItem> QuarantineAsync(string path) =>
            Service.QuarantineAsync(new QuarantineRequest
            {
                FilePath = path,
                Reason = "Signature connue",
                DetectionEngine = "Scanner.Signature",
                ThreatName = "Test.Malware.Sample"
            });

        public void Dispose() => _temp.Delete(true);
    }

    [Fact]
    public async Task QuarantineAsync_RemovesOriginalAndEncryptsContent()
    {
        using var env = new QuarantineTestEnv();
        byte[] content = "contenu-secret-a-ne-pas-retrouver"u8.ToArray();
        string path = await env.CreateFileAsync("malware.bin", content);

        QuarantineItem item = await env.QuarantineAsync(path);

        Assert.False(File.Exists(path));
        Assert.Equal(content.Length, item.SizeBytes);

        string blobPath = Directory.GetFiles(env.QuarantineDir, "*.gqf").Single();
        byte[] blob = await File.ReadAllBytesAsync(blobPath);
        Assert.Equal(-1, blob.AsSpan().IndexOf((ReadOnlySpan<byte>)content));
    }

    [Fact]
    public async Task RestoreAsync_RoundTrip_RestoresOriginalContentAndEmptiesQuarantine()
    {
        using var env = new QuarantineTestEnv();
        byte[] content = "contenu a restaurer"u8.ToArray();
        string path = await env.CreateFileAsync("fichier.bin", content);
        QuarantineItem item = await env.QuarantineAsync(path);

        string restored = await env.Service.RestoreAsync(item.Id);

        Assert.Equal(path, restored);
        Assert.Equal(content, await File.ReadAllBytesAsync(restored));
        Assert.Empty(await env.Service.ListAsync());
    }

    [Fact]
    public async Task RestoreAsync_ExistingDestination_RefusesToOverwrite()
    {
        using var env = new QuarantineTestEnv();
        string path = await env.CreateFileAsync("fichier.bin", "original"u8.ToArray());
        QuarantineItem item = await env.QuarantineAsync(path);

        await File.WriteAllBytesAsync(path, "nouveau"u8.ToArray());

        await Assert.ThrowsAsync<IOException>(() => env.Service.RestoreAsync(item.Id));

        Assert.Equal("nouveau"u8.ToArray(), await File.ReadAllBytesAsync(path));
        Assert.Single(await env.Service.ListAsync());
    }

    [Fact]
    public async Task RestoreAsync_TamperedData_ThrowsInvalidData()
    {
        using var env = new QuarantineTestEnv();
        string path = await env.CreateFileAsync("fichier.bin", "donnees importantes"u8.ToArray());
        QuarantineItem item = await env.QuarantineAsync(path);

        string blobPath = Directory.GetFiles(env.QuarantineDir, "*.gqf").Single();
        byte[] blob = await File.ReadAllBytesAsync(blobPath);
        blob[^1] ^= 0xFF;
        await File.WriteAllBytesAsync(blobPath, blob);

        await Assert.ThrowsAsync<InvalidDataException>(() => env.Service.RestoreAsync(item.Id));

        Assert.False(File.Exists(path));
    }

    [Fact]
    public async Task ListAsync_ReturnsQuarantinedItemWithMetadata()
    {
        using var env = new QuarantineTestEnv();
        string path = await env.CreateFileAsync("fichier.bin", "abc"u8.ToArray());
        QuarantineItem item = await env.QuarantineAsync(path);

        IReadOnlyList<QuarantineItem> items = await env.Service.ListAsync();

        QuarantineItem listed = Assert.Single(items);
        Assert.Equal(item.Id, listed.Id);
        Assert.Equal(path, listed.OriginalPath);
        Assert.Equal("Signature connue", listed.Reason);
        Assert.Equal(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            listed.Sha256);
    }

    [Fact]
    public async Task DeleteAsync_RemovesItemPermanently()
    {
        using var env = new QuarantineTestEnv();
        string path = await env.CreateFileAsync("fichier.bin", "abc"u8.ToArray());
        QuarantineItem item = await env.QuarantineAsync(path);

        await env.Service.DeleteAsync(item.Id);

        Assert.Empty(await env.Service.ListAsync());
        Assert.Empty(Directory.GetFiles(env.QuarantineDir));
        await Assert.ThrowsAsync<FileNotFoundException>(() => env.Service.RestoreAsync(item.Id));
    }

    [Fact]
    public async Task QuarantineAsync_MissingFile_Throws()
    {
        using var env = new QuarantineTestEnv();
        string missing = Path.Combine(env.WorkDir, "inexistant.bin");

        await Assert.ThrowsAsync<FileNotFoundException>(() => env.QuarantineAsync(missing));
    }

    [Fact]
    public async Task Actions_AreJournaledWithoutLeakingFilePath()
    {
        using var env = new QuarantineTestEnv();
        string path = await env.CreateFileAsync("fichier.bin", "abc"u8.ToArray());

        QuarantineItem item = await env.QuarantineAsync(path);
        await env.Service.RestoreAsync(item.Id);

        Assert.Contains(env.Journal.Entries, e => e.Action == "Quarantine" && e.Succeeded);
        Assert.Contains(env.Journal.Entries, e => e.Action == "Restore" && e.Succeeded);
        Assert.All(env.Journal.Entries, e => Assert.DoesNotContain(path, e.Details ?? string.Empty));
    }

    [Fact]
    public void DpapiKeyProtector_RoundTrip_OnWindows()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        var protector = new DpapiKeyProtector();
        byte[] key = [1, 2, 3, 4, 5, 6, 7, 8];

        byte[] wrapped = protector.Protect(key);

        Assert.NotEqual(key, wrapped);
        Assert.Equal(key, protector.Unprotect(wrapped));
    }
}