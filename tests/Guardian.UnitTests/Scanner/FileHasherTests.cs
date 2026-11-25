using Guardian.Scanner.Hashing;

namespace Guardian.UnitTests.Scanner;

public class FileHasherTests
{
    [Fact]
    public async Task ComputeSha256Async_KnownContent_ReturnsExpectedHash()
    {
        string path = Path.GetTempFileName();
        try
        {
            await File.WriteAllTextAsync(path, "abc");

            string hash = await FileHasher.ComputeSha256Async(path);

            Assert.Equal(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                hash);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ComputeSha256Async_EmptyFile_ReturnsEmptyHash()
    {
        string path = Path.GetTempFileName();
        try
        {
            string hash = await FileHasher.ComputeSha256Async(path);

            Assert.Equal(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                hash);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task ComputeSha256Async_MissingFile_Throws()
    {
        // Le dossier existe (temp), mais le fichier n'existe pas.
        string missingPath = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".bin");

        await Assert.ThrowsAsync<FileNotFoundException>(
            () => FileHasher.ComputeSha256Async(missingPath));
    }
}
