using System.Text;
using Guardian.Scanner.FileTypes;

namespace Guardian.UnitTests.Scanner;

public class FileTypeDetectorTests
{
    [Theory]
    [InlineData(new byte[] { 0x4D, 0x5A, 0x90, 0x00 }, DetectedFileType.WindowsExecutable)]
    [InlineData(new byte[] { 0x25, 0x50, 0x44, 0x46, 0x2D }, DetectedFileType.Pdf)]
    [InlineData(new byte[] { 0x50, 0x4B, 0x03, 0x04 }, DetectedFileType.Zip)]
    [InlineData(new byte[] { 0x89, 0x50, 0x4E, 0x47, 0x0D }, DetectedFileType.Png)]
    [InlineData(new byte[] { 0xFF, 0xD8, 0xFF, 0xE0 }, DetectedFileType.Jpeg)]
    [InlineData(new byte[] { 0x01, 0x02, 0x03, 0x04 }, DetectedFileType.Unknown)]
    public void Detect_KnownHeaders_ReturnsExpectedType(byte[] header, DetectedFileType expected)
    {
        Assert.Equal(expected, FileTypeDetector.Detect(header));
    }

    [Fact]
    public void Detect_EmptyHeader_ReturnsUnknown()
    {
        Assert.Equal(DetectedFileType.Unknown, FileTypeDetector.Detect([]));
    }

    [Fact]
    public async Task DetectAsync_ExecutableRenamedAsPdf_IsDetectedAsDisguised()
    {
        string path = await WriteTempFileAsync(".pdf", [0x4D, 0x5A, 0x90, 0x00, 0x03]);
        try
        {
            var type = await FileTypeDetector.DetectAsync(path);

            Assert.Equal(DetectedFileType.WindowsExecutable, type);
            Assert.True(FileTypeDetector.IsDisguisedExecutable(path, type));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task DetectAsync_RealExecutable_IsNotDisguised()
    {
        string path = await WriteTempFileAsync(".exe", [0x4D, 0x5A, 0x90, 0x00, 0x03]);
        try
        {
            var type = await FileTypeDetector.DetectAsync(path);

            Assert.False(FileTypeDetector.IsDisguisedExecutable(path, type));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task DetectAsync_RealPdf_IsPdfAndNotDisguised()
    {
        string path = await WriteTempFileAsync(".pdf", Encoding.ASCII.GetBytes("%PDF-1.7\n"));
        try
        {
            var type = await FileTypeDetector.DetectAsync(path);

            Assert.Equal(DetectedFileType.Pdf, type);
            Assert.False(FileTypeDetector.IsDisguisedExecutable(path, type));
        }
        finally
        {
            File.Delete(path);
        }
    }

    private static async Task<string> WriteTempFileAsync(string extension, byte[] content)
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + extension);
        await File.WriteAllBytesAsync(path, content);
        return path;
    }
}
