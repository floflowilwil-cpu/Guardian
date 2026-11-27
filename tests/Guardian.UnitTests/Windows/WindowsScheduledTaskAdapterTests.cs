using System.Text;
using Guardian.Contracts.Common;
using Guardian.Contracts.System;
using Guardian.Windows.Tasks;

namespace Guardian.UnitTests.Windows;

public class WindowsScheduledTaskAdapterTests
{
    [Fact]
    public async Task GetScheduledTasksAsync_ShouldParseValidExecTasksAndSkipMalformedOrOversizedFiles()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"guardian-tasks-{Guid.NewGuid():N}");
        var subDir = Path.Combine(tempDir, "Vendor");
        Directory.CreateDirectory(subDir);

        try
        {
            const string validTaskXml = """
                <?xml version="1.0" encoding="UTF-16"?>
                <Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
                  <Actions Context="Author">
                    <Exec>
                      <Command>C:\Program Files\Example\Updater.exe</Command>
                      <Arguments>--silent --check</Arguments>
                    </Exec>
                  </Actions>
                </Task>
                """;
            await File.WriteAllTextAsync(Path.Combine(subDir, "ExampleUpdater"), validTaskXml, Encoding.Unicode);

            const string brokenXml = "<Task><Actions><Exec><Command>broken";
            await File.WriteAllTextAsync(Path.Combine(tempDir, "MalformedTask"), brokenXml);

            // Fichier dépassant la limite autorisée -> ignoré sans exception.
            await File.WriteAllBytesAsync(
                Path.Combine(tempDir, "OversizedTask"),
                new byte[WindowsScheduledTaskAdapter.DefaultMaxTaskFileBytes + 128]);

            var adapter = new WindowsScheduledTaskAdapter(tasksRootOverride: tempDir);
            var tasks = await adapter.GetScheduledTasksAsync();

            var entry = Assert.Single(tasks);
            Assert.Equal("ExampleUpdater", entry.Name);
            Assert.Equal(PersistenceEntryKind.ScheduledTask, entry.Kind);
            Assert.Equal(@"\Vendor\ExampleUpdater", entry.Location);
            Assert.Equal(@"C:\Program Files\Example\Updater.exe --silent --check", entry.CommandOrPath);
            Assert.Equal("Machine", entry.Scope);
            Assert.Equal(FeatureAvailabilityStatus.Available, entry.AccessStatus);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Fact]
    public async Task GetScheduledTasksAsync_WhenRootDoesNotExist_ShouldReturnEmptyList()
    {
        var missing = Path.Combine(Path.GetTempPath(), $"guardian-missing-tasks-{Guid.NewGuid():N}");
        var adapter = new WindowsScheduledTaskAdapter(tasksRootOverride: missing);

        var tasks = await adapter.GetScheduledTasksAsync();

        Assert.Empty(tasks);
    }
}
