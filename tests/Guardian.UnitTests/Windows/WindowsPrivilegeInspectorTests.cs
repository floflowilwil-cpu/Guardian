using Guardian.Windows.Environment;

namespace Guardian.UnitTests.Windows;

public class WindowsPrivilegeInspectorTests
{
    [Fact]
    public void GetStandardPaths_WithCustomRoots_ShouldMatchSpecificationSection13_1Layout()
    {
        var inspector = new WindowsPrivilegeInspector();
        var root = Path.Combine(Path.GetTempPath(), $"guardian-paths-test-{Guid.NewGuid():N}");
        var programData = Path.Combine(root, "ProgramData");
        var programFiles = Path.Combine(root, "ProgramFiles");
        var localAppData = Path.Combine(root, "LocalAppData");

        var paths = inspector.GetStandardPaths(programData, programFiles, localAppData);

        Assert.Equal(Path.Combine(programFiles, "Guardian"), paths.BinariesDirectory);
        Assert.Equal(Path.Combine(programData, "Guardian", "config"), paths.ConfigDirectory);
        Assert.Equal(Path.Combine(programData, "Guardian", "data"), paths.DataDirectory);
        Assert.Equal(Path.Combine(programData, "Guardian", "data", "guardian.db"), paths.DatabaseFilePath);
        Assert.Equal(Path.Combine(programData, "Guardian", "quarantine"), paths.QuarantineDirectory);
        Assert.Equal(Path.Combine(programData, "Guardian", "signatures"), paths.SignaturesDirectory);
        Assert.Equal(Path.Combine(programData, "Guardian", "models"), paths.ModelsDirectory);
        Assert.Equal(Path.Combine(programData, "Guardian", "logs"), paths.LogsDirectory);
        Assert.Equal(Path.Combine(programData, "Guardian", "backup"), paths.BackupDirectory);
        Assert.Equal(Path.Combine(localAppData, "Guardian"), paths.UiPreferencesDirectory);
    }
}
