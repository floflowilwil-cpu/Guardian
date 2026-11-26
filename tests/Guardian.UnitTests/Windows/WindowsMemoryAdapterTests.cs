using Guardian.Contracts.Common;
using Guardian.Contracts.Memory;
using Guardian.Windows.Memory;

namespace Guardian.UnitTests.Windows;

public class WindowsMemoryAdapterTests
{
    [Theory]
    [InlineData("lsass", true)]
    [InlineData("LSASS.EXE", true)]
    [InlineData("csrss", true)]
    [InlineData("wininit.exe", true)]
    [InlineData("notepad", false)]
    [InlineData("Guardian.Service.exe", false)]
    public void IsProtectedProcessName_ShouldStrictlyProtectCredentialProcesses(string processName, bool expectedProtected)
    {
        Assert.Equal(expectedProtected, WindowsMemoryAdapter.IsProtectedProcessName(processName));
    }

    [Fact]
    public void ClassifyRegionProtection_ShouldClassifyPrivateRwxAndExecutableRegionsCorrectly()
    {
        const uint memCommit = 0x1000;
        const uint memReserve = 0x2000;
        const uint memPrivate = 0x20000;
        const uint memImage = 0x1000000;
        const uint pageExecuteReadWrite = 0x40;
        const uint pageExecuteRead = 0x20;
        const uint pageReadWrite = 0x04;

        var rwx = WindowsMemoryAdapter.ClassifyRegionProtection(memCommit, memPrivate, pageExecuteReadWrite);
        Assert.NotNull(rwx);
        Assert.Equal(MemorySignalKind.ReadWriteExecuteRegion, rwx.Value.Kind);
        Assert.Equal(EventSeverity.High, rwx.Value.Severity);

        var rx = WindowsMemoryAdapter.ClassifyRegionProtection(memCommit, memPrivate, pageExecuteRead);
        Assert.NotNull(rx);
        Assert.Equal(MemorySignalKind.PrivateExecutableRegion, rx.Value.Kind);
        Assert.Equal(EventSeverity.Medium, rx.Value.Severity);

        Assert.Null(WindowsMemoryAdapter.ClassifyRegionProtection(memCommit, memImage, pageExecuteReadWrite));
        Assert.Null(WindowsMemoryAdapter.ClassifyRegionProtection(memCommit, memPrivate, pageReadWrite));
        Assert.Null(WindowsMemoryAdapter.ClassifyRegionProtection(memReserve, memPrivate, pageExecuteReadWrite));
    }
}
