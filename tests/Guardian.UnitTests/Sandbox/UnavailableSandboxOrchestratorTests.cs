using Guardian.Contracts.AI.Models;
using Guardian.Contracts.Sandbox;
using Guardian.Sandbox;

namespace Guardian.UnitTests.Sandbox;

public class UnavailableSandboxOrchestratorTests
{
    private sealed class FakeHyperVDetector : IHyperVDetector
    {
        private readonly HyperVState _state;

        public FakeHyperVDetector(HyperVState state) => _state = state;

        public HyperVState Detect() => _state;
    }

    private static UnavailableSandboxOrchestrator Create(HyperVState state) =>
        new(new FakeHyperVDetector(state));

    [Theory]
    [InlineData(HyperVState.NotWindows, SandboxUnavailableReason.UnsupportedPlatform)]
    [InlineData(HyperVState.NotInstalled, SandboxUnavailableReason.HyperVNotInstalled)]
    [InlineData(HyperVState.Installed, SandboxUnavailableReason.NotImplemented)]
    public async Task GetAvailabilityAsync_IsUnavailableWithExpectedReason(
        HyperVState state,
        SandboxUnavailableReason expected)
    {
        SandboxAvailability availability = await Create(state).GetAvailabilityAsync();

        Assert.False(availability.IsAvailable);
        Assert.Equal(expected, availability.Reason);
        Assert.Contains("indisponible", availability.Message);
    }

    [Fact]
    public async Task AnalyzeAsync_ReturnsUnavailableAndInconclusiveVerdict()
    {
        SandboxAnalysisResult result = await Create(HyperVState.NotInstalled).AnalyzeAsync(
            new SandboxAnalysisRequest { FilePath = @"C:\echantillon\inconnu.bin" });

        Assert.Equal(SandboxRunStatus.Unavailable, result.Status);
        Assert.Equal(ThreatVerdict.Inconclusive, result.Verdict);
        Assert.Contains("Analyse dynamique indisponible", result.Summary);
        Assert.Empty(result.Observations);
    }

    [Fact]
    public async Task AnalyzeAsync_NeverModifiesOrDeletesTheFile()
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".bin");
        await File.WriteAllTextAsync(path, "contenu");
        try
        {
            await Create(HyperVState.Installed).AnalyzeAsync(
                new SandboxAnalysisRequest { FilePath = path });

            Assert.True(File.Exists(path));
            Assert.Equal("contenu", await File.ReadAllTextAsync(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task AnalyzeAsync_NullRequest_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(
            () => Create(HyperVState.Installed).AnalyzeAsync(null!));
    }

    [Fact]
    public async Task AnalyzeAsync_BlankPath_Throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(
            () => Create(HyperVState.Installed).AnalyzeAsync(
                new SandboxAnalysisRequest { FilePath = "  " }));
    }

    [Fact]
    public async Task AnalyzeAsync_NonPositiveLimits_Throw()
    {
        var request = new SandboxAnalysisRequest
        {
            FilePath = "x.bin",
            Limits = new SandboxLimits { Timeout = TimeSpan.Zero }
        };

        await Assert.ThrowsAsync<ArgumentException>(
            () => Create(HyperVState.Installed).AnalyzeAsync(request));
    }

    [Fact]
    public async Task AnalyzeAsync_CanceledToken_Throws()
    {
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Create(HyperVState.Installed).AnalyzeAsync(
                new SandboxAnalysisRequest { FilePath = "x.bin" },
                cts.Token));
    }

    [Fact]
    public void DefaultLimits_DisableNetworkAndAreStrictlyPositive()
    {
        SandboxLimits limits = SandboxLimits.Default;

        Assert.Equal(SandboxNetworkMode.Disabled, limits.Network);
        Assert.True(limits.Timeout > TimeSpan.Zero);
        Assert.True(limits.MaxMemoryMegabytes > 0);
        Assert.True(limits.MaxProcesses > 0);
    }

    [Fact]
    public void Request_WithoutExplicitLimits_UsesDefaultsWithNetworkDisabled()
    {
        var request = new SandboxAnalysisRequest { FilePath = "x.bin" };

        Assert.Equal(SandboxNetworkMode.Disabled, request.Limits.Network);
    }

    [Fact]
    public void RegistryHyperVDetector_OnWindows_ReportsInstalledOrNot()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        HyperVState state = new RegistryHyperVDetector().Detect();

        Assert.NotEqual(HyperVState.NotWindows, state);
    }
}
