using Guardian.Service.Configuration;

namespace Guardian.UnitTests.Service;

public class GuardianServiceOptionsValidatorTests
{
    private readonly GuardianServiceOptionsValidator _validator = new();

    [Fact]
    public void Validate_DefaultOptions_ShouldSucceed()
    {
        var result = _validator.Validate(name: null, new GuardianServiceOptions());

        Assert.True(result.Succeeded);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(121)]
    public void Validate_InvalidShutdownTimeout_ShouldFail(int timeoutSeconds)
    {
        var options = new GuardianServiceOptions { ShutdownTimeoutSeconds = timeoutSeconds };

        var result = _validator.Validate(name: null, options);

        Assert.True(result.Failed);
    }

    [Fact]
    public void Validate_StaleThresholdNotGreaterThanHeartbeatInterval_ShouldFail()
    {
        var options = new GuardianServiceOptions
        {
            HeartbeatIntervalSeconds = 10,
            HeartbeatStaleThresholdSeconds = 10
        };

        var result = _validator.Validate(name: null, options);

        Assert.True(result.Failed);
        Assert.Contains(result.Failures, f => f.Contains("HeartbeatStaleThresholdSeconds", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(512)]
    [InlineData(2_000_000)]
    public void Validate_InvalidIpcMaxMessageBytes_ShouldFail(int maxBytes)
    {
        var options = new GuardianServiceOptions { IpcMaxMessageBytes = maxBytes };

        var result = _validator.Validate(name: null, options);

        Assert.True(result.Failed);
    }

    [Fact]
    public void Validate_EmptyServiceName_ShouldFail()
    {
        var options = new GuardianServiceOptions { ServiceName = "   " };

        var result = _validator.Validate(name: null, options);

        Assert.True(result.Failed);
    }
}
