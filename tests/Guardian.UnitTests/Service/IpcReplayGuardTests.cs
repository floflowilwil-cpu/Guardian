using Guardian.Contracts.Ipc;
using Guardian.Service.Configuration;
using Guardian.Service.Ipc;
using Microsoft.Extensions.Options;

namespace Guardian.UnitTests.Service;

public class IpcReplayGuardTests
{
    [Fact]
    public void TryValidate_ShouldAcceptFreshRequestAndRejectReplayAndStaleTimestamp()
    {
        var timeProvider = new TestTimeProvider();
        var options = Options.Create(new GuardianServiceOptions { IpcReplayWindowSeconds = 60 });
        var guard = new IpcReplayGuard(options, timeProvider);

        var request = new IpcRequest(
            ProtocolVersion: IpcProtocolConstants.ProtocolVersion,
            RequestId: "req-1",
            Command: IpcCommandType.Ping,
            TimestampUtc: timeProvider.GetUtcNow(),
            Nonce: "nonce-1");

        Assert.True(guard.TryValidate(request, out var reason1));
        Assert.Null(reason1);

        Assert.False(guard.TryValidate(request, out var replayReason));
        Assert.NotNull(replayReason);

        var stalePastRequest = request with
        {
            RequestId = "req-stale-past",
            TimestampUtc = timeProvider.GetUtcNow().AddSeconds(-120)
        };
        Assert.False(guard.TryValidate(stalePastRequest, out var pastReason));
        Assert.NotNull(pastReason);

        var staleFutureRequest = request with
        {
            RequestId = "req-stale-future",
            TimestampUtc = timeProvider.GetUtcNow().AddSeconds(120)
        };
        Assert.False(guard.TryValidate(staleFutureRequest, out var futureReason));
        Assert.NotNull(futureReason);
    }
}
