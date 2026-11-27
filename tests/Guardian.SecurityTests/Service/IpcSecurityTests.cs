using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using Guardian.Contracts.Ipc;
using Guardian.Service.Configuration;
using Guardian.Service.Hosting;
using Guardian.Service.Ipc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Guardian.SecurityTests.Service;

public class IpcSecurityTests
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task IpcServer_ShouldRejectOversizedInvalidReplayAndNeverLeakSensitivePayloadInLogs()
    {
        var pipeName = $"Guardian.Sec.Ipc.{Guid.NewGuid():N}";
        var missingDataDir = Path.Combine(Path.GetTempPath(), $"guardian-sec-none-{Guid.NewGuid():N}");
        var logCapture = new CapturingLoggerProvider();

        var builder = Host.CreateApplicationBuilder();
        builder.Logging.ClearProviders();
        builder.Logging.AddProvider(logCapture);
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["GuardianService:IpcPipeName"] = pipeName,
            ["GuardianService:HeartbeatIntervalSeconds"] = "5",
            ["GuardianService:HeartbeatStaleThresholdSeconds"] = "20",
            ["GuardianService:ShutdownTimeoutSeconds"] = "5",
            ["GuardianService:DataDirectoryOverride"] = missingDataDir
        });
        builder.Services.AddGuardianServiceCore(builder.Configuration);

        using var host = builder.Build();
        await host.StartAsync();

        try
        {
            var oversizedResp = await SendRawFrameLengthAsync(pipeName, 10_000_000);
            Assert.NotNull(oversizedResp);
            Assert.False(oversizedResp.Success);
            Assert.Equal(IpcErrorCode.PayloadTooLarge, oversizedResp.ErrorCode);

            var negativeResp = await SendRawFrameLengthAsync(pipeName, -5);
            Assert.NotNull(negativeResp);
            Assert.False(negativeResp.Success);
            Assert.Equal(IpcErrorCode.InvalidRequest, negativeResp.ErrorCode);

            var malformedResp = await SendRawPayloadAsync(pipeName, Encoding.UTF8.GetBytes("{corrupted-json!!!"));
            Assert.NotNull(malformedResp);
            Assert.False(malformedResp.Success);
            Assert.Equal(IpcErrorCode.InvalidRequest, malformedResp.ErrorCode);

            var client = new NamedPipeIpcClient(pipeName, timeout: TimeSpan.FromSeconds(5));

            var badVersionResp = await client.SendAsync(new IpcRequest(
                ProtocolVersion: "9.9",
                RequestId: Guid.NewGuid().ToString("N"),
                Command: IpcCommandType.Ping,
                TimestampUtc: DateTimeOffset.UtcNow,
                Nonce: Guid.NewGuid().ToString("N")));
            Assert.False(badVersionResp.Success);
            Assert.Equal(IpcErrorCode.InvalidProtocolVersion, badVersionResp.ErrorCode);

            const string sensitiveCanary = "CANARY-SENSITIVE-PAYLOAD-9941";
            var replayableRequest = new IpcRequest(
                ProtocolVersion: IpcProtocolConstants.ProtocolVersion,
                RequestId: "fixed-replay-id",
                Command: IpcCommandType.GetComponentHealth,
                TimestampUtc: DateTimeOffset.UtcNow,
                Nonce: "fixed-nonce",
                PayloadJson: JsonSerializer.Serialize(sensitiveCanary, JsonOptions));

            var first = await client.SendAsync(replayableRequest);
            Assert.True(first.Success);

            var second = await client.SendAsync(replayableRequest);
            Assert.False(second.Success);
            Assert.Equal(IpcErrorCode.ReplayDetected, second.ErrorCode);

            var pingAfterAttacks = await client.PingAsync();
            Assert.True(pingAfterAttacks.Success);

            Assert.DoesNotContain(logCapture.Messages, msg => msg.Contains(sensitiveCanary, StringComparison.Ordinal));
        }
        finally
        {
            await host.StopAsync();
        }
    }

    private static async Task<IpcResponse?> SendRawFrameLengthAsync(string pipeName, int declaredLength)
    {
        await using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await client.ConnectAsync(5000);

        var header = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(header, declaredLength);
        await client.WriteAsync(header);
        await client.FlushAsync();

        var frame = await IpcFraming.ReadFrameAsync(client, IpcProtocolConstants.DefaultMaxMessageBytes);
        return frame.Status == FrameReadStatus.Success && frame.Payload is not null
            ? JsonSerializer.Deserialize<IpcResponse>(frame.Payload, JsonOptions)
            : null;
    }

    private static async Task<IpcResponse?> SendRawPayloadAsync(string pipeName, byte[] rawPayload)
    {
        await using var client = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        await client.ConnectAsync(5000);

        await IpcFraming.WriteFrameAsync(client, rawPayload, IpcProtocolConstants.DefaultMaxMessageBytes);
        var frame = await IpcFraming.ReadFrameAsync(client, IpcProtocolConstants.DefaultMaxMessageBytes);
        return frame.Status == FrameReadStatus.Success && frame.Payload is not null
            ? JsonSerializer.Deserialize<IpcResponse>(frame.Payload, JsonOptions)
            : null;
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<string> Messages { get; } = new();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(Messages);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(ConcurrentQueue<string> messages) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                messages.Enqueue(formatter(state, exception));
            }
        }
    }
}
