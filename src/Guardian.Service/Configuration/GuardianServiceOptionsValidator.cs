using Microsoft.Extensions.Options;

namespace Guardian.Service.Configuration;

/// <summary>
/// Valide les bornes opérationnelles et de sécurité de <see cref="GuardianServiceOptions"/> dès le démarrage.
/// </summary>
public sealed class GuardianServiceOptionsValidator : IValidateOptions<GuardianServiceOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, GuardianServiceOptions options)
    {
        if (options is null)
        {
            return ValidateOptionsResult.Fail("GuardianServiceOptions cannot be null.");
        }

        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(options.ServiceName))
        {
            errors.Add("ServiceName must not be empty.");
        }

        if (options.ShutdownTimeoutSeconds is < 5 or > 120)
        {
            errors.Add("ShutdownTimeoutSeconds must be between 5 and 120 seconds.");
        }

        if (options.HeartbeatIntervalSeconds is < 1 or > 60)
        {
            errors.Add("HeartbeatIntervalSeconds must be between 1 and 60 seconds.");
        }

        if (options.HeartbeatStaleThresholdSeconds <= options.HeartbeatIntervalSeconds)
        {
            errors.Add("HeartbeatStaleThresholdSeconds must be strictly greater than HeartbeatIntervalSeconds.");
        }

        if (options.WatchdogCheckIntervalSeconds is < 1 or > 120)
        {
            errors.Add("WatchdogCheckIntervalSeconds must be between 1 and 120 seconds.");
        }

        if (options.WatchdogMaxRestartsInWindow is < 1 or > 10)
        {
            errors.Add("WatchdogMaxRestartsInWindow must be between 1 and 10.");
        }

        if (options.WatchdogRestartWindowMinutes is < 1 or > 60)
        {
            errors.Add("WatchdogRestartWindowMinutes must be between 1 and 60 minutes.");
        }

        if (options.IntegrityCheckIntervalMinutes is < 1 or > 1440)
        {
            errors.Add("IntegrityCheckIntervalMinutes must be between 1 and 1440 minutes.");
        }

        if (string.IsNullOrWhiteSpace(options.IpcPipeName))
        {
            errors.Add("IpcPipeName must not be empty.");
        }

        if (options.IpcMaxConcurrentConnections is < 1 or > 32)
        {
            errors.Add("IpcMaxConcurrentConnections must be between 1 and 32.");
        }

        if (options.IpcReadTimeoutSeconds is < 1 or > 60)
        {
            errors.Add("IpcReadTimeoutSeconds must be between 1 and 60 seconds.");
        }

        if (options.IpcMaxMessageBytes is < 1024 or > 1_048_576)
        {
            errors.Add("IpcMaxMessageBytes must be between 1024 and 1048576 bytes.");
        }

        if (options.IpcReplayWindowSeconds is < 5 or > 600)
        {
            errors.Add("IpcReplayWindowSeconds must be between 5 and 600 seconds.");
        }

        if (options.RequiredComponents is null || options.RequiredComponents.Count == 0 ||
            options.RequiredComponents.Any(string.IsNullOrWhiteSpace))
        {
            errors.Add("RequiredComponents must contain at least one valid component name.");
        }

        return errors.Count > 0
            ? ValidateOptionsResult.Fail(errors)
            : ValidateOptionsResult.Success;
    }
}
