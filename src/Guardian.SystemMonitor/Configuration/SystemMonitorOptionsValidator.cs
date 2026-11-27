using Microsoft.Extensions.Options;

namespace Guardian.SystemMonitor.Configuration;

/// <summary>
/// Validateur strict des bornes de configuration de <see cref="SystemMonitorOptions"/>.
/// </summary>
public sealed class SystemMonitorOptionsValidator : IValidateOptions<SystemMonitorOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, SystemMonitorOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var errors = new List<string>();

        if (options.PollingIntervalSeconds is < 1 or > 300)
        {
            errors.Add("PollingIntervalSeconds must be between 1 and 300.");
        }

        if (options.MemoryScanIntervalSeconds is < 5 or > 3600)
        {
            errors.Add("MemoryScanIntervalSeconds must be between 5 and 3600.");
        }

        if (options.MaxRetainedEvents is < 10 or > 10_000)
        {
            errors.Add("MaxRetainedEvents must be between 10 and 10000.");
        }

        if (options.FileBurstWindowSeconds is < 1 or > 120)
        {
            errors.Add("FileBurstWindowSeconds must be between 1 and 120.");
        }

        if (options.FileBurstThreshold is < 3 or > 10_000)
        {
            errors.Add("FileBurstThreshold must be between 3 and 10000.");
        }

        if (options.FileBurstCooldownSeconds is < 1 or > 3600)
        {
            errors.Add("FileBurstCooldownSeconds must be between 1 and 3600.");
        }

        if (options.MemoryAlertCooldownMinutes is < 1 or > 1440)
        {
            errors.Add("MemoryAlertCooldownMinutes must be between 1 and 1440.");
        }

        if (options.WatchedDirectories is null)
        {
            errors.Add("WatchedDirectories must not be null.");
        }
        else if (options.WatchedDirectories.Any(string.IsNullOrWhiteSpace))
        {
            errors.Add("WatchedDirectories must not contain empty or whitespace entries.");
        }

        return errors.Count == 0
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(errors);
    }
}
