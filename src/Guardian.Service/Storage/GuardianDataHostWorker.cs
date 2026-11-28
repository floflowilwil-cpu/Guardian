using Guardian.Contracts.Common;
using Guardian.Contracts.Health;
using Guardian.Data;
using Guardian.Service.Configuration;
using Guardian.Service.Watchdog;
using Guardian.Windows.Security;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Guardian.Service.Storage;

/// <summary>
/// Composant de démarrage de la couche de données : sécurise le dossier de données, applique les migrations SQLite,
/// puis publie sa santé et un battement de cœur régulier au watchdog.
/// </summary>
/// <remarks>
/// <para>Un échec d'initialisation n'arrête pas le service : le composant passe en état dégradé, journalise l'erreur
/// et le watchdog relance l'initialisation (avec son plafond de redémarrages).</para>
/// <para>Les messages de santé n'incluent jamais le détail technique de l'exception (chemins, texte SQL) :
/// il reste dans les journaux du service.</para>
/// </remarks>
public sealed class GuardianDataHostWorker : BackgroundService, IMonitoredComponent
{
    /// <summary>Nom du composant tel que publié dans la santé du service.</summary>
    public const string DataComponentName = "Guardian.Data";

    private readonly MigrationRunner _migrations;
    private readonly ISqliteConnectionFactory _connections;
    private readonly GuardianDatabaseOptions _database;
    private readonly IWindowsAclInspector _aclInspector;
    private readonly IGuardianHealthService _healthService;
    private readonly IOptions<GuardianServiceOptions> _options;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<GuardianDataHostWorker> _logger;
    private readonly SemaphoreSlim _initializationGate = new(1, 1);

    private volatile bool _isHealthy;
    private DateTimeOffset? _lastHeartbeatUtc;

    /// <summary>
    /// Crée le composant de démarrage de la couche de données.
    /// </summary>
    public GuardianDataHostWorker(
        MigrationRunner migrations,
        ISqliteConnectionFactory connections,
        GuardianDatabaseOptions database,
        IWindowsAclInspector aclInspector,
        IGuardianHealthService healthService,
        IOptions<GuardianServiceOptions> options,
        TimeProvider timeProvider,
        ILogger<GuardianDataHostWorker> logger)
    {
        _migrations = migrations ?? throw new ArgumentNullException(nameof(migrations));
        _connections = connections ?? throw new ArgumentNullException(nameof(connections));
        _database = database ?? throw new ArgumentNullException(nameof(database));
        _aclInspector = aclInspector ?? throw new ArgumentNullException(nameof(aclInspector));
        _healthService = healthService ?? throw new ArgumentNullException(nameof(healthService));
        _options = options ?? throw new ArgumentNullException(nameof(options));
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    /// <inheritdoc />
    public string ComponentName => DataComponentName;

    /// <inheritdoc />
    public bool IsHealthy => _isHealthy;

    /// <inheritdoc />
    public DateTimeOffset? LastHeartbeatUtc => _lastHeartbeatUtc;

    /// <inheritdoc />
    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        await InitializeAsync(cancellationToken).ConfigureAwait(false);
        await base.StartAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromSeconds(Math.Max(1, _options.Value.HeartbeatIntervalSeconds));
        using var timer = new PeriodicTimer(interval, _timeProvider);

        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                var now = _timeProvider.GetUtcNow();

                if (_isHealthy)
                {
                    await ProbeAsync(stoppingToken).ConfigureAwait(false);
                }

                _lastHeartbeatUtc = now;
                await PublishHealthAsync(now, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Arrêt propre demandé par l'hôte.
        }
    }

    /// <inheritdoc />
    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        _isHealthy = false;
        var now = _timeProvider.GetUtcNow();
        _lastHeartbeatUtc = now;

        await _healthService.ReportComponentHealthAsync(
            new ComponentHealthReport(
                ComponentName: ComponentName,
                Status: GuardianHealthStatus.Stopped,
                Summary: "Guardian data layer stopped cleanly.",
                LastUpdatedUtc: now,
                LastHeartbeatUtc: now,
                Availability: FeatureAvailabilityStatus.Unavailable,
                Reasons: ["Guardian data host worker stopped."]),
            CancellationToken.None).ConfigureAwait(false);

        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public Task RestartAsync(CancellationToken cancellationToken = default)
    {
        _logger.LogWarning("Re-initializing the Guardian data layer via watchdog request.");
        return InitializeAsync(cancellationToken);
    }

    /// <inheritdoc />
    public override void Dispose()
    {
        _initializationGate.Dispose();
        base.Dispose();
    }

    private async Task InitializeAsync(CancellationToken cancellationToken)
    {
        await _initializationGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureDataDirectory();

            var applied = await _migrations.MigrateAsync(cancellationToken).ConfigureAwait(false);
            await ProbeCoreAsync(cancellationToken).ConfigureAwait(false);

            _isHealthy = true;
            _logger.LogInformation("Guardian data layer ready ({Applied} migration(s) applied).", applied);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _isHealthy = false;
            _logger.LogError(ex, "Guardian data layer initialization failed.");
        }
        finally
        {
            _initializationGate.Release();
        }

        var now = _timeProvider.GetUtcNow();
        _lastHeartbeatUtc = now;
        await PublishHealthAsync(now, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Crée le dossier de données avec une ACL restrictive s'il n'existe pas encore (Windows).
    /// Un dossier existant est laissé tel quel : l'auto-vérification d'intégrité en audite les droits.
    /// </summary>
    private void EnsureDataDirectory()
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(_database.DatabasePath));

        if (string.IsNullOrEmpty(directory) || Directory.Exists(directory))
        {
            return;
        }

        if (OperatingSystem.IsWindows())
        {
            _aclInspector.ApplyRestrictiveDirectoryAcl(directory, includeCurrentUser: true);
        }
        else
        {
            Directory.CreateDirectory(directory);
        }
    }

    private async Task ProbeAsync(CancellationToken cancellationToken)
    {
        try
        {
            await ProbeCoreAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _isHealthy = false;
            _logger.LogWarning(ex, "Guardian data layer health probe failed.");
        }
    }

    private async Task ProbeCoreAsync(CancellationToken cancellationToken)
    {
        await using var connection = await _connections.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT 1";
        await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
    }

    private Task PublishHealthAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        if (_isHealthy)
        {
            return _healthService.ReportComponentHealthAsync(
                new ComponentHealthReport(
                    ComponentName: ComponentName,
                    Status: GuardianHealthStatus.Healthy,
                    Summary: "Guardian data layer ready.",
                    LastUpdatedUtc: now,
                    LastHeartbeatUtc: now,
                    Availability: FeatureAvailabilityStatus.Available,
                    Reasons: []),
                cancellationToken);
        }

        return _healthService.ReportComponentHealthAsync(
            new ComponentHealthReport(
                ComponentName: ComponentName,
                Status: GuardianHealthStatus.Degraded,
                Summary: "Guardian data layer is unavailable.",
                LastUpdatedUtc: now,
                LastHeartbeatUtc: now,
                Availability: FeatureAvailabilityStatus.Degraded,
                Reasons: ["Database initialization or health probe failed; see service logs."]),
            cancellationToken);
    }
}
