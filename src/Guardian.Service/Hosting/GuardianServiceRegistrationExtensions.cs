using Guardian.Contracts.AI.Models;
using Guardian.Contracts.Health;
using Guardian.Contracts.Heuristics;
using Guardian.Contracts.Ipc;
using Guardian.Contracts.Scanning;
using Guardian.Contracts.Signatures;
using Guardian.Scanner;
using Guardian.Scanner.Heuristics;
using Guardian.Service.Configuration;
using Guardian.Service.Health;
using Guardian.Service.Ipc;
using Guardian.Service.Scanning;
using Guardian.Service.Security;
using Guardian.Service.Watchdog;
using Guardian.Signatures;
using Guardian.SystemMonitor;
using Guardian.Windows;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Guardian.Service.Hosting;

/// <summary>
/// Méthodes d'extension pour enregistrer le cœur du service Guardian et son intégration Windows Service.
/// </summary>
public static class GuardianServiceRegistrationExtensions
{
    /// <summary>
    /// Configure l'hôte pour utiliser le gestionnaire de cycle de vie Windows Service lorsqu'il s'exécute sous le SCM Windows.
    /// </summary>
    /// <param name="builder">Constructeur d'application hôte .NET.</param>
    /// <returns>Le constructeur enrichi.</returns>
    public static IHostApplicationBuilder UseGuardianWindowsService(this IHostApplicationBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        if (GuardianWindowsServiceLifetime.IsRunningAsWindowsService())
        {
            builder.Services.AddSingleton<IHostLifetime, GuardianWindowsServiceLifetime>();
        }

        return builder;
    }

    /// <summary>
    /// Enregistre les options validées, les adaptateurs Windows, le service de santé,
    /// le watchdog anti-boucle, le moniteur d'auto-intégrité, le coordinateur de scans et le serveur IPC.
    /// </summary>
    /// <param name="services">Collection de services cible.</param>
    /// <param name="configuration">Configuration applicative source.</param>
    /// <returns>La collection de services enrichie.</returns>
    public static IServiceCollection AddGuardianServiceCore(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.TryAddSingleton(TimeProvider.System);
        services.AddSingleton<IValidateOptions<GuardianServiceOptions>, GuardianServiceOptionsValidator>();

        services.AddOptions<GuardianServiceOptions>()
            .Bind(configuration.GetSection(GuardianServiceConstants.ConfigurationSectionName))
            .ValidateOnStart();

        var boundOptions = configuration
            .GetSection(GuardianServiceConstants.ConfigurationSectionName)
            .Get<GuardianServiceOptions>() ?? new GuardianServiceOptions();

        services.Configure<HostOptions>(hostOptions =>
        {
            if (boundOptions.ShutdownTimeoutSeconds >= 5)
            {
                hostOptions.ShutdownTimeout = TimeSpan.FromSeconds(boundOptions.ShutdownTimeoutSeconds);
            }
        });

        services.AddGuardianWindowsAdapters();
        services.AddGuardianSystemMonitor(configuration);

        services.AddSingleton<GuardianHealthService>();
        services.AddSingleton<IGuardianHealthService>(sp => sp.GetRequiredService<GuardianHealthService>());

        services.AddSingleton<WatchdogTracker>();
        services.AddSingleton<ISelfIntegrityMonitor, SelfIntegrityMonitor>();

        services.TryAddSingleton<ISignatureProvider>(_ => new InMemorySignatureProvider(
        [
            new SignatureMatch
            {
                SignatureId = "EICAR-STANDARD-TEST",
                Sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                ThreatName = "EICAR-Test-File",
                ThreatFamily = "Test",
                Severity = SignalSeverity.High
            }
        ]));
        services.TryAddSingleton<IHeuristicAnalyzer, HeuristicAnalyzer>();
        services.TryAddSingleton<IScanTargetResolver, DefaultScanTargetResolver>();
        services.TryAddSingleton<IFileScanner, FileScanner>();
        services.TryAddSingleton<IScanOrchestrator, ScanOrchestrator>();
        services.AddSingleton<IScanExecutionCoordinator, ScanExecutionCoordinator>();

        services.AddSingleton<IpcReplayGuard>();
        services.AddSingleton<IIpcRequestDispatcher, IpcRequestDispatcher>();

        services.AddSingleton<NamedPipeIpcServer>();
        services.AddSingleton<IMonitoredComponent>(sp => sp.GetRequiredService<NamedPipeIpcServer>());

        services.AddSingleton<SystemMonitorHostWorker>();
        services.AddSingleton<IMonitoredComponent>(sp => sp.GetRequiredService<SystemMonitorHostWorker>());

        services.AddSingleton<GuardianWatchdogService>();
        services.AddHostedService<GuardianCoreHostWorker>();
        services.AddHostedService(sp => sp.GetRequiredService<SystemMonitorHostWorker>());
        services.AddHostedService(sp => sp.GetRequiredService<NamedPipeIpcServer>());
        services.AddHostedService(sp => sp.GetRequiredService<GuardianWatchdogService>());
        services.AddHostedService<SelfIntegrityWorker>();

        return services;
    }
}
