using Guardian.Contracts.System;
using Guardian.SystemMonitor.Configuration;
using Guardian.SystemMonitor.Detection;
using Guardian.SystemMonitor.Events;
using Guardian.SystemMonitor.Sensors;
using Guardian.Windows;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Guardian.SystemMonitor;

/// <summary>
/// Méthodes d'extension d'injection de dépendances pour enregistrer le module <c>Guardian.SystemMonitor</c>.
/// </summary>
public static class SystemMonitorServiceCollectionExtensions
{
    /// <summary>
    /// Enregistre <see cref="ISystemMonitor"/>, <see cref="IBehaviorMonitor"/> et les capteurs associés
    /// sans jamais collecter de frappes ni affaiblir les défenses natives Windows.
    /// </summary>
    /// <param name="services">Collection de services cible.</param>
    /// <param name="configuration">Configuration applicative optionnelle contenant la section <c>SystemMonitor</c>.</param>
    /// <returns>La collection de services enrichie.</returns>
    public static IServiceCollection AddGuardianSystemMonitor(
        this IServiceCollection services,
        IConfiguration? configuration = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton(TimeProvider.System);
        services.AddGuardianWindowsAdapters();

        services.AddSingleton<IValidateOptions<SystemMonitorOptions>, SystemMonitorOptionsValidator>();
        var optionsBuilder = services.AddOptions<SystemMonitorOptions>();
        if (configuration is not null)
        {
            optionsBuilder.Bind(configuration.GetSection(SystemMonitorOptions.ConfigurationSectionName));
        }

        optionsBuilder.ValidateOnStart();

        services.AddSingleton<BoundedSystemEventStore>();
        services.TryAddSingleton<IRemovableDriveProvider, WindowsRemovableDriveProvider>();
        services.AddSingleton<WindowsEtwCapabilityProbe>();
        services.AddSingleton<SystemMonitorService>();
        services.AddSingleton<ISystemMonitor>(sp => sp.GetRequiredService<SystemMonitorService>());
        services.AddSingleton<IBehaviorMonitor>(sp => sp.GetRequiredService<SystemMonitorService>());

        return services;
    }
}
