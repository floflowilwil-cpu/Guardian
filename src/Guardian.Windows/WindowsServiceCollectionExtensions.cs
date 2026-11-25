using Guardian.Contracts.Memory;
using Guardian.Windows.Environment;
using Guardian.Windows.Memory;
using Guardian.Windows.Processes;
using Guardian.Windows.Registry;
using Guardian.Windows.Security;
using Guardian.Windows.Services;
using Microsoft.Extensions.DependencyInjection;

namespace Guardian.Windows;

/// <summary>
/// Méthodes d'extension d'injection de dépendances pour les adaptateurs système Windows Guardian.
/// </summary>
public static class WindowsServiceCollectionExtensions
{
    /// <summary>
    /// Enregistre l'ensemble des adaptateurs Windows en lecture seule dans le conteneur de services.
    /// </summary>
    /// <param name="services">Collection de services cible.</param>
    /// <returns>La collection de services enrichie.</returns>
    public static IServiceCollection AddGuardianWindowsAdapters(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSingleton<IWindowsPrivilegeInspector, WindowsPrivilegeInspector>();
        services.AddSingleton<IWindowsRegistryAdapter, WindowsRegistryAdapter>();
        services.AddSingleton<IWindowsServiceAdapter, WindowsServiceAdapter>();
        services.AddSingleton<IWindowsAclInspector, WindowsAclInspector>();
        services.AddSingleton<IWindowsAuthenticodeVerifier, WindowsAuthenticodeVerifier>();
        services.AddSingleton<IWindowsSecurityPostureReader, WindowsSecurityPostureReader>();
        services.AddSingleton<IWindowsProcessAdapter, WindowsProcessAdapter>();
        services.AddSingleton<IWindowsMemoryAdapter, WindowsMemoryAdapter>();
        services.AddSingleton<IMemoryAnalyzer>(sp => sp.GetRequiredService<IWindowsMemoryAdapter>());

        return services;
    }
}
