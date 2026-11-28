using Guardian.Data;
using Guardian.Service.Configuration;
using Guardian.Service.Watchdog;
using Guardian.Windows.Environment;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Guardian.Service.Storage;

/// <summary>
/// Enregistrement de la couche de données dans le service Guardian.
/// </summary>
public static class GuardianDataStorageRegistrationExtensions
{
    /// <summary>
    /// Branche la base SQLite : dépôts, migrations au démarrage et composant surveillé par le watchdog.
    /// À appeler après <c>AddGuardianServiceCore</c>.
    /// </summary>
    /// <param name="services">Collection de services.</param>
    /// <returns>La collection de services, pour chaînage.</returns>
    public static IServiceCollection AddGuardianDataStorage(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddGuardianData(sp => new GuardianDatabaseOptions
        {
            DatabasePath = ResolveDatabasePath(
                sp.GetRequiredService<IWindowsPrivilegeInspector>(),
                sp.GetRequiredService<IOptions<GuardianServiceOptions>>().Value)
        });

        services.AddSingleton<GuardianDataHostWorker>();
        services.AddSingleton<IMonitoredComponent>(sp => sp.GetRequiredService<GuardianDataHostWorker>());
        services.AddHostedService(sp => sp.GetRequiredService<GuardianDataHostWorker>());

        return services;
    }

    /// <summary>
    /// Détermine le chemin de la base : le dossier de <c>DataDirectoryOverride</c> s'il est défini,
    /// sinon le chemin standard fourni par <c>GetStandardPaths()</c>.
    /// </summary>
    /// <param name="inspector">Inspecteur des chemins standards.</param>
    /// <param name="options">Options du service.</param>
    /// <returns>Chemin complet du fichier de base.</returns>
    public static string ResolveDatabasePath(IWindowsPrivilegeInspector inspector, GuardianServiceOptions options)
    {
        ArgumentNullException.ThrowIfNull(inspector);
        ArgumentNullException.ThrowIfNull(options);

        var standardPath = inspector.GetStandardPaths().DatabaseFilePath;

        return string.IsNullOrWhiteSpace(options.DataDirectoryOverride)
            ? standardPath
            : Path.Combine(Path.GetFullPath(options.DataDirectoryOverride), Path.GetFileName(standardPath));
    }
}
