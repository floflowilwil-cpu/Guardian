using Guardian.Contracts.Data;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Guardian.Data;

/// <summary>
/// Enregistrement de la couche de données dans le conteneur d'injection de dépendances.
/// </summary>
public static class GuardianDataServiceCollectionExtensions
{
    /// <summary>
    /// Enregistre la base SQLite, le moteur de migrations et les dépôts de menaces et d'événements.
    /// </summary>
    /// <param name="services">Collection de services.</param>
    /// <param name="options">Options de la base (chemin obligatoire).</param>
    /// <returns>La collection de services, pour chaînage.</returns>
    public static IServiceCollection AddGuardianData(this IServiceCollection services, GuardianDatabaseOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        return services.AddGuardianData(_ => options);
    }

    /// <summary>
    /// Enregistre la couche de données en résolvant les options au moment de la construction des services
    /// (utile quand le chemin dépend d'autres services, comme l'inspecteur de chemins Windows).
    /// </summary>
    /// <param name="services">Collection de services.</param>
    /// <param name="optionsFactory">Fabrique des options de la base.</param>
    /// <returns>La collection de services, pour chaînage.</returns>
    public static IServiceCollection AddGuardianData(
        this IServiceCollection services,
        Func<IServiceProvider, GuardianDatabaseOptions> optionsFactory)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(optionsFactory);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<GuardianDatabaseOptions>(optionsFactory);
        services.TryAddSingleton<ISqliteConnectionFactory, SqliteConnectionFactory>();
        services.TryAddSingleton<MigrationRunner>();
        services.TryAddSingleton<IThreatRepository, SqliteThreatRepository>();
        services.TryAddSingleton<IEventRepository, SqliteEventRepository>();

        return services;
    }
}
