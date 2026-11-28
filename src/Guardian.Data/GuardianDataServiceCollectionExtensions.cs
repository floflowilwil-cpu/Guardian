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
    /// <param name="options">Options de la base ; valeurs par défaut si omises.</param>
    /// <returns>La collection de services, pour chaînage.</returns>
    public static IServiceCollection AddGuardianData(this IServiceCollection services, GuardianDatabaseOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(options ?? new GuardianDatabaseOptions());
        services.TryAddSingleton<ISqliteConnectionFactory, SqliteConnectionFactory>();
        services.TryAddSingleton<MigrationRunner>();
        services.TryAddSingleton<IThreatRepository, SqliteThreatRepository>();
        services.TryAddSingleton<IEventRepository, SqliteEventRepository>();

        return services;
    }
}
