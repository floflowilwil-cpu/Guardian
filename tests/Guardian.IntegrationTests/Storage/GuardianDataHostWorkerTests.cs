using Guardian.Contracts.Common;
using Guardian.Contracts.AI.Models;
using Guardian.Contracts.Data;
using Guardian.Contracts.Health;
using Guardian.Service.Configuration;
using Guardian.Service.Hosting;
using Guardian.Service.Storage;
using Guardian.Windows;
using Guardian.Windows.Environment;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Guardian.IntegrationTests.Storage;

public class GuardianDataHostWorkerTests
{
    private static IHost BuildHost(string dataDirectory)
    {
        var builder = Host.CreateApplicationBuilder();
        builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["GuardianService:HeartbeatIntervalSeconds"] = "1",
            ["GuardianService:HeartbeatStaleThresholdSeconds"] = "10",
            ["GuardianService:ShutdownTimeoutSeconds"] = "5",
            ["GuardianService:DataDirectoryOverride"] = dataDirectory,
            ["GuardianService:IpcPipeName"] = $"Guardian.Test.Ipc.{Guid.NewGuid():N}"
        });
        builder.Services.AddGuardianServiceCore(builder.Configuration);
        builder.Services.AddGuardianDataStorage();

        return builder.Build();
    }

    private static void Cleanup(string path)
    {
        SqliteConnection.ClearAllPools();

        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // Nettoyage au mieux : un dossier temporaire résiduel est sans conséquence.
        }
    }

    [Fact]
    public async Task ServiceStart_ShouldCreateDatabaseApplyMigrationsAndReportHealthyDataComponent()
    {
        var dataDirectory = Path.Combine(Path.GetTempPath(), $"guardian-data-{Guid.NewGuid():N}");

        try
        {
            using var host = BuildHost(dataDirectory);
            await host.StartAsync();

            var health = host.Services.GetRequiredService<IGuardianHealthService>();
            var report = await health.GetComponentHealthAsync(GuardianDataHostWorker.DataComponentName);

            Assert.NotNull(report);
            Assert.Equal(GuardianHealthStatus.Healthy, report.Status);
            Assert.True(File.Exists(Path.Combine(dataDirectory, "guardian.db")));

            await host.StopAsync();
        }
        finally
        {
            Cleanup(dataDirectory);
        }
    }

    [Fact]
    public async Task ServiceStart_WhenDatabaseCannotBeInitialized_ShouldStayUpAndReportDegraded()
    {
        var blockingFile = Path.Combine(Path.GetTempPath(), $"guardian-blocker-{Guid.NewGuid():N}.tmp");
        await File.WriteAllTextAsync(blockingFile, "ce fichier empêche la création du dossier de données");
        var impossibleDirectory = Path.Combine(blockingFile, "data");

        try
        {
            using var host = BuildHost(impossibleDirectory);
            await host.StartAsync();

            var health = host.Services.GetRequiredService<IGuardianHealthService>();
            var report = await health.GetComponentHealthAsync(GuardianDataHostWorker.DataComponentName);

            Assert.NotNull(report);
            Assert.Equal(GuardianHealthStatus.Degraded, report.Status);

            var overall = await health.GetOverallHealthAsync();
            Assert.NotEqual(GuardianHealthStatus.Healthy, overall.OverallStatus);

            await host.StopAsync();
        }
        finally
        {
            File.Delete(blockingFile);
        }
    }

    [Fact]
    public async Task ServiceRestart_ShouldKeepPersistedThreats()
    {
        var dataDirectory = Path.Combine(Path.GetTempPath(), $"guardian-data-{Guid.NewGuid():N}");
        var when = new DateTimeOffset(2026, 11, 1, 10, 0, 0, TimeSpan.Zero);
        var threat = new ThreatRecordDto(
            Guid.NewGuid(), when, when, "Trojan.Persistant", ThreatVerdict.Malicious, 90,
            ThreatStatus.Detected, "Scanner", null, null, []);

        try
        {
            using (var first = BuildHost(dataDirectory))
            {
                await first.StartAsync();
                await first.Services.GetRequiredService<IThreatRepository>().UpsertAsync(threat);
                await first.StopAsync();
            }

            using (var second = BuildHost(dataDirectory))
            {
                await second.StartAsync();

                var loaded = await second.Services.GetRequiredService<IThreatRepository>().GetByIdAsync(threat.ThreatId);

                Assert.NotNull(loaded);
                Assert.Equal("Trojan.Persistant", loaded.DisplayName);

                await second.StopAsync();
            }
        }
        finally
        {
            Cleanup(dataDirectory);
        }
    }

    [Fact]
    public void ResolveDatabasePath_ShouldUseOverrideDirectoryOrStandardPath()
    {
        var services = new ServiceCollection();
        services.AddGuardianWindowsAdapters();
        using var provider = services.BuildServiceProvider();
        var inspector = provider.GetRequiredService<IWindowsPrivilegeInspector>();
        var standardPath = inspector.GetStandardPaths().DatabaseFilePath;

        var withoutOverride = GuardianDataStorageRegistrationExtensions.ResolveDatabasePath(
            inspector, new GuardianServiceOptions());
        Assert.Equal(standardPath, withoutOverride);

        var overrideDirectory = Path.Combine(Path.GetTempPath(), "guardian-override-test");
        var withOverride = GuardianDataStorageRegistrationExtensions.ResolveDatabasePath(
            inspector, new GuardianServiceOptions { DataDirectoryOverride = overrideDirectory });

        Assert.Equal(
            Path.Combine(Path.GetFullPath(overrideDirectory), Path.GetFileName(standardPath)),
            withOverride);
    }
}
