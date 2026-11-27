using Guardian.Contracts.Common;
using Guardian.Contracts.System;

namespace Guardian.SystemMonitor.Detection;

/// <summary>
/// Instantané léger d'un volume amovible détecté.
/// </summary>
/// <param name="RootPath">Point de montage (ex. <c>E:\</c>).</param>
/// <param name="VolumeLabel">Étiquette du volume si disponible.</param>
/// <param name="DriveFormat">Système de fichiers (FAT32, exFAT, NTFS).</param>
/// <param name="TotalSizeBytes">Capacité totale en octets.</param>
public sealed record RemovableDriveSnapshot(
    string RootPath,
    string VolumeLabel,
    string DriveFormat,
    long TotalSizeBytes);

/// <summary>
/// Contrat de lecture des lecteurs amovibles actuellement prêts sur la machine.
/// </summary>
public interface IRemovableDriveProvider
{
    /// <summary>
    /// Retourne la liste des supports amovibles prêts en lecture seule.
    /// </summary>
    /// <returns>Instantané des supports détectés.</returns>
    IReadOnlyList<RemovableDriveSnapshot> GetRemovableDrives();
}

/// <summary>
/// Implémentation Windows/standard reposant sur <see cref="DriveInfo"/> en lecture seule.
/// </summary>
public sealed class WindowsRemovableDriveProvider : IRemovableDriveProvider
{
    /// <inheritdoc />
    public IReadOnlyList<RemovableDriveSnapshot> GetRemovableDrives()
    {
        var drives = new List<RemovableDriveSnapshot>();

        try
        {
            foreach (var drive in DriveInfo.GetDrives())
            {
                try
                {
                    if (drive.DriveType != DriveType.Removable || !drive.IsReady)
                    {
                        continue;
                    }

                    drives.Add(new RemovableDriveSnapshot(
                        RootPath: drive.RootDirectory.FullName,
                        VolumeLabel: string.IsNullOrWhiteSpace(drive.VolumeLabel) ? "(Sans étiquette)" : drive.VolumeLabel,
                        DriveFormat: drive.DriveFormat,
                        TotalSizeBytes: drive.TotalSize));
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
                {
                    // Lecteur en cours d'éjection ou inaccessible : on l'ignore sans interrompre l'inventaire.
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return [];
        }

        return drives;
    }
}

/// <summary>
/// Traceur différentiel des branchements et retraits de supports USB / amovibles.
/// </summary>
public sealed class RemovableDriveTracker
{
    private readonly TimeProvider _timeProvider;
    private readonly object _gate = new();

    private bool _hasBaseline;
    private Dictionary<string, RemovableDriveSnapshot> _knownDrives = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Initialise le traceur de supports amovibles.
    /// </summary>
    /// <param name="timeProvider">Horloge injectée.</param>
    public RemovableDriveTracker(TimeProvider timeProvider)
    {
        _timeProvider = timeProvider ?? throw new ArgumentNullException(nameof(timeProvider));
    }

    /// <summary>
    /// Compare la liste courante des supports amovibles à la référence précédente.
    /// </summary>
    /// <param name="currentDrives">Supports détectés à cet instant.</param>
    /// <returns>Événements générés (vide lors de la capture initiale).</returns>
    public IReadOnlyList<SystemSecurityEventDto> EvaluateDrives(IReadOnlyList<RemovableDriveSnapshot> currentDrives)
    {
        ArgumentNullException.ThrowIfNull(currentDrives);

        var now = _timeProvider.GetUtcNow();
        var current = new Dictionary<string, RemovableDriveSnapshot>(StringComparer.OrdinalIgnoreCase);
        foreach (var drive in currentDrives)
        {
            current[drive.RootPath] = drive;
        }

        lock (_gate)
        {
            if (!_hasBaseline)
            {
                _knownDrives = current;
                _hasBaseline = true;
                return [];
            }

            var events = new List<SystemSecurityEventDto>();

            foreach (var pair in current)
            {
                if (!_knownDrives.ContainsKey(pair.Key))
                {
                    var d = pair.Value;
                    events.Add(new SystemSecurityEventDto(
                        EventId: Guid.NewGuid(),
                        TimestampUtc: now,
                        Category: SystemEventCategory.UsbDeviceEvent,
                        Severity: EventSeverity.Info,
                        Source: "Guardian.SystemMonitor.UsbTracker",
                        ProcessId: null,
                        ProcessName: null,
                        Target: d.RootPath,
                        Summary: $"Support amovible monté : {d.RootPath} ({d.VolumeLabel}, {d.DriveFormat}).",
                        Metadata: new Dictionary<string, string>
                        {
                            ["volumeLabel"] = d.VolumeLabel,
                            ["driveFormat"] = d.DriveFormat,
                            ["totalSizeBytes"] = d.TotalSizeBytes.ToString()
                        }));
                }
            }

            foreach (var pair in _knownDrives)
            {
                if (!current.ContainsKey(pair.Key))
                {
                    events.Add(new SystemSecurityEventDto(
                        EventId: Guid.NewGuid(),
                        TimestampUtc: now,
                        Category: SystemEventCategory.UsbDeviceEvent,
                        Severity: EventSeverity.Low,
                        Source: "Guardian.SystemMonitor.UsbTracker",
                        ProcessId: null,
                        ProcessName: null,
                        Target: pair.Key,
                        Summary: $"Support amovible retiré : {pair.Key}.",
                        Metadata: new Dictionary<string, string>
                        {
                            ["volumeLabel"] = pair.Value.VolumeLabel
                        }));
                }
            }

            _knownDrives = current;
            return events;
        }
    }
}
