using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using Guardian.Desktop.Models;

namespace Guardian.Desktop.Infrastructure;

public enum ScanOutcome
{
    Completed,
    Cancelled,
    Failed,
}

/// <summary>Résumé d'une analyse lancée depuis l'interface.</summary>
public sealed record ScanRecord(
    Guid Id,
    DateTime StartedAt,
    ScanKind Kind,
    double DurationSeconds,
    int FilesScanned,
    int FilesSkipped,
    int Threats,
    ScanOutcome Outcome);

/// <summary>
/// Historique des analyses, conservé dans %LocalAppData%\Guardian\scan-history.json.
/// Ne contient que des compteurs (aucun chemin de fichier, aucun contenu) : c'est une donnée
/// d'interface, au même titre que les préférences. Le plus récent est en premier.
/// </summary>
public sealed class ScanHistoryStore
{
    public const int DefaultMaxEntries = 200;

    // Doit être déclaré avant Default : les initialiseurs statiques s'exécutent dans l'ordre du fichier.
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    private readonly object _gate = new();
    private readonly string _path;
    private readonly int _maxEntries;
    private readonly List<ScanRecord> _records;

    public static ScanHistoryStore Default { get; } = new(DefaultPath);

    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Guardian", "scan-history.json");

    public ScanHistoryStore(string path, int maxEntries = DefaultMaxEntries)
    {
        _path = path;
        _maxEntries = Math.Max(1, maxEntries);
        _records = Load();
    }

    /// <summary>Levé après chaque ajout ou effacement (sur le thread de l'appelant).</summary>
    public event Action? Changed;

    /// <summary>Copie des enregistrements, du plus récent au plus ancien.</summary>
    public IReadOnlyList<ScanRecord> Records
    {
        get
        {
            lock (_gate)
            {
                return _records.ToArray();
            }
        }
    }

    public void Add(ScanRecord record)
    {
        lock (_gate)
        {
            _records.Insert(0, record);
            if (_records.Count > _maxEntries)
            {
                _records.RemoveRange(_maxEntries, _records.Count - _maxEntries);
            }

            Save();
        }

        Changed?.Invoke();
    }

    public void Clear()
    {
        lock (_gate)
        {
            _records.Clear();
            Save();
        }

        Changed?.Invoke();
    }

    private List<ScanRecord> Load()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return new List<ScanRecord>();
            }

            var loaded = JsonSerializer.Deserialize<List<ScanRecord>>(File.ReadAllText(_path), JsonOptions);
            return loaded is null
                ? new List<ScanRecord>()
                : loaded.OrderByDescending(r => r.StartedAt).Take(_maxEntries).ToList();
        }
        catch (Exception ex)
        {
            // Fichier illisible ou modifié à la main : on repart d'un historique vide plutôt que de planter.
            AppLog.Write(ex, "Lecture de l'historique des analyses");
            return new List<ScanRecord>();
        }
    }

    private void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);

            // Écriture dans un fichier temporaire puis remplacement : pas de fichier à moitié écrit.
            var temp = _path + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(_records, JsonOptions));
            File.Move(temp, _path, overwrite: true);
        }
        catch (Exception ex)
        {
            AppLog.Write(ex, "Écriture de l'historique des analyses");
        }
    }
}
