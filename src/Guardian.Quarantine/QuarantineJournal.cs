using System.Text.Json;
using Guardian.Contracts.Common;

namespace Guardian.Quarantine;

/// <summary>Journal des actions de quarantaine.</summary>
public interface IQuarantineJournal
{
    void Write(AuditEventDto entry);
}

/// <summary>Journal en fichier texte, une ligne JSON par événement.</summary>
public sealed class FileQuarantineJournal : IQuarantineJournal
{
    private readonly string _path;
    private readonly object _lock = new();

    public FileQuarantineJournal(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);

        string? directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }

    public void Write(AuditEventDto entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        string line = JsonSerializer.Serialize(entry) + Environment.NewLine;

        lock (_lock)
        {
            File.AppendAllText(_path, line);
        }
    }
}