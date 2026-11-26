namespace Guardian.Contracts.Scanning;

/// <summary>Étendue d'une analyse (correspond aux modes rapide, complet, personnalisé de l'interface).</summary>
public enum ScanScope
{
    Quick,
    Full,
    Custom
}

/// <summary>Demande d'analyse d'un ensemble de fichiers.</summary>
public sealed record ScanJobRequest
{
    public required ScanScope Scope { get; init; }

    /// <summary>Dossier ou fichier à analyser. Obligatoire pour <see cref="ScanScope.Custom"/>.</summary>
    public string? CustomPath { get; init; }
}

/// <summary>Progression d'une analyse en cours.</summary>
public sealed record ScanProgressInfo(
    int Percent,
    string CurrentPath,
    int FilesProcessed,
    int FilesTotal,
    int ThreatsFound);

/// <summary>Bilan d'une analyse terminée.</summary>
public sealed record ScanSummary
{
    public required ScanScope Scope { get; init; }

    /// <summary>Fichiers réellement analysés.</summary>
    public required int FilesScanned { get; init; }

    /// <summary>Fichiers non analysés (illisibles, trop gros, erreur).</summary>
    public required int FilesSkipped { get; init; }

    /// <summary>Fichiers suspects ou malveillants.</summary>
    public required IReadOnlyList<FileScanResult> Findings { get; init; }

    public required DateTime StartedAtUtc { get; init; }
    public required TimeSpan Duration { get; init; }
}
