using Guardian.Contracts.Common;

namespace Guardian.Contracts.System;

/// <summary>
/// Représente les métadonnées défensives d'un processus actif sur Windows.
/// </summary>
/// <param name="ProcessId">Identifiant numérique du processus (PID).</param>
/// <param name="ParentProcessId">Identifiant du processus parent lorsqu'il est résolu.</param>
/// <param name="ProcessName">Nom du processus.</param>
/// <param name="ExecutablePath">Chemin complet vers l'exécutable si accessible selon les privilèges.</param>
/// <param name="SessionId">Identifiant de session Windows.</param>
/// <param name="StartTimeUtc">Horodatage UTC de démarrage si accessible.</param>
/// <param name="AccessStatus">Statut de disponibilité de l'inspection pour ce processus.</param>
/// <param name="AccessNotes">Précision explicite en cas d'accès limité ou protégé.</param>
/// <param name="Modules">Modules chargés collectés lorsque demandés et accessibles.</param>
public sealed record ProcessInfoDto(
    int ProcessId,
    int? ParentProcessId,
    string ProcessName,
    string? ExecutablePath,
    int SessionId,
    DateTimeOffset? StartTimeUtc,
    FeatureAvailabilityStatus AccessStatus,
    string? AccessNotes,
    IReadOnlyList<LoadedModuleDto> Modules);
