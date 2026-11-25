namespace Guardian.Contracts.System;

/// <summary>
/// Décrit un service Windows inventorié en lecture seule.
/// </summary>
/// <param name="ServiceName">Nom interne du service dans le SCM Windows.</param>
/// <param name="DisplayName">Nom d'affichage du service.</param>
/// <param name="State">État d'exécution courant.</param>
/// <param name="StartMode">Mode de démarrage configuré.</param>
/// <param name="BinaryPath">Ligne de commande ou chemin du binaire, si accessible.</param>
/// <param name="AccountName">Compte d'exécution configuré pour le service, si accessible.</param>
/// <param name="ProcessId">Identifiant du processus hôte lorsque le service est actif.</param>
public sealed record WindowsServiceInfoDto(
    string ServiceName,
    string DisplayName,
    WindowsServiceState State,
    WindowsServiceStartMode StartMode,
    string? BinaryPath,
    string? AccountName,
    int? ProcessId);
