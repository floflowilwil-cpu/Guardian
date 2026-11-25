using Guardian.Contracts.Common;

namespace Guardian.Contracts.Health;

/// <summary>
/// État de surveillance d'un composant suivi par le watchdog Guardian.
/// </summary>
/// <param name="ComponentName">Nom du composant surveillé.</param>
/// <param name="Status">État courant évalué par le watchdog.</param>
/// <param name="LastHeartbeatUtc">Horodatage UTC du dernier battement reçu.</param>
/// <param name="RestartsInCurrentWindow">Nombre de redémarrages tentés dans la fenêtre glissante active.</param>
/// <param name="MaxRestartsInWindow">Plafond maximal de redémarrages autorisés avant ouverture du disjoncteur.</param>
/// <param name="CircuitBreakerOpen">Indique si le disjoncteur anti-boucle bloque de nouveaux redémarrages.</param>
/// <param name="LastFailureReason">Motif du dernier échec ou redémarrage observé, le cas échéant.</param>
public sealed record WatchdogComponentStateDto(
    string ComponentName,
    GuardianHealthStatus Status,
    DateTimeOffset? LastHeartbeatUtc,
    int RestartsInCurrentWindow,
    int MaxRestartsInWindow,
    bool CircuitBreakerOpen,
    string? LastFailureReason = null);
