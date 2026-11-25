using Guardian.Contracts.Common;

namespace Guardian.Contracts.Health;

/// <summary>
/// Instantané global et vérifiable de la santé du service Guardian et de ses modules.
/// </summary>
/// <remarks>
/// Conformément à la règle de transparence, <see cref="OverallStatus"/> ne vaut
/// <see cref="GuardianHealthStatus.Healthy"/> que si l'ensemble des composants requis
/// sont opérationnels et disposent d'un heartbeat valide.
/// </remarks>
/// <param name="OverallStatus">État de santé global agrégé.</param>
/// <param name="CapturedAtUtc">Horodatage UTC de l'évaluation.</param>
/// <param name="ServiceVersion">Version applicative du service résident.</param>
/// <param name="Components">Liste des rapports individuels par composant.</param>
/// <param name="DegradedReasons">Raisons explicites justifiant tout état non nominal.</param>
/// <param name="Watchdog">Instantané courant du watchdog, s'il est disponible.</param>
public sealed record GuardianHealthSnapshot(
    GuardianHealthStatus OverallStatus,
    DateTimeOffset CapturedAtUtc,
    string ServiceVersion,
    IReadOnlyList<ComponentHealthReport> Components,
    IReadOnlyList<string> DegradedReasons,
    WatchdogSnapshot? Watchdog = null);
