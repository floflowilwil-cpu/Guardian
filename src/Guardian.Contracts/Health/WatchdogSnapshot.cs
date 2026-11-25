using Guardian.Contracts.Common;

namespace Guardian.Contracts.Health;

/// <summary>
/// Instantané global de l'état du watchdog et de ses composants surveillés.
/// </summary>
/// <param name="CapturedAtUtc">Horodatage UTC de capture de l'instantané.</param>
/// <param name="OverallStatus">État agrégé du watchdog.</param>
/// <param name="Components">État détaillé de chacun des composants suivis.</param>
public sealed record WatchdogSnapshot(
    DateTimeOffset CapturedAtUtc,
    GuardianHealthStatus OverallStatus,
    IReadOnlyList<WatchdogComponentStateDto> Components);
