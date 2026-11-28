using Guardian.Contracts.Common;

namespace Guardian.Contracts.Updates;

/// <summary>
/// Famille de composants pouvant être mis à jour.
/// </summary>
public enum UpdateComponentKind
{
    /// <summary>Composant inconnu.</summary>
    Unknown = 0,

    /// <summary>Binaires de l'application Guardian.</summary>
    Application = 1,

    /// <summary>Base de signatures.</summary>
    SignatureDatabase = 2,

    /// <summary>Modèles d'intelligence artificielle locaux.</summary>
    AiModel = 3,

    /// <summary>Règles de détection et de politique.</summary>
    DetectionRules = 4
}

/// <summary>
/// État d'une opération de mise à jour.
/// </summary>
public enum UpdateStatus
{
    /// <summary>Composant à jour.</summary>
    UpToDate = 0,

    /// <summary>Une version plus récente est disponible.</summary>
    UpdateAvailable = 1,

    /// <summary>Téléchargement en cours.</summary>
    Downloading = 2,

    /// <summary>Vérification de la signature et des empreintes en cours.</summary>
    Verifying = 3,

    /// <summary>Installation en cours.</summary>
    Installing = 4,

    /// <summary>Mise à jour installée avec succès.</summary>
    Installed = 5,

    /// <summary>Mise à jour annulée et version précédente restaurée.</summary>
    RolledBack = 6,

    /// <summary>Mise à jour rejetée par la chaîne de confiance.</summary>
    Rejected = 7,

    /// <summary>Échec technique sans rejet de sécurité (réseau, disque, etc.).</summary>
    Failed = 8
}

/// <summary>
/// Motif de rejet d'une mise à jour.
/// </summary>
public enum UpdateRejectionReason
{
    /// <summary>Aucun rejet.</summary>
    None = 0,

    /// <summary>Signature du manifeste invalide ou clé non reconnue.</summary>
    InvalidSignature = 1,

    /// <summary>Manifeste mal formé ou incomplet.</summary>
    ManifestInvalid = 2,

    /// <summary>Empreinte d'un composant différente de celle du manifeste.</summary>
    HashMismatch = 3,

    /// <summary>Version antérieure à la version installée (downgrade non autorisé).</summary>
    DowngradeNotAllowed = 4,

    /// <summary>Source de téléchargement non approuvée.</summary>
    UntrustedSource = 5,

    /// <summary>Version incompatible avec la configuration installée.</summary>
    IncompatibleVersion = 6
}

/// <summary>
/// Version installée et version disponible d'un composant.
/// </summary>
/// <param name="Kind">Famille du composant.</param>
/// <param name="Name">Nom canonique du composant.</param>
/// <param name="InstalledVersion">Version actuellement installée, ou <see langword="null"/> si absente.</param>
/// <param name="AvailableVersion">Version disponible au dernier contrôle, ou <see langword="null"/> si aucune.</param>
public sealed record UpdateComponentInfoDto(
    UpdateComponentKind Kind,
    string Name,
    string? InstalledVersion,
    string? AvailableVersion);

/// <summary>
/// Résultat d'un contrôle de mises à jour.
/// </summary>
/// <param name="CheckedAtUtc">Horodatage UTC du contrôle.</param>
/// <param name="ManifestVerified">Indique si le manifeste a été reçu et sa signature vérifiée.</param>
/// <param name="Components">État de chaque composant.</param>
/// <param name="Error">Erreur de diagnostic si le contrôle a échoué ou si le manifeste a été rejeté.</param>
public sealed record UpdateCheckResultDto(
    DateTimeOffset CheckedAtUtc,
    bool ManifestVerified,
    IReadOnlyList<UpdateComponentInfoDto> Components,
    DiagnosticErrorDto? Error);

/// <summary>
/// Demande d'installation d'une mise à jour.
/// </summary>
/// <param name="Kind">Famille du composant à mettre à jour.</param>
/// <param name="TargetVersion">Version cible, présente dans un manifeste signé.</param>
public sealed record UpdateInstallRequest(
    UpdateComponentKind Kind,
    string TargetVersion);

/// <summary>
/// Progression d'une mise à jour en cours.
/// </summary>
/// <param name="Kind">Famille du composant concerné.</param>
/// <param name="Status">Étape en cours.</param>
/// <param name="Percent">Avancement de 0 à 100.</param>
public sealed record UpdateProgressDto(
    UpdateComponentKind Kind,
    UpdateStatus Status,
    int Percent);

/// <summary>
/// Résultat d'une installation ou d'un retour arrière.
/// </summary>
/// <param name="Kind">Famille du composant concerné.</param>
/// <param name="Status">État final.</param>
/// <param name="PreviousVersion">Version avant l'opération.</param>
/// <param name="CurrentVersion">Version active après l'opération.</param>
/// <param name="RejectionReason">Motif si la mise à jour a été rejetée.</param>
/// <param name="CompletedAtUtc">Horodatage UTC de fin.</param>
/// <param name="Error">Erreur de diagnostic en cas d'échec ou de rejet.</param>
public sealed record UpdateResultDto(
    UpdateComponentKind Kind,
    UpdateStatus Status,
    string? PreviousVersion,
    string? CurrentVersion,
    UpdateRejectionReason RejectionReason,
    DateTimeOffset CompletedAtUtc,
    DiagnosticErrorDto? Error);

/// <summary>
/// Entrée de l'historique des mises à jour.
/// </summary>
/// <param name="EntryId">Identifiant unique de l'entrée.</param>
/// <param name="TimestampUtc">Horodatage UTC de l'opération.</param>
/// <param name="Kind">Famille du composant.</param>
/// <param name="FromVersion">Version de départ.</param>
/// <param name="ToVersion">Version visée.</param>
/// <param name="Status">État final.</param>
/// <param name="RejectionReason">Motif de rejet éventuel.</param>
public sealed record UpdateHistoryEntryDto(
    Guid EntryId,
    DateTimeOffset TimestampUtc,
    UpdateComponentKind Kind,
    string? FromVersion,
    string ToVersion,
    UpdateStatus Status,
    UpdateRejectionReason RejectionReason);
