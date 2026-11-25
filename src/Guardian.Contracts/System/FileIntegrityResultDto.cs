using Guardian.Contracts.Common;

namespace Guardian.Contracts.System;

/// <summary>
/// Résultat d'une vérification d'intégrité cryptographique et Authenticode sur un fichier.
/// </summary>
/// <param name="FilePath">Chemin du fichier vérifié.</param>
/// <param name="Exists">Indique si le fichier existe au moment du contrôle.</param>
/// <param name="Sha256">Empreinte SHA-256 hexadécimale en minuscules, si calculée.</param>
/// <param name="ExpectedHashMatched">Résultat de la comparaison avec l'empreinte attendue, si fournie.</param>
/// <param name="IsAuthenticodeSigned">Indique si une signature Authenticode a été détectée.</param>
/// <param name="IsSignatureValid">Indique si la validation de signature système a réussi.</param>
/// <param name="SignerSubject">Sujet du certificat signataire, le cas échéant.</param>
/// <param name="TrustStatusCode">Code de retour brut de l'API de vérification de confiance Windows.</param>
/// <param name="Availability">Statut de disponibilité de la vérification Authenticode.</param>
/// <param name="Summary">Résumé lisible du contrôle d'intégrité.</param>
public sealed record FileIntegrityResultDto(
    string FilePath,
    bool Exists,
    string? Sha256,
    bool? ExpectedHashMatched,
    bool IsAuthenticodeSigned,
    bool IsSignatureValid,
    string? SignerSubject,
    int? TrustStatusCode,
    FeatureAvailabilityStatus Availability,
    string Summary);
