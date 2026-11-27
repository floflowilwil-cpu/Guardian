namespace Guardian.Contracts.Network;

/// <summary>
/// Observation d'une requête DNS, sans contenu autre que le nom demandé et le résultat.
/// </summary>
/// <param name="ObservationId">Identifiant unique de l'observation.</param>
/// <param name="ObservedAtUtc">Horodatage UTC de la requête.</param>
/// <param name="QueryName">Nom de domaine demandé.</param>
/// <param name="RecordType">Type d'enregistrement demandé (ex. <c>A</c>, <c>AAAA</c>, <c>TXT</c>).</param>
/// <param name="Succeeded">Indique si la résolution a abouti.</param>
/// <param name="ResolvedAddresses">Adresses obtenues, vide en cas d'échec.</param>
/// <param name="ProcessId">Processus à l'origine de la requête, si connu.</param>
/// <param name="ProcessName">Nom du processus à l'origine de la requête, si connu.</param>
public sealed record DnsObservationDto(
    Guid ObservationId,
    DateTimeOffset ObservedAtUtc,
    string QueryName,
    string RecordType,
    bool Succeeded,
    IReadOnlyList<string> ResolvedAddresses,
    int? ProcessId,
    string? ProcessName);

/// <summary>
/// Métadonnées TLS visibles passivement. Guardian ne déchiffre pas le trafic et ne lit pas le contenu HTTPS.
/// </summary>
/// <param name="ServerName">Nom de serveur indiqué (SNI), si visible.</param>
/// <param name="TlsVersion">Version du protocole TLS négociée, si visible.</param>
/// <param name="CertificateSubject">Sujet du certificat présenté, si visible.</param>
/// <param name="CertificateIssuer">Émetteur du certificat présenté, si visible.</param>
/// <param name="CertificateSha256Fingerprint">Empreinte SHA-256 du certificat, en hexadécimal.</param>
/// <param name="NotBeforeUtc">Début de validité du certificat.</param>
/// <param name="NotAfterUtc">Fin de validité du certificat.</param>
/// <param name="IsSelfSigned">Indique si le certificat est auto-signé, ou <see langword="null"/> si inconnu.</param>
/// <param name="IsExpired">Indique si le certificat est expiré, ou <see langword="null"/> si inconnu.</param>
public sealed record TlsMetadataDto(
    string? ServerName,
    string? TlsVersion,
    string? CertificateSubject,
    string? CertificateIssuer,
    string? CertificateSha256Fingerprint,
    DateTimeOffset? NotBeforeUtc,
    DateTimeOffset? NotAfterUtc,
    bool? IsSelfSigned,
    bool? IsExpired);

/// <summary>
/// Réputation d'une adresse ou d'un domaine telle qu'évaluée par une source identifiée.
/// </summary>
/// <param name="Verdict">Verdict de réputation.</param>
/// <param name="Score">Score de 0 (sûr) à 100 (très risqué), ou <see langword="null"/> si non fourni.</param>
/// <param name="Source">Nom de la source de réputation (ex. liste locale, fournisseur de mises à jour).</param>
public sealed record NetworkReputationDto(
    NetworkReputation Verdict,
    int? Score,
    string Source);
