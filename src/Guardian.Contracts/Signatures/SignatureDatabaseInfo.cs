namespace Guardian.Contracts.Signatures;

/// <summary>Informations sur la base de signatures chargée (affichées dans « Définitions »).</summary>
public sealed record SignatureDatabaseInfo(
    string Version,
    DateTime GeneratedAtUtc,
    int SignatureCount);

/// <summary>Expose la version de la base de signatures.</summary>
public interface ISignatureDatabaseInfoProvider
{
    /// <summary>Retourne null si la provenance de la base est inconnue.</summary>
    SignatureDatabaseInfo? GetDatabaseInfo();
}
