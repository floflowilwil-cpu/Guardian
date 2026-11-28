namespace Guardian.Contracts.Quarantine;

/// <summary>
/// Isolation, restauration et suppression de fichiers dangereux.
/// La décision d'agir appartient à la politique de sécurité, pas à ce service.
/// </summary>
public interface IQuarantineService
{
    /// <summary>Chiffre le fichier, le conserve en quarantaine puis supprime l'original.</summary>
    Task<QuarantineItem> QuarantineAsync(
        QuarantineRequest request,
        CancellationToken cancellationToken = default);

    Task<IReadOnlyList<QuarantineItem>> ListAsync(
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Restaure l'élément après vérification d'intégrité. Retourne le chemin restauré.
    /// Refuse d'écraser un fichier existant.
    /// </summary>
    Task<string> RestoreAsync(
        Guid id,
        string? destinationPath = null,
        CancellationToken cancellationToken = default);

    /// <summary>Supprime définitivement l'élément de la quarantaine.</summary>
    Task DeleteAsync(
        Guid id,
        CancellationToken cancellationToken = default);
}