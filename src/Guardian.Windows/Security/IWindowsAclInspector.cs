using System.IO.Pipes;
using System.Runtime.Versioning;

namespace Guardian.Windows.Security;

/// <summary>
/// Contrat d'inspection et de durcissement contrôlé des ACL système pour les dossiers et Named Pipes Guardian.
/// </summary>
public interface IWindowsAclInspector
{
    /// <summary>
    /// Audite les permissions NTFS d'un fichier ou répertoire afin de détecter des droits d'écriture accordés aux groupes larges.
    /// </summary>
    /// <param name="path">Chemin du fichier ou du répertoire à auditer.</param>
    /// <returns>Résultat détaillé signalant toute règle trop permissive.</returns>
    AclAuditResult AuditPathAcl(string path);

    /// <summary>
    /// Applique une ACL restrictive sur un répertoire dédié à Guardian (désactive l'héritage et limite aux comptes autorisés).
    /// </summary>
    /// <param name="directoryPath">Chemin du répertoire à durcir.</param>
    /// <param name="includeCurrentUser">Ajoute l'utilisateur courant si nécessaire dans les environnements de test non élevés.</param>
    void ApplyRestrictiveDirectoryAcl(string directoryPath, bool includeCurrentUser = false);

    /// <summary>
    /// Construit une politique de sécurité ACL restrictive pour le serveur Named Pipe local Guardian.
    /// </summary>
    /// <param name="allowCurrentUser">Autorise en lecture/écriture l'identité courante du processus hôte.</param>
    /// <param name="allowAuthenticatedUsers">Autorise en lecture/écriture les utilisateurs locaux authentifiés (ex. UI non élevée).</param>
    /// <returns>Objet <see cref="PipeSecurity"/> configuré avec refus explicite des connexions réseau.</returns>
    [SupportedOSPlatform("windows")]
    PipeSecurity CreateRestrictedPipeSecurity(bool allowCurrentUser = true, bool allowAuthenticatedUsers = false);
}
