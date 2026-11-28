using System.Security.Cryptography;
using System.Text;

namespace Guardian.Desktop.Services;

/// <summary>
/// Identifiant stable d'une menace : dérivé du SHA-256 du fichier et de son chemin.
/// Il ne change pas d'un rafraîchissement à l'autre (la sélection dans la liste est conservée)
/// et reste unique si le même fichier existe à deux endroits.
/// </summary>
internal static class ThreatId
{
    public static Guid From(string? sha256, string? path)
    {
        var key = (sha256 ?? string.Empty).Trim().ToLowerInvariant() + "|" + (path ?? string.Empty).Trim().ToLowerInvariant();
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(key));
        return new Guid(hash.AsSpan(0, 16));
    }
}
