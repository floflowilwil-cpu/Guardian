namespace Guardian.Signatures;

/// <summary>Fichier de signatures invalide, corrompu ou non supporté.</summary>
public sealed class SignatureFormatException : Exception
{
    public SignatureFormatException(string message)
        : base(message)
    {
    }

    public SignatureFormatException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}