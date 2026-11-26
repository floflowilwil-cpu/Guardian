namespace Guardian.Signatures;

internal static class Sha256Format
{
    private const int HexLength = 64;

    public static bool IsValid(string? value)
    {
        if (value is null || value.Length != HexLength)
        {
            return false;
        }

        foreach (char c in value)
        {
            if (!char.IsAsciiHexDigit(c))
            {
                return false;
            }
        }

        return true;
    }
}
