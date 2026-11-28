using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace Guardian.Quarantine;

/// <summary>Protège les clés de chiffrement stockées avec les éléments en quarantaine.</summary>
public interface IKeyProtector
{
    byte[] Protect(byte[] data);

    byte[] Unprotect(byte[] protectedData);
}

/// <summary>Protection par DPAPI (portée machine). Windows uniquement.</summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiKeyProtector : IKeyProtector
{
    private static readonly byte[] Entropy = "Guardian.Quarantine.v1"u8.ToArray();

    public byte[] Protect(byte[] data) =>
        ProtectedData.Protect(data, Entropy, DataProtectionScope.LocalMachine);

    public byte[] Unprotect(byte[] protectedData) =>
        ProtectedData.Unprotect(protectedData, Entropy, DataProtectionScope.LocalMachine);
}