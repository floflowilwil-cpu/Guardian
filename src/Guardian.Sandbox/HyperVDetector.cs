using System.Runtime.Versioning;
using Microsoft.Win32;

namespace Guardian.Sandbox;

public enum HyperVState
{
    NotWindows = 0,
    NotInstalled = 1,
    Installed = 2
}

/// <summary>Détecte la présence de Hyper-V sur la machine.</summary>
public interface IHyperVDetector
{
    HyperVState Detect();
}

/// <summary>
/// Détection par la présence du service de gestion Hyper-V (vmms).
/// Sa présence ne prouve ni que la virtualisation matérielle est activée,
/// ni qu'une image de base est prête : elle sert à donner une raison utile à l'utilisateur.
/// </summary>
public sealed class RegistryHyperVDetector : IHyperVDetector
{
    private const string VmmsServiceKey = @"SYSTEM\CurrentControlSet\Services\vmms";

    public HyperVState Detect()
    {
        if (!OperatingSystem.IsWindows())
        {
            return HyperVState.NotWindows;
        }

        return DetectOnWindows();
    }

    [SupportedOSPlatform("windows")]
    private static HyperVState DetectOnWindows()
    {
        try
        {
            using RegistryKey? key = Registry.LocalMachine.OpenSubKey(VmmsServiceKey);
            return key is null ? HyperVState.NotInstalled : HyperVState.Installed;
        }
        catch (Exception ex) when (ex is System.Security.SecurityException
                                      or UnauthorizedAccessException
                                      or IOException)
        {
            return HyperVState.NotInstalled;
        }
    }
}
