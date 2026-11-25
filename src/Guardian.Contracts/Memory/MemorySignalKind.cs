namespace Guardian.Contracts.Memory;

/// <summary>
/// Nature d'un signal défensif observé lors de l'inspection des métadonnées mémoire d'un processus.
/// </summary>
public enum MemorySignalKind
{
    /// <summary>
    /// Page mémoire privée et commise disposant de droits d'exécution.
    /// </summary>
    PrivateExecutableRegion = 0,

    /// <summary>
    /// Page mémoire privée disposant simultanément des droits lecture, écriture et exécution (RWX).
    /// </summary>
    ReadWriteExecuteRegion = 1,

    /// <summary>
    /// Région exécutable non associée à une image disque connue.
    /// </summary>
    UnbackedExecutableRegion = 2,

    /// <summary>
    /// Module chargé dont la signature Authenticode est absente ou invalide.
    /// </summary>
    UnsignedLoadedModule = 3,

    /// <summary>
    /// Indicateur observable de mécanisme de hook ou d'injection défensivement repéré.
    /// </summary>
    SuspiciousHookIndicator = 4,

    /// <summary>
    /// Processus système ou sensible exclu délibérément de l'inspection mémoire pour protéger la confidentialité.
    /// </summary>
    ProtectedProcessSkipped = 5
}
