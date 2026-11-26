namespace Guardian.Contracts.System;

/// <summary>
/// Décrit un module (DLL ou exécutable) chargé dans l'espace d'un processus observé.
/// </summary>
/// <param name="ModuleName">Nom du module chargé.</param>
/// <param name="FilePath">Chemin complet sur disque lorsqu'il est accessible.</param>
/// <param name="BaseAddress">Adresse de base du module en mémoire.</param>
/// <param name="MemorySizeBytes">Taille mappée du module en octets.</param>
/// <param name="IsSigned">Indique si la signature Authenticode du fichier est valide, si vérifiée.</param>
public sealed record LoadedModuleDto(
    string ModuleName,
    string? FilePath,
    long BaseAddress,
    int MemorySizeBytes,
    bool? IsSigned = null);
