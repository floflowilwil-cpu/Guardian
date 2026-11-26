namespace Guardian.Contracts.System;

/// <summary>
/// Contrat du moniteur système en lecture seule (processus, services, persistance, posture et intégrité).
/// </summary>
/// <remarks>
/// <para><b>Privilèges :</b> fonctionne en utilisateur standard avec dégradation explicite des informations nécessitant élévation.</para>
/// <para><b>Sécurité Windows :</b> strictement passif ; ne désactive ni ne modifie Defender, le pare-feu ou l'UAC.</para>
/// </remarks>
public interface ISystemMonitor
{
    /// <summary>
    /// Démarre la surveillance système et ses capteurs passifs.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    Task StartAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Arrête proprement la surveillance système.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    Task StopAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Inventorie les processus actifs et, si demandé, leurs modules accessibles.
    /// </summary>
    /// <param name="includeModules">Indique s'il faut tenter d'inventorier les modules chargés.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Liste des processus observés avec leur statut d'accès explicite.</returns>
    Task<IReadOnlyList<ProcessInfoDto>> GetProcessesAsync(bool includeModules = false, CancellationToken cancellationToken = default);

    /// <summary>
    /// Inventorie les services Windows configurés sur la machine.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Liste des services Windows observés.</returns>
    Task<IReadOnlyList<WindowsServiceInfoDto>> GetServicesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Collecte les points de démarrage et de persistance observables.
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Liste des entrées de démarrage inventoriées.</returns>
    Task<IReadOnlyList<StartupEntryDto>> GetStartupEntriesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Lit l'état des mécanismes de sécurité natifs Windows (Defender, pare-feu, UAC, Secure Boot, TPM, VBS, LSASS).
    /// </summary>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Instantané de posture sécurité accompagné de recommandations.</returns>
    Task<WindowsSecurityPostureDto> GetSecurityPostureAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Vérifie l'intégrité cryptographique et la signature Authenticode d'un fichier donné.
    /// </summary>
    /// <param name="filePath">Chemin du fichier à contrôler.</param>
    /// <param name="expectedSha256">Empreinte SHA-256 attendue optionnelle.</param>
    /// <param name="cancellationToken">Jeton d'annulation.</param>
    /// <returns>Résultat détaillé du contrôle d'intégrité.</returns>
    Task<FileIntegrityResultDto> VerifyFileIntegrityAsync(string filePath, string? expectedSha256 = null, CancellationToken cancellationToken = default);
}
