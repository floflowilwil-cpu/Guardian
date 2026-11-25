# Contrats communs — Service Windows, Surveillance Système, Mémoire et IPC

**Module :** `Guardian.Contracts`  
**Version des contrats :** `1.0`  
**Responsable :** Développeur 4 (John), en coordination avec Développeur 5 (Ange) et l'équipe  

Ce document spécifie les contrats publics partagés relatifs à la santé du service résident, à la surveillance système en lecture seule, à l'analyse défensive des métadonnées mémoire et au protocole IPC local authentifié.

---

## 1. Règles transverses des contrats

- **Aucune dépendance circulaire :** `Guardian.Contracts` ne référence aucun autre projet de la solution ni paquet tiers.
- **Vie privée stricte :** aucun DTO ne transporte de mot de passe, secret utilisateur, clé privée, jeton d'authentification ou frappe clavier.
- **Transparence :** les statuts utilisent exclusivement les valeurs exactes définies par la spécification (`Healthy`, `Degraded`, `Stopped`, `OutOfDate`, `Unknown`) et indiquent explicitement toute restriction liée aux privilèges ou à l'édition Windows (`FeatureAvailabilityStatus`).
- **Annulation & délais :** toutes les méthodes asynchrones acceptent un `CancellationToken` et doivent respecter les timeouts définis par l'appelant ou par `IpcProtocolConstants.DefaultTimeout`.

---

## 2. Santé et Watchdog (`Guardian.Contracts.Health`)

### Interface : `IGuardianHealthService`
- **But :** publier et agréger de manière vérifiable la santé de chaque composant ainsi que les battements (`heartbeat`) du service résident.
- **DTOs :**
  - `GuardianHealthSnapshot` : état global agrégé, horodatage UTC, version du service, rapports individuels (`ComponentHealthReport`), liste `DegradedReasons`, et état éventuel du watchdog (`WatchdogSnapshot`).
  - `ComponentHealthReport` : nom canonique, `GuardianHealthStatus`, résumé, dernier heartbeat, `FeatureAvailabilityStatus`, motifs et privilège requis.
  - `WatchdogSnapshot` / `WatchdogComponentStateDto` : suivi des redémarrages bornés dans la fenêtre et état du disjoncteur (`CircuitBreakerOpen`).
- **Règles d'erreurs & résilience :** toute absence, panne ou expiration de heartbeat d'un composant requis doit basculer `OverallStatus` vers `Degraded` (ou `Stopped` si l'hôte est arrêté), jamais vers `Healthy`.
- **Privilèges :** écriture réservée aux composants internes du service ; lecture exposée via IPC aux clients locaux autorisés.
- **Audit :** les transitions vers `Degraded`/`Stopped` et les ouvertures de disjoncteur doivent être journalisées sans données sensibles.

---

## 3. Surveillance système (`Guardian.Contracts.System`)

### Interface : `ISystemMonitor`
- **But :** inventorier de façon strictement passive les processus, services Windows, points de démarrage/persistance, posture de sécurité Windows et intégrité de fichiers.
- **DTOs :**
  - `ProcessInfoDto` et `LoadedModuleDto`
  - `WindowsServiceInfoDto` (`WindowsServiceState`, `WindowsServiceStartMode`)
  - `StartupEntryDto` (`PersistenceEntryKind`)
  - `WindowsSecurityPostureDto` et `SecurityControlStatusDto` (Defender, pare-feu, UAC, Secure Boot, TPM, VBS, Credential Guard, protection LSASS)
  - `FileIntegrityResultDto`
- **Privilèges & mode dégradé :** fonctionne sans privilèges administrateur ; les objets protégés (ex. processus PPL ou clés restreintes) retournent `FeatureAvailabilityStatus.RequiresElevation` ou `Degraded` sans lever d'exception globale.
- **Limites :** lecture seule absolue — aucun affaiblissement ni modification de Defender, du pare-feu ou de l'UAC.

### Interface : `IBehaviorMonitor`
- **But :** collecter et diffuser des signaux comportementaux corrélés (`SystemSecurityEventDto`, `SystemEventCategory`, `EventSeverity`).
- **Vie privée :** aucune capture clavier/souris ni lecture de contenu privé de documents.

---

## 4. Analyse défensive mémoire (`Guardian.Contracts.Memory`)

### Interface : `IMemoryAnalyzer`
- **But :** détecter des indicateurs structurels sur les plages mémoire (pages privées exécutables, pages RWX, modules non signés) à partir des seules métadonnées OS.
- **DTOs :** `MemoryAnalysisReportDto`, `MemoryRegionSignalDto`, `MemorySignalKind`.
- **Règles de sécurité et vie privée :**
  - Interdiction absolue d'utiliser `PROCESS_VM_READ` ou d'extraire des secrets en mémoire.
  - Exclusion obligatoire des processus critiques d'identifiants (`lsass`, etc.), signalés explicitement avec `MemorySignalKind.ProtectedProcessSkipped`.

---

## 5. Protocole IPC local (`Guardian.Contracts.Ipc`)

### Interface : `IIpcRequestDispatcher`
- **But :** valider et exécuter les commandes typées reçues via Named Pipes locaux (`IpcProtocolConstants.DefaultPipeName`).
- **DTOs :** `IpcRequest`, `IpcResponse`, `IpcClientContext`, `IpcCommandType`, `IpcErrorCode`.
- **Contraintes de sécurité :**
  - Version de protocole vérifiée (`IpcProtocolConstants.ProtocolVersion = "1.0"`).
  - Taille maximale bornée (`DefaultMaxMessageBytes = 262144` octets) vérifiée avant allocation.
  - Timeout par défaut (`10 s`) et annulation propagée.
  - Liste blanche stricte `IpcCommandType` (aucune commande shell générique).
  - Codes d'erreur typés (`InvalidProtocolVersion`, `PayloadTooLarge`, `ReplayDetected`, `Unauthorized`, `UnknownCommand`, etc.).
  - Identité Windows cliente authentifiée via `IpcClientContext` (`IdentityName`, `SecurityIdentifier`, `ClientProcessId`, `IsAdministrator`).
  - Audit de chaque opération reçue sans journalisation de données sensibles.
