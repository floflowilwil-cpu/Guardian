# Guardian.Service — Architecture du Service Windows, Watchdog, Intégrité et IPC

**Module :** `Guardian.Service`  
**Responsable :** Développeur 4 (John)  
**Cible :** .NET 10 (`net10.0`) sur Windows 10/11 x64  

Ce document décrit l'architecture interne du service résident `Guardian.Service`, sa gestion d'état de santé, son watchdog anti-boucle, son auto-intégrité, son canal IPC local authentifié et sa coordination des analyses de fichiers.

---

## 1. Cycle de vie Windows Service et mode autonome

- **`GuardianWindowsServiceLifetime`** (`src/Guardian.Service/Hosting/GuardianWindowsServiceLifetime.cs`) :
  - Détecte si l'exécutable est démarré par le Service Control Manager (SCM) Windows en session 0 non interactive (`IsRunningAsWindowsService()`).
  - En mode service Windows, communique nativement avec `advapi32.dll` (`StartServiceCtrlDispatcherW`, `RegisterServiceCtrlHandlerExW`, `SetServiceStatus`) sans dépendance NuGet externe, gérant `SERVICE_START_PENDING`, `SERVICE_RUNNING`, `SERVICE_STOP_PENDING` et `SERVICE_STOPPED`.
  - En mode console ou dans les tests d'intégration, bascule proprement sur le cycle de vie console standard, sans aucune dépendance à l'interface WPF `Guardian.Desktop`.
- **`GuardianCoreHostWorker`** (`src/Guardian.Service/Hosting/GuardianCoreHostWorker.cs`) :
  - Inspecte l'environnement et le niveau de privilège au démarrage (`IWindowsPrivilegeInspector`).
  - Émet un heartbeat régulier (`HeartbeatIntervalSeconds`, 5 s par défaut) et publie explicitement l'état `Stopped` lors de l'arrêt propre.

---

## 2. Santé vérifiable et transparence (`GuardianHealthService`)

- Implémente `IGuardianHealthService` (`src/Guardian.Service/Health/GuardianHealthService.cs`).
- Expose exclusivement les cinq états de la spécification : `Unknown`, `Healthy`, `Degraded`, `Stopped`, `OutOfDate`.
- **Garantie d'honnêteté :**
  - Si un composant requis (`Guardian.Service.Host`, `Guardian.Service.Watchdog`, `Guardian.Service.SelfIntegrity`, `Guardian.Service.Ipc`) est absent, arrêté ou dégradé, l'état global passe immédiatement à `Degraded` (ou `Stopped` si l'hôte est arrêté).
  - Si le dernier heartbeat d'un composant dépasse `HeartbeatStaleThresholdSeconds` (20 s par défaut), il est automatiquement reclassé en `Degraded` avec la raison exacte dans `DegradedReasons`.

---

## 3. Watchdog anti-boucle (`WatchdogTracker` & `GuardianWatchdogService`)

- Surveille les `IMonitoredComponent` enregistrés (dont `NamedPipeIpcServer`).
- En cas de défaillance ou d'expiration de heartbeat, autorise un redémarrage automatique **borné** dans une fenêtre glissante (`WatchdogMaxRestartsInWindow = 3` sur `WatchdogRestartWindowMinutes = 10`).
- Dès que la limite est atteinte, ouvre le disjoncteur (`CircuitBreakerOpen = true`), stoppe toute boucle de redémarrage, journalise en `LogCritical` et bascule le service en `Degraded`.
- Aucune dissimulation ni résistance à une désinstallation administrateur légitime.

---

## 4. Auto-intégrité (`SelfIntegrityMonitor` & `SelfIntegrityWorker`)

- Au démarrage, capture une baseline SHA-256 des binaires Guardian surveillés via `IWindowsAuthenticodeVerifier`.
- Vérifie périodiquement (`IntegrityCheckIntervalMinutes`) :
  - absence de modification SHA-256, de suppression ou de binaire intrus dans le répertoire surveillé ;
  - validité des signatures Authenticode lorsque `RequireSignedBinaries = true` ;
  - permissions NTFS restrictives du répertoire de données via `IWindowsAclInspector.AuditPathAcl`.
- Toute anomalie bascule `Guardian.Service.SelfIntegrity` en `Degraded` avec la liste détaillée dans `Anomalies`.

---

## 5. Canal IPC local authentifié (`NamedPipeIpcServer`)

- **Transport :** Named Pipe local `Guardian.Service.Ipc.v1` (`IpcProtocolConstants.DefaultPipeName`).
- **ACLs Windows :** `WindowsAclInspector.CreateRestrictedPipeSecurity` autorise `LocalSystem`, `BuiltinAdministrators` et les comptes locaux configurés (`AllowNonAdminInteractiveIpc` pour l'UI WPF non élevée), tout en ajoutant un `Deny NetworkSid` explicite.
- **Protection mémoire (`IpcFraming`) :** lit d'abord la longueur sur 4 octets little-endian et rejette immédiatement toute trame négative ou supérieure à `IpcMaxMessageBytes` (256 Kio) **avant** d'allouer le tampon.
- **Anti-rejeu (`IpcReplayGuard`) :** vérifie que `TimestampUtc` est dans la fenêtre `±IpcReplayWindowSeconds` (60 s) et que le couple `(RequestId, Nonce)` n'a jamais été consommé.
- **Identité & Audit (`IpcClientIdentityReader` & `IpcRequestDispatcher`) :** extrait le compte, le SID, le PID et le statut administrateur côté serveur ; applique la liste blanche stricte `IpcCommandType` (aucune commande shell) ; journalise les commandes exécutées sans jamais journaliser de données sensibles ni de payload brut.

---

## 6. Orchestration des scans et coexistence Windows

- `ScanExecutionCoordinator` héberge `IScanOrchestrator` (`Guardian.Scanner` + `InMemorySignatureProvider` + `HeuristicAnalyzer`) et expose `StartScan` (`Quick`, `Full` sur tous les disques fixes, `Custom`), `GetScanStatus` et `CancelScan` via IPC.
- **Coexistence Windows :** `Guardian.Service` observe la posture native (Defender, pare-feu, UAC, Secure Boot, TPM, VBS, Credential Guard, LSASS) en lecture seule via `IWindowsSecurityPostureReader` et ne désactive jamais Microsoft Defender ni aucune défense Windows.
