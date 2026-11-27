# Guardian.SystemMonitor — Surveillance Système, Comportementale et Scripts Service

**Module :** `Guardian.SystemMonitor` (et extensions `Guardian.Windows.Tasks`, `Guardian.Service`, `scripts/windows-service/`)  
**Responsable :** Développeur 4 (John)  
**Cible :** .NET 10 (`net10.0`) sur Windows 10/11 x64

Ce document décrit l'architecture du module `Guardian.SystemMonitor`, ses capteurs différentiels passifs, ses garanties strictes de confidentialité (aucune capture de frappe ni lecture de secrets), son intégration dans `Guardian.Service`, ainsi que les scripts d'installation et de désinstallation administrateur.

---

## 1. Vue d'ensemble et contrats implémentés

- **`SystemMonitorService`** (`src/Guardian.SystemMonitor/SystemMonitorService.cs`) implémente conjointement :
  - `ISystemMonitor` : cycle de vie `StartAsync` / `StopAsync` et inventaires en lecture seule (`GetProcessesAsync`, `GetServicesAsync`, `GetStartupEntriesAsync` incluant registre + dossiers de démarrage + tâches planifiées, `GetSecurityPostureAsync`, `VerifyFileIntegrityAsync`).
  - `IBehaviorMonitor` : diffusion temps réel (`EventDetected`) et consultation en mémoire bornée (`GetRecentEventsAsync`).
- Les capteurs travaillent en **mode différentiel** : le premier cycle établit une référence silencieuse afin d'éviter un flot de fausses alertes au démarrage du service.

---

## 2. Capteurs différentiels et détections implémentées

| Capteur / Traceur | Source de données | Événements émis (`SystemEventCategory`) | Gravité typique |
|---|---|---|---|
| `ProcessActivityTracker` | `IWindowsProcessAdapter` (`CreateToolhelp32Snapshot`, `QueryFullProcessImageNameW`) | `ProcessLifecycle`, `InterProcessAccess` | `High` si filiation Office/navigateur → script/LOLBin ou DLL chargée depuis Temp/Public ; `Medium` si exécutable dans Temp/Public |
| `ProcessActivityTracker` (mémoire) | `IWindowsMemoryAdapter` (`VirtualQueryEx` uniquement, zéro `PROCESS_VM_READ`, exclusion `lsass`) | `InterProcessAccess` | `High` (`ReadWriteExecuteRegion`, `UnbackedExecutableRegion`, `SuspiciousHookIndicator`), `Medium` (`PrivateExecutableRegion`, `UnsignedLoadedModule`) avec cooldown dédupliqué |
| `PersistenceChangeTracker` | `IWindowsRegistryAdapter` + `IWindowsScheduledTaskAdapter` + `IWindowsServiceAdapter` | `RegistryModification`, `PersistenceChange` | `High` pour `Winlogon` / `ImageFileExecutionOptions` / modification de binaire service ; `Medium` pour `Run`, `RunOnce`, `ScheduledTask`, `StartupFolder` |
| `SecurityPostureChangeTracker` | `IWindowsSecurityPostureReader` (lecture seule) | `SecurityPostureChange` | `High` si Microsoft Defender, pare-feu Windows, UAC ou protection LSASS est affaibli ou désactivé ; `Info` lors d'un rétablissement |
| `FileBurstDetector` + `DirectoryBurstSensor` | `FileSystemWatcher` sur métadonnées/horodatages uniquement | `FileBurstAnomaly` | `High` si le seuil d'opérations dans la fenêtre glissante est dépassé |
| `RemovableDriveTracker` | `IRemovableDriveProvider` (`DriveInfo.DriveType == Removable`) | `UsbDeviceEvent` | `Info` (montage) / `Low` (retrait) |

---

## 3. Inventaire des tâches planifiées (`WindowsScheduledTaskAdapter`)

- Inspecte `%SystemRoot%\System32\Tasks` en lecture seule avec plafond de taille (`256 Kio` par XML) et plafond d'entrées (`500`).
- Le parseur XML interdit explicitement toute résolution de DTD (`DtdProcessing.Prohibit`, `XmlResolver = null`) afin de bloquer toute attaque XXE.
- Extrait les actions `<Exec>` (`<Command>` + `<Arguments>`) sans exécuter aucune commande ni modifier le planificateur Windows.

---

## 4. Transparence ETW vs repli Win32 (`WindowsEtwCapabilityProbe`)

- `WindowsEtwCapabilityProbe` évalue l'OS et les privilèges effectifs :
  - Sous Windows non élevé : expose `FeatureAvailabilityStatus.RequiresElevation` (les traces noyau/ETW complètes nécessitent un privilège Administrateur ou `LocalSystem` et `Microsoft-Windows-Threat-Intelligence` reste réservé PPL/ELAM) et bascule de façon transparente vers les capteurs différentiels Win32 + `FileSystemWatcher`.
  - Sous Windows élevé (`LocalSystem` en service) : expose `FeatureAvailabilityStatus.Available` pour les fournisseurs ETW user-mode standards en complément des capteurs Win32.
  - Hors Windows : expose `FeatureAvailabilityStatus.Unavailable`.

---

## 5. Garanties de confidentialité et durcissement

- **Aucun enregistrement de frappe clavier ni d'entrée utilisateur :** aucune importation des APIs `SetWindowsHookEx*`, `GetAsyncKeyState`, `GetKeyState` ou `RegisterRawInputDevices` (vérifié automatiquement dans `SystemMonitorSecurityTests`).
- **Aucun contenu de fichier ni secret collecté :** `DirectoryBurstSensor` enregistre uniquement l'horodatage et le type d'événement ; `BoundedSystemEventStore` supprime systématiquement toute clé de métadonnée contenant `password`, `secret`, `privatekey`, `keystroke` ou `token` et borne la mémoire en anneau FIFO (`MaxRetainedEvents`).
- **Coexistence Windows stricte :** `Guardian.SystemMonitor` observe Defender, le pare-feu Windows et l'UAC en lecture seule sans jamais les affaiblir.

---

## 6. Intégration dans `Guardian.Service` et IPC

- `SystemMonitorHostWorker` démarre et arrête `SystemMonitorService` avec l'hôte Windows Service, émet des heartbeats vers `IGuardianHealthService` sous l'identifiant canonique `Guardian.SystemMonitor`, et implémente `IMonitoredComponent` pour le redémarrage borné par `GuardianWatchdogService`.
- Nouvelles commandes IPC authentifiées sur `NamedPipeIpcServer` (`IpcCommandType`) :
  - `GetRecentSystemEvents` : retourne les événements comportementaux récents (bornés à 100 max) ;
  - `RunMemoryAnalysis` : déclenche l'inspection défensive d'un PID cible ou des processus accessibles (troncature contrôlée sous `IpcMaxMessageBytes`).
- Les clients peuvent appeler `NamedPipeIpcClient.GetRecentSystemEventsAsync(...)` et `NamedPipeIpcClient.RunMemoryAnalysisAsync(...)`.

---

## 7. Scripts PowerShell d'administration du service (`scripts/windows-service/`)

Conformément aux limites d'éthique et de gouvernance (aucune dissimulation ni résistance à une désinstallation administrateur légitime) :

- **`Install-GuardianService.ps1`** *(Administrateur requis, `-WhatIf` supporté)* : crée l'arborescence `%ProgramData%\Guardian\{config,data,quarantine,signatures,models,logs,backup}` avec ACL restrictives (`SYSTEM` + `Administrators`), enregistre ou met à jour le service `GuardianService` (`start= delayed-auto`), et configure la récupération SCM bornée (`sc.exe failure reset= 600 actions= restart/5000/restart/15000/restart/30000`).
- **`Uninstall-GuardianService.ps1`** *(Administrateur requis, `-WhatIf` supporté)* : arrête proprement `GuardianService`, le supprime du SCM (`sc.exe delete`) et supprime éventuellement le dossier de données uniquement si `-PurgeData` est passé.
- **`Get-GuardianServiceStatus.ps1`** *(lecture seule sans élévation)* : affiche l'état SCM du service, sa politique de récupération et la présence du Named Pipe `\\.\pipe\Guardian.Service.Ipc.v1`.
