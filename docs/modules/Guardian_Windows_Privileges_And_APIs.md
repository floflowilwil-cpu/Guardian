# Guardian.Windows — Privilèges, APIs Win32 et comportement dégradé

**Module :** `Guardian.Windows`  
**Responsable :** Développeur 4 (John)  
**Cible :** .NET 10 (`net10.0`) sur Windows 10/11 x64  

Ce document décrit les adaptateurs système de `Guardian.Windows`, les APIs Windows utilisées, les privilèges minimaux exigés, le fonctionnement en mode non élevé et les garde-fous de confidentialité.

---

## 1. Principes de sécurité et limites

- **100 % user-mode :** aucun pilote noyau personnalisé ni chargement non signé.
- **Lecture seule sur la sécurité native :** Guardian observe Microsoft Defender, le pare-feu Windows, l'UAC, Secure Boot, TPM, VBS, Credential Guard et LSASS sans jamais les désactiver ou les contourner.
- **Zéro collecte de secrets ou frappes :** aucun hook clavier/souris, aucun appel à `PROCESS_VM_READ`, aucune ouverture de `lsass`, `csrss`, `smss`, `wininit`, `services`, `registry`, `system` ou `idle`.
- **Transparence multiplateforme :** tous les appels Windows sont gardés par `OperatingSystem.IsWindows()` et retournent un statut explicite (`FeatureAvailabilityStatus`) en cas d'indisponibilité ou de droit insuffisant.

---

## 2. Inventaire des adaptateurs et APIs utilisées

| Adaptateur | APIs / Mécanismes | Privilège minimal | Mode dégradé (sans admin / hors Windows) |
|---|---|---|---|
| `WindowsPrivilegeInspector` | `WindowsIdentity`, `WindowsPrincipal`, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`, `Environment.SpecialFolder` | Utilisateur standard | Si registre restreint : édition marquée `Unknown (RequiresElevation)`. Hors Windows : `IsWindows = false`. |
| `WindowsRegistryAdapter` | `Microsoft.Win32.RegistryKey` (ouverture `writable: false`), dossiers `Startup` et `CommonStartup` | Utilisateur standard (`HKCU` et majorité `HKLM`) | Toute sous-clé protégée retourne `FeatureAvailabilityStatus.RequiresElevation` sans faire échouer le reste de l'inventaire. |
| `WindowsServiceAdapter` | `advapi32.dll` (`OpenSCManagerW`, `EnumServicesStatusExW`, `OpenServiceW`, `QueryServiceConfigW`, `QueryServiceStatusEx`, `CloseServiceHandle`) | `SC_MANAGER_ENUMERATE_SERVICE`, `SERVICE_QUERY_STATUS` | Pour les services protégés refusant `SERVICE_QUERY_CONFIG`, retourne quand même `State` et `ProcessId` avec `StartMode = Unknown`. |
| `WindowsAclInspector` | `DirectoryInfo.GetAccessControl` / `SetAccessControl`, `PipeSecurity`, `SecurityIdentifier` | Propriétaire du dossier ou Administrateur | Refuse explicitement la racine lecteur, `%SystemRoot%`, `System32` et `%ProgramFiles%` racine. Ajoute un `Deny NetworkSid` sur le Named Pipe. |
| `WindowsAuthenticodeVerifier` | `SHA256.HashDataAsync`, `CryptographicOperations.FixedTimeEquals`, `wintrust.dll` (`WinVerifyTrust`, `CryptCATAdmin*`), `crypt32.dll` (`CryptQueryObject`, `CertGetNameStringW`) | Utilisateur standard | Fonctionne hors ligne (`WTD_REVOCATION_CHECK_NONE`). Vérifie d'abord la signature intégrée, puis les catalogues Windows. |
| `WindowsSecurityPostureReader` | Composition en lecture seule de `IWindowsPrivilegeInspector`, `IWindowsRegistryAdapter`, `IWindowsServiceAdapter` | Utilisateur standard | Toute clé inaccessible bascule uniquement le contrôle concerné vers `RequiresElevation` ou `Unavailable`. |
| `WindowsProcessAdapter` | `CreateToolhelp32Snapshot`, `Process32FirstW`/`NextW`, `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, `QueryFullProcessImageNameW` | Utilisateur standard (sessions locales) | Les processus PPL/système refusant `PROCESS_QUERY_LIMITED_INFORMATION` ou `Process.Modules` retournent `AccessStatus = RequiresElevation`. |
| `WindowsMemoryAdapter` | `OpenProcess(PROCESS_QUERY_INFORMATION)` + `VirtualQueryEx` uniquement (métadonnées pages mémoire x64) | Utilisateur standard (propres processus) / Admin pour certains processus | Exclusion absolue avant `OpenProcess` de `lsass` et processus critiques (`ProtectedProcessSkipped`). Jamais de `PROCESS_VM_READ`. |

---

## 3. Chemins standards résolus (`GuardianPaths`)

Conformément à la section 13.1 de la documentation technique :
- `%ProgramFiles%\Guardian\` (binaires)
- `%ProgramData%\Guardian\config\`
- `%ProgramData%\Guardian\data\guardian.db`
- `%ProgramData%\Guardian\quarantine\`
- `%ProgramData%\Guardian\signatures\`
- `%ProgramData%\Guardian\models\`
- `%ProgramData%\Guardian\logs\`
- `%ProgramData%\Guardian\backup\`
- `%LocalAppData%\Guardian\` (préférences UI)
