# Guardian.Data — Base SQLite locale

**Module :** `Guardian.Data`
**Responsable :** Développeur 5 (Ange)
**Relecture :** consommateurs de la base (migrations SQLite)

## 1. Choix technique

`Microsoft.Data.Sqlite` avec scripts SQL de migration écrits à la main (ni EF Core ni Dapper).
Raisons : peu de dépendances, requêtes toujours paramétrées, schéma lisible et relisible en revue.

### Sécurité de la dépendance SQLite
`Microsoft.Data.Sqlite` embarque par défaut un SQLite natif antérieur à 3.50.2, concerné par l'avis
GHSA-2m69-gcr7-jv3q (CVE-2025-6965, corruption mémoire sur requête d'agrégation forgée).
Guardian force `SQLitePCLRaw.lib.e_sqlite3` en 3.50.3 (référence directe dans `Guardian.Data.csproj`).
Guardian n'exécute de toute façon que ses propres requêtes paramétrées sur un fichier local.
La CI échoue si un paquet vulnérable réapparaît. Réévaluer cette épingle à chaque mise à jour de `Microsoft.Data.Sqlite`.

## 2. Emplacement

`%ProgramData%\Guardian\data\guardian.db`. La source unique des chemins est `IWindowsPrivilegeInspector.GetStandardPaths()`
(Guardian.Windows) : `Guardian.Data` n'a aucun chemin par défaut et reçoit le sien du service.
`GuardianService:DataDirectoryOverride` (tests, déploiements particuliers) remplace le dossier, pas le nom du fichier.

## 3. Conventions de stockage

- Dates : texte UTC ISO 8601 à largeur fixe (`yyyy-MM-ddTHH:mm:ss.fffffffZ`), triables lexicalement.
- Identifiants : `Guid` en texte (format `D`).
- Énumérations : entiers (valeurs stables des contrats).
- Tables `STRICT`, clés étrangères actives sur chaque connexion, journal WAL.
- Aucun mot de passe, secret, clé privée, jeton ni frappe clavier dans aucune colonne.

## 4. Migrations

- Scripts `Migrations/NNN_nom.sql`, embarqués dans l'assembly.
- Appliqués dans l'ordre, chacun dans une transaction, par `MigrationRunner`.
- Une migration déjà appliquée **ne se modifie jamais** : son empreinte SHA-256 est contrôlée. Pour changer le schéma, ajouter une nouvelle migration.
- Une base plus récente que l'application est refusée.

### Ajouter une migration
1. Créer `Migrations/002_description.sql` (numéro suivant, tiret bas, nom court).
2. Écrire uniquement des changements de schéma ou de données, compatibles avec la version précédente quand c'est possible.
3. Ajouter un test dans `tests/Guardian.IntegrationTests/Data/`.
4. Demander la relecture des développeurs qui consomment les tables concernées.

## 5. Tables (v1)

`ScanJobs`, `ScanItems`, `Threats`, `ThreatEvidence`, `QuarantineItems`, `SystemEvents`, `NetworkEvents`,
`PolicyDecisions`, `Signatures`, `ModelVersions`, `UpdateHistory`, `Exclusions`, `Settings`, `AuditEvents`,
`HealthChecks`, `SandboxRuns`.

Les tables `ScanJobs`, `ScanItems`, `QuarantineItems`, `PolicyDecisions`, `Signatures`, `ModelVersions`,
`Exclusions`, `Settings`, `HealthChecks` et `SandboxRuns` ont un schéma minimal : leurs propriétaires les
étendent par de nouvelles migrations lorsque leurs contrats sont définis.

## 6. Dépôts fournis

| Contrat | Implémentation | Tables |
|---|---|---|
| `IThreatRepository` | `SqliteThreatRepository` | `Threats`, `ThreatEvidence` |
| `IEventRepository` | `SqliteEventRepository` | `SystemEvents`, `NetworkEvents`, `AuditEvents` |

- Événements système et réseau : colonnes d'index (date, gravité, etc.) plus la charge utile JSON complète du DTO.
- `AuditEvents` : ajout seul. Un déclencheur SQL refuse toute modification ; la suppression passe uniquement par `PurgeOlderThanAsync(..., includeAudit: true)`.
- Pagination plafonnée à 1000 éléments.

## 7. Intégration dans le service

`Program.cs` appelle `services.AddGuardianDataStorage()` après `AddGuardianServiceCore(...)`. Cela enregistre :

- les dépôts (`IThreatRepository`, `IEventRepository`) et `MigrationRunner` ;
- `GuardianDataHostWorker`, composant de démarrage **surveillé par le watchdog** (nom de composant : `Guardian.Data`).

Déroulement au démarrage :
1. Si le dossier de données n'existe pas, il est créé avec une **ACL restrictive** (`IWindowsAclInspector.ApplyRestrictiveDirectoryAcl`).
   Un dossier déjà présent est laissé tel quel : l'auto-vérification d'intégrité en audite les droits.
2. Les migrations sont appliquées, puis une sonde `SELECT 1` valide l'accès à la base.
3. Le composant publie sa santé et un battement de cœur régulier (`HeartbeatIntervalSeconds`).

En cas d'échec, le service **continue de tourner** : `Guardian.Data` passe en `Degraded` (donc la santé globale aussi),
le détail technique reste dans les journaux, et le watchdog relance l'initialisation dans la limite de son plafond de redémarrages.
`Guardian.Data` n'est pas dans `RequiredComponents` par défaut.

`AddGuardianDataStorage` n'est volontairement pas appelé par `AddGuardianServiceCore` : les tests du service qui utilisent
un dossier de données inexistant ne créent donc pas de base.
