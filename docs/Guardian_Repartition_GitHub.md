# GUARDIAN
## Répartition des responsabilités, règles GitHub et plan de collaboration — Version 3.0

**Projet :** Guardian — sécurité endpoint Windows  
**Équipe :** 5 développeurs  
**Technologie :** C# / .NET 10 LTS / WPF / SQLite / ML.NET / ONNX Runtime  
**Référence technique :** `Guardian_Documentation_Technique_v3.md`

---

# 1. Objectif de l'équipe

Construire Guardian comme une application complète dès sa première version fonctionnelle : interface WPF, service Windows résident, moteurs antivirus, surveillance système et réseau, IA locale, agent gouverné, sandbox isolée, quarantaine, mises à jour, installation, tests et documentation.

Les cinq développeurs possèdent des domaines principaux distincts. Les contrats communs, la sécurité et l'intégration sont collectifs.

**Règle : chaque développeur travaille dans sa branche et propose une Pull Request. Il peut fusionner sa propre PR uniquement après approbation obligatoire d'un autre développeur et réussite de la CI.** Personne ne pousse directement sur `main` ou `develop`.

---

# 2. Répartition des cinq développeurs

## 2.1 Développeur 1 — Florent : IA, détection intelligente et agent

**Responsabilité :** moteur d'intelligence artificielle et corrélation intelligente.

### Périmètre
- `Guardian.AI`
- modèles ONNX / ML.NET ;
- classification de fichiers ;
- détection d'anomalies ;
- score de risque et calibration ;
- explication des facteurs de détection ;
- analyse prédictive prudente ;
- corrélation des signaux ;
- mémoire locale des indicateurs et incidents ;
- graphe de relations et timeline assistée ;
- assistant IA local, en coordination avec Alexia ;
- détection des attaques contre les modèles : prompt injection, data poisoning, entrées adversariales, extraction abusive et jailbreak ;
- pipeline d'évaluation, versionnement et validation des modèles ;
- apprentissage continu gouverné et rollback.

### Livrables
- projet `Guardian.AI` ;
- interfaces d'inférence et de scoring ;
- modèles et fiches de modèle ;
- jeux de tests versionnés ;
- rapports de précision, rappel, F1, calibration et faux positifs ;
- documentation des caractéristiques utilisées ;
- tests de robustesse et de performance.

### Limites de responsabilité
- le modèle ne lance pas de commandes arbitraires ;
- il ne supprime ni ne met en quarantaine directement ;
- il ne collecte pas de frappe clavier, de contenu privé ou de secrets ;
- il ne s'entraîne pas librement sur les fichiers privés ;
- toute action passe par `Guardian.Policy`.

### Branches types
`feature/florent-ai-classifier`, `feature/florent-risk-engine`, `feature/florent-threat-graph`.

---

## 2.2 Développeur 2 — Alexia : interface WPF et expérience utilisateur

**Responsabilité :** application graphique complète et parcours utilisateur.

### Périmètre
- `Guardian.Desktop`
- architecture MVVM ;
- tableau de bord ;
- scans et progression ;
- résultats et preuves ;
- quarantaine et restauration ;
- centre de notifications ;
- historique et rapports ;
- vue réseau et connexions ;
- état de santé des moteurs ;
- paramètres, exclusions et planification ;
- assistant conversationnel local ;
- graphe de menaces et timeline ;
- vues sandbox ;
- mode silencieux ;
- mode hors ligne ;
- accessibilité, thèmes et localisation.

### Livrables
- application WPF complète ;
- composants réutilisables ;
- ViewModels et services UI ;
- tests UI pertinents ;
- guide visuel et documentation des parcours.

### Limites
- aucune opération privilégiée directement dans l'interface ;
- appels au service via IPC et contrats ;
- aucune logique critique de détection dans les ViewModels ;
- affichage fidèle des états `Healthy`, `Degraded`, `Stopped`, `OutOfDate`, `Unknown`.

### Branches types
`feature/alexia-dashboard`, `feature/alexia-scan-ui`, `feature/alexia-threat-center`.

---

## 2.3 Développeur 3 — Iness : scan, signatures, quarantaine et sandbox

**Responsabilité :** analyse des fichiers et remédiation contrôlée.

### Périmètre
- `Guardian.Scanner`
- `Guardian.Signatures`
- `Guardian.Quarantine`
- `Guardian.Sandbox`
- scan rapide, complet et personnalisé ;
- hash et signatures ;
- analyse statique et heuristique ;
- inspection des types de fichiers ;
- analyse des archives avec limites ;
- détection des extensions trompeuses ;
- détection de macros/scripts suspects ;
- quarantaine chiffrée et ACL restrictives ;
- restauration contrôlée ;
- suppression après confirmation et politique ;
- orchestrateur de sandbox VM jetable ;
- gestion des snapshots et artefacts de sandbox ;
- exclusions auditées ;
- progression, annulation et reprise.

### Livrables
- moteurs de scan ;
- base de signatures locale et format de mise à jour ;
- quarantaine testée ;
- adaptateur sandbox ;
- corpus de tests inoffensifs ;
- documentation des formats et limites.

### Limites
- aucun fichier inconnu n'est exécuté sur l'hôte de production ;
- l'analyse dynamique se fait dans un environnement isolé ;
- aucun effacement de composant système sur le seul score IA ;
- toute remédiation est gouvernée par `Guardian.Policy`.

### Branches types
`feature/iness-scanner`, `feature/iness-quarantine`, `feature/iness-sandbox`.

---

## 2.4 Développeur 4 — John : service Windows, surveillance et sécurité système

**Responsabilité :** exécution résidente et observation défensive du système.

### Périmètre
- `Guardian.Service`
- `Guardian.SystemMonitor`
- `Guardian.Windows`
- démarrage automatique ;
- arrêt propre et récupération ;
- watchdog et heartbeat ;
- état de santé ;
- collecte ETW et API Windows documentées ;
- inventaire processus, modules, services et tâches ;
- surveillance registre et persistance ;
- événements de démarrage ;
- analyse défensive de mémoire ;
- détection d'injection et d'accès interprocessus suspects ;
- détection de mécanismes de keylogging sans capturer les frappes ;
- état LSASS/PPL/Credential Guard ;
- intégrité des composants ;
- coexistence Defender, pare-feu et UAC ;
- intégration éventuelle d'un pilote défensif signé comme projet séparé, après décision d'architecture.

### Livrables
- service Windows ;
- moniteurs système ;
- adaptateurs Win32/ETW ;
- watchdog ;
- install/uninstall scripts en coordination ;
- tests d'intégration Windows ;
- documentation des privilèges et API utilisées.

### Limites
- aucun enregistrement clavier/souris ;
- aucune extraction de mot de passe ou de secret ;
- aucune désactivation Defender/UAC/pare-feu ;
- aucun driver non signé, furtif ou non validé ;
- aucun mécanisme empêchant la désinstallation administrateur légitime.

### Branches types
`feature/john-windows-service`, `feature/john-system-monitor`, `feature/john-memory-signals`.

---

## 2.5 Développeur 5 — Ange : réseau, données, infrastructure et livraison

**Responsabilité :** services transversaux, réseau, stockage et intégration.

### Périmètre
- `Guardian.Network`
- `Guardian.Data`
- `Guardian.Infrastructure`
- `Guardian.Updater`
- `Guardian.Contracts` avec validation collective ;
- SQLite et migrations ;
- journalisation et audit ;
- configuration ;
- IPC local et contrats de communication en coordination avec John ;
- inventaire des connexions réseau ;
- inspection DNS et réputation ;
- détection C2 basée sur métadonnées et indicateurs ;
- métadonnées TLS sans déchiffrement généralisé ;
- ARP et anomalies réseau selon données disponibles ;
- règles Windows Firewall/WFP avec autorisation ;
- mise à jour signée des moteurs, modèles et règles ;
- packaging, CI, installateur et désinstallateur ;
- tests end-to-end et coordination de version.

### Livrables
- base de données et migrations ;
- couche réseau ;
- pipeline de mise à jour ;
- infrastructure et IPC ;
- workflows GitHub Actions ;
- scripts de packaging ;
- documentation schéma, réseau et livraison.

### Limites
- pas de collecte du contenu privé réseau ;
- pas d'interception TLS silencieuse ;
- pas de désactivation du pare-feu ;
- aucune mise à jour non authentifiée ;
- aucun secret ou certificat privé dans Git.

### Branches types
`feature/ange-network-monitor`, `feature/ange-data-layer`, `feature/ange-updater`.

---

# 3. Responsabilités partagées

| Sujet | Responsable principal | Relecteur obligatoire |
|---|---|---|
| Contrats communs | Ange + équipe | Tous les développeurs concernés |
| Politique de sécurité | Florent + John | Iness et Ange |
| Quarantaine | Iness | John |
| IPC/service | John + Ange | Un troisième développeur |
| Assistant IA | Florent + Alexia | John |
| Sandbox | Iness | John |
| Réseau et règles firewall | Ange | John |
| Migrations SQLite | Ange | Consommateurs des données |
| Installation/désinstallation | John + Ange | Alexia |
| CI et qualité | Ange | Tous |
| Documentation globale | Tous | Responsable de domaine |

Un changement de contrat public doit être annoncé avant implémentation et validé par les consommateurs concernés.

---

# 4. Contrats communs obligatoires

À définir dans `Guardian.Contracts` avant le développement parallèle :

- `IFileScanner`
- `IScanOrchestrator`
- `ISignatureProvider`
- `IHeuristicAnalyzer`
- `IBehaviorMonitor`
- `IThreatClassifier`
- `IRiskScorer`
- `IPolicyEngine`
- `IQuarantineService`
- `ISystemMonitor`
- `IMemoryAnalyzer`
- `INetworkMonitor`
- `ISandboxOrchestrator`
- `IThreatRepository`
- `IEventRepository`
- `IUpdateService`
- `INotificationService`
- `IGuardianHealthService`

Chaque contrat documente : but, DTO, erreurs, annulation, timeout, privilèges, données sensibles, journalisation, version et tests de contrat.

Les DTO ne transportent jamais de mots de passe, jetons, clés privées ou frappes clavier.

---

# 5. Organisation GitHub

## 5.1 Branches

- `main` : version stable, protégée ;
- `develop` : intégration continue, protégée ;
- `feature/<dev>-<module>-<sujet>` : fonctionnalité ;
- `fix/<module>-<sujet>` : correction ;
- `refactor/<module>-<sujet>` : refactorisation ;
- `docs/<sujet>` : documentation ;
- `test/<module>-<sujet>` : tests ;
- `release/<version>` : préparation d'une version ;
- `hotfix/<sujet>` : correction urgente issue de `main`.

Exemples :
- `feature/florent-ai-classifier`
- `feature/alexia-dashboard`
- `feature/iness-quarantine`
- `feature/john-windows-service`
- `feature/ange-network-monitor`

## 5.2 Règle de fusion : chacun merge sa PR

Chaque développeur :
1. crée sa branche depuis `develop` ;
2. développe dans son périmètre ;
3. ajoute tests et documentation ;
4. lance build et tests ;
5. synchronise sa branche avec `develop` ;
6. pousse sa branche ;
7. ouvre une PR vers `develop` ;
8. demande une approbation d'un autre développeur ;
9. corrige les commentaires ;
10. attend la CI verte ;
11. fusionne lui-même sa PR après approbation ;
12. supprime sa branche après fusion.

**L'auteur de la PR ne peut pas approuver sa propre PR.** « Chacun merge » signifie que chaque développeur est responsable de la fusion de sa PR après revue indépendante ; cela ne signifie pas qu'il peut s'auto-approuver.

Pour les composants sensibles (`Service`, `Policy`, `Quarantine`, `Updater`, `Network`), une revue supplémentaire d'un développeur compétent sur le sujet est exigée.

## 5.3 Commandes de départ

```bash
git clone <URL_DU_DEPOT>
cd Guardian
git switch develop
git pull origin develop
git switch -c feature/florent-ai-classifier
```

Avant de pousser :

```bash
git status
dotnet restore
dotnet build
dotnet test
git fetch origin
git rebase origin/develop
git push -u origin feature/florent-ai-classifier
```

Après fusion :

```bash
git switch develop
git pull origin develop
git branch -d feature/florent-ai-classifier
```

Ne jamais utiliser `git push --force` sur `main` ou `develop`. Si une branche personnelle doit être réécrite après rebase, utiliser `--force-with-lease` uniquement si autorisé par l'équipe.

## 5.4 Protection des branches GitHub

Sur `main` et `develop` :
- interdire les push directs ;
- exiger une Pull Request ;
- exiger au moins une approbation d'un autre membre ;
- exiger les checks CI ;
- exiger la résolution des conversations ;
- interdire force-push et suppression ;
- exiger une branche à jour avant merge ;
- activer Dependabot et secret scanning ;
- limiter les permissions des workflows.

## 5.5 Convention de commits

Format : `type(scope): description courte`

Types :
- `feat` fonctionnalité ;
- `fix` correction ;
- `docs` documentation ;
- `test` tests ;
- `refactor` restructuration ;
- `build` dépendances/construction ;
- `ci` pipeline ;
- `security` durcissement.

Exemples :
```text
feat(scanner): add full scan orchestration
fix(quarantine): validate restore destination
docs(architecture): describe service boundaries
test(ai): add model threshold tests
security(updater): verify package signature
```

## 5.6 Modèle de Pull Request

```markdown
## Objectif
Quel besoin cette PR résout-elle ?

## Changements
- ...
- ...

## Tests
- [ ] dotnet restore
- [ ] dotnet build
- [ ] dotnet test
- [ ] tests d'intégration concernés

## Sécurité
- [ ] Aucun secret ajouté
- [ ] Entrées validées
- [ ] Actions privilégiées typées et contrôlées
- [ ] Journaux sans données sensibles
- [ ] Aucun affaiblissement des défenses Windows
- [ ] Pas de régression connue

## Compatibilité
- [ ] Contrats publics respectés
- [ ] Migration SQLite si nécessaire
- [ ] Documentation mise à jour
- [ ] Mode dégradé géré
```

---

# 6. Règles de collaboration

1. Les contrats sont validés avant les développements parallèles.
2. Toute modification d'un contrat passe par PR.
3. Aucun développeur ne modifie directement la branche de travail d'un autre.
4. Les conflits sont résolus manuellement et compris.
5. Chaque fonctionnalité comprend des tests.
6. Les API publiques sont documentées en XML.
7. Aucun secret, token, certificat privé ou donnée personnelle ne doit être commité.
8. Les dépendances NuGet sont justifiées, centralisées et surveillées.
9. Les changements SQLite utilisent des migrations.
10. Les PR sont petites et focalisées.
11. Les revues vérifient sécurité, maintenabilité, tests et compatibilité.
12. Chaque développeur met à jour la documentation de son module.
13. Toute fonction dépendante d'une édition Windows ou d'un privilège l'indique clairement.
14. Les erreurs et indisponibilités sont remontées, jamais masquées.
15. Les fonctionnalités IA ne contournent jamais le moteur de politiques.

---

# 7. Définition de « terminé »

Une tâche est terminée lorsque :
- le code compile ;
- les tests unitaires et d'intégration concernés passent ;
- les erreurs, timeouts et annulations sont gérés ;
- les privilèges sont documentés ;
- les logs ne divulguent aucune donnée sensible ;
- le contrat est respecté ;
- la documentation est mise à jour ;
- l'état de santé est observable ;
- la PR a été approuvée par une autre personne ;
- la CI est verte ;
- la PR a été fusionnée ;
- aucune régression connue n'est laissée sans ticket.

---

# 8. Ordre d'intégration

Cet ordre organise les dépendances, sans réduire le produit à un MVP.

1. Dépôt, SDK, conventions et solution.
2. Contrats communs et DTO.
3. Infrastructure, configuration, logs et SQLite.
4. Service Windows, IPC, watchdog et santé.
5. Scanner, signatures, heuristiques et quarantaine.
6. Moteur de politiques et agent.
7. IA locale, score, explications et assistant.
8. Surveillance système, mémoire et démarrage.
9. Réseau, DNS, réputation et pare-feu.
10. Sandbox VM.
11. Interface WPF complète.
12. Mise à jour, installateur et désinstallateur.
13. Tests de sécurité, performance et compatibilité.
14. Signature et livraison.

---

# 9. Synchronisation de l'équipe

- point quotidien court : terminé, à faire, blocage ;
- revue hebdomadaire des contrats ;
- démonstration à chaque jalon intégré ;
- GitHub Projects : `Backlog`, `Ready`, `In progress`, `Review`, `Done`, `Blocked` ;
- chaque ticket possède un responsable, des critères d'acceptation et les tests attendus ;
- toute dépendance entre développeurs est inscrite dans le ticket.

---

# 10. Critères d'acceptation du projet

Guardian est prêt pour une livraison candidate lorsque :
- les cinq domaines fonctionnent ensemble par contrats documentés ;
- le service fonctionne sans ouvrir WPF ;
- l'interface affiche l'état réel ;
- scans rapides, complets et personnalisés sont exécutables ;
- les menaces de test sont détectées et tracées ;
- la quarantaine et la restauration sont sûres ;
- les décisions automatiques respectent les politiques ;
- la surveillance système et réseau est disponible sur les plateformes annoncées ;
- les mises à jour sont authentifiées ;
- l'installation et la désinstallation sont testées ;
- les pannes produisent un état dégradé explicite ;
- les tests sécurité et intégration sont reproductibles ;
- les limites et fonctions indisponibles sont visibles et documentées.

---

# 11. Responsabilité collective

Chaque développeur est responsable de la qualité de son module, mais la sécurité de Guardian est collective. Une fonctionnalité ne doit jamais être fusionnée uniquement parce qu'elle compile : elle doit respecter les contrats, les privilèges minimaux, la vie privée, les tests et les limites décrites dans la documentation technique.
