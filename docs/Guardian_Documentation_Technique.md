# GUARDIAN
## Documentation fonctionnelle, technique et sécurité — Version 3.0

**Produit :** Guardian — plateforme de protection endpoint Windows  
**Langage principal :** C#  
**Interface :** WPF / MVVM  
**Runtime cible :** .NET 10 LTS (à confirmer sur le poste et à épingler dans `global.json`)  
**Stockage :** SQLite  
**IA locale :** ML.NET et ONNX Runtime  
**Plateforme :** Windows 10/11 x64  
**Équipe :** 5 développeurs  
**Statut :** spécification de référence avant implémentation

> Cette documentation vise une application complète dès la première version fonctionnelle. « Complète » signifie que tous les domaines fonctionnels sont prévus dans l'architecture et que les fonctions annoncées disposent d'un périmètre, d'un contrat, d'un test et d'un état de disponibilité vérifiable. Cela ne signifie pas que toutes les fonctions peuvent être activées sur chaque édition de Windows, ni qu'une protection absolue est possible.

---

# 1. Vision et objectifs

Guardian est un agent de sécurité endpoint pour Windows, composé d'un service résident, de moteurs de détection, d'un moteur de politiques, d'une IA locale, d'une couche réseau, d'une quarantaine et d'une interface WPF.

Il doit :
- démarrer avec Windows et fonctionner sans fenêtre ouverte ;
- surveiller les événements système pertinents en continu ;
- analyser les fichiers à la demande et à l'accès lorsque les mécanismes Windows disponibles le permettent ;
- détecter les menaces connues et suspectes par signatures, heuristiques, réputation, comportement et modèles ML ;
- corréler les signaux fichiers, processus, registre, démarrage, mémoire et réseau ;
- bloquer, contenir ou mettre en quarantaine les menaces selon une politique explicite ;
- fournir une explication lisible, un historique, des preuves et une restauration contrôlée ;
- protéger ses propres composants contre l'altération non autorisée ;
- fonctionner hors ligne pour les fonctions locales ;
- conserver une coexistence sûre avec Microsoft Defender.

## 1.1 Positionnement

Guardian est un produit de sécurité endpoint indépendant. Il peut fournir des fonctions de prévention, de détection, de réponse locale et d'investigation. Il ne doit pas se présenter comme un remplacement certifié de Microsoft Defender, un EDR/XDR d'entreprise certifié, un SIEM ou une solution de sécurité certifiée tant que les certifications, validations et intégrations correspondantes ne sont pas réellement obtenues.

## 1.2 Principes non négociables

1. Défense en profondeur : aucune détection ne dépend d'un seul moteur.
2. Moindre privilège : chaque processus ne reçoit que les droits nécessaires.
3. Transparence : l'interface expose l'état réel des composants.
4. Réversibilité : quarantaine et restauration avant suppression irréversible.
5. Explicabilité : chaque décision conserve ses facteurs et ses preuves.
6. Sécurité du système : Guardian ne désactive pas les défenses Windows.
7. Vie privée : aucune collecte de frappes, contenu privé ou secret utilisateur.
8. Contrôle : les actions privilégiées sont typées, journalisées et gouvernées par une politique.
9. Résilience : panne d'un module = état dégradé explicite, pas faux état « protégé ».
10. Mesurabilité : les taux de faux positifs, faux négatifs, latence et consommation sont mesurés.

---

# 2. Périmètre et clarification des capacités sensibles

Les capacités ci-dessous sont traitées comme des objectifs défensifs. Certaines sont intégrables directement en C# avec les API Windows documentées ; d'autres nécessitent des composants signés, des droits élevés, une validation indépendante ou une édition Windows compatible. Les fonctions de surveillance intrusive ou d'extraction de secrets ne font pas partie du produit.

## 2.1 Capacités système avancées retenues

| Domaine demandé | Décision de conception Guardian | Limites et conditions |
|---|---|---|
| Driver noyau personnalisé | Architecture extensible pour un éventuel pilote défensif signé, minimal, audité et distribué selon les exigences Microsoft | Pas de pilote maison non signé, pas de contournement de Secure Boot, pas de chargement furtif. Le cœur V1 fonctionne sans pilote propriétaire. |
| Inspection TLS | Analyse DNS, IP, ports, SNI/certificat lorsque visible, réputation, volumes, fréquence et métadonnées de flux | Pas de déchiffrement TLS généralisé ni d'interception silencieuse. Une inspection TLS d'entreprise ne peut exister que comme intégration proxy explicite, administrée et consentie. |
| Détection de keyloggers | Détection défensive de mécanismes de capture : inventaire des modules, hooks documentés observables, signatures, comportements, événements et alertes | Guardian ne collecte ni n'enregistre les frappes clavier/souris. |
| Protection des secrets | Détection des tentatives d'accès anormales aux processus sensibles, contrôle de l'état LSASS/PPL/Credential Guard et recommandations de durcissement | Guardian ne lit, n'extrait, ne stocke ni n'affiche les mots de passe, jetons ou clés privées. |
| Defender / pare-feu / UAC | Surveillance de leur état et alerte si une configuration est affaiblie ; recommandations de restauration | Aucun affaiblissement, désactivation ou contournement. Toute modification passe par l'administrateur et les interfaces Windows prévues. |
| Analyse dynamique de fichiers inconnus | Exécution uniquement dans une VM/sandbox jetable, isolée et restaurable, ou analyse statique sans exécution | Aucun lancement d'échantillon inconnu sur l'hôte de production. |
| Zero-days | Détection probabiliste d'anomalies, exploitation suspecte, comportements et indicateurs inconnus | Aucune promesse de détecter tous les zero-days. |
| Apprentissage continu | Apprentissage contrôlé, opt-in, données validées, environnement d'entraînement séparé, modèle évalué puis signé | Aucun apprentissage autonome direct à partir des fichiers privés ou événements bruts de l'utilisateur. |
| Remédiation automatique | Blocage/isolement réversible et nettoyage de mécanismes de persistance précisément identifiés | Pas de suppression irréversible de composants système sur la seule base d'une prédiction IA. |

## 2.2 Modèle d'intégration noyau

Le produit est conçu pour fonctionner en user-mode au premier démarrage. Un futur pilote éventuel est un sous-système isolé :
- code minimal en C/C++ selon le modèle de pilote Windows approprié ;
- signature et distribution conformes aux exigences Microsoft ;
- revue de sécurité indépendante ;
- tests en VM, tests de stabilité et procédure de désinstallation ;
- communication avec le service via un protocole versionné et ACL strictes ;
- aucun accès noyau arbitraire depuis l'interface ;
- désactivation contrôlée et documentée en cas d'incompatibilité.

Le pilote n'est pas une dépendance obligatoire du moteur de scan, de la base SQLite ou de l'interface.

## 2.3 Modèle d'analyse réseau et TLS

Guardian collecte des métadonnées réseau utiles à la défense : processus associé quand disponible, IP, port, protocole, DNS, horodatage, volume, fréquence, réputation, certificats et attributs TLS visibles. Les données de contenu ne sont pas collectées par défaut. Une intégration proxy TLS d'entreprise, si elle est développée plus tard, doit être explicite, documentée, limitée à un parc administré et respecter les obligations légales et de confidentialité.

## 2.4 Modèle de protection contre les keyloggers et le vol d'identifiants

Guardian détecte des indices de capture clavier ou de vol d'identifiants sans observer les frappes :
- inventaire des modules et processus ;
- détection de comportements d'injection et d'accès anormal aux processus ;
- contrôle des protections Windows disponibles (LSASS protection, Credential Guard, Secure Boot) ;
- alertes sur les outils et comportements de dumping mémoire ;
- corrélation avec les connexions réseau et la persistance ;
- recommandations de durcissement.

## 2.5 Analyse dynamique et sandbox

La sandbox est un environnement séparé, jetable et restaurable :
- VM Hyper-V ou environnement d'analyse dédié ;
- réseau désactivé par défaut ou simulé ;
- snapshots avant/après ;
- limites CPU, mémoire, durée, disque et nombre de processus ;
- aucun dossier hôte partagé en écriture ;
- collecte d'artefacts limitée et contrôlée ;
- destruction/restauration de l'environnement après analyse.

La simulation IA seule ne remplace pas une exécution instrumentée : elle estime des comportements possibles à partir des caractéristiques observées et affiche un niveau d'incertitude.

## 2.6 Promesses interdites

Guardian ne doit jamais annoncer « protection à 100 % », « détecte tous les virus », « protège contre tous les zero-days », « IA infaillible » ou « système sécurisé » lorsqu'un moteur essentiel est indisponible. L'état « protégé » n'est affiché que si les composants requis sont opérationnels et à jour.

---

# 3. Catalogue fonctionnel complet

## 3.1 Antivirus classique

| ID | Fonction | Spécification |
|---|---|---|
| AV-01 | Scan rapide | Zones sensibles, démarrage, emplacements temporaires, processus et éléments récemment modifiés selon permissions |
| AV-02 | Scan complet | Analyse des volumes sélectionnés, avec exclusions système justifiées et progression |
| AV-03 | Scan personnalisé | Fichiers, dossiers, volumes et périphériques sélectionnés |
| AV-04 | Protection temps réel | Surveillance de création, modification, accès et téléchargement via API Windows disponibles |
| AV-05 | Signatures | Hash, règles YARA compatibles si retenues, signatures locales signées et versionnées |
| AV-06 | Heuristique statique | Type réel, en-têtes, imports, métadonnées, entropie, macros et indicateurs suspects |
| AV-07 | Analyse comportementale | Corrélation d'événements processus/fichiers/registre/réseau |
| AV-08 | Ransomware | Détection de rafales de modifications, renommages, suppressions, entropie et accès atypiques |
| AV-09 | Quarantaine | Stockage non exécutable, ACL restrictives, chiffrement, hash et journal |
| AV-10 | Remédiation | Blocage ou quarantaine selon politique ; suppression finale après validation |
| AV-11 | Historique | Scans, alertes, actions, résultats, erreurs et versions moteur |
| AV-12 | USB | Détection de montage, scan à la connexion, autorun et raccourcis suspects |
| AV-13 | Démarrage | Contrôle des tâches planifiées, services, Run keys, Startup folders et boot chain observable |
| AV-14 | Mises à jour | Signatures, moteur, règles, modèles, manifestes et rollback |
| AV-15 | Nettoyage | Remédiation d'artefacts confirmés, sauvegarde/restauration lorsque possible |

## 3.2 Protection web, messagerie et réseau

- réputation URL et domaine ;
- détection de domaines récemment créés ou ressemblant à des marques ;
- blocage/avertissement phishing via extension ou intégration navigateur explicitement installée ;
- analyse des téléchargements avant ouverture ;
- analyse des pièces jointes lorsqu'elles sont accessibles par une intégration autorisée ou lors de leur enregistrement local ;
- inventaire des connexions par processus ;
- inspection DNS et détection d'anomalies ;
- détection de communications C2 à partir d'indicateurs, réputation, périodicité et corrélation ;
- analyse des métadonnées TLS sans déchiffrement généralisé ;
- détection ARP spoofing sur le réseau local lorsque les données sont accessibles ;
- carte des connexions actives ;
- règles de filtrage via Windows Firewall/WFP selon les API et droits supportés ;
- journalisation et expiration des règles temporaires.

## 3.3 Couche système avancée

- inventaire de processus, modules, services et tâches planifiées ;
- surveillance des clés de registre critiques ;
- détection de persistance ;
- détection d'injection de processus à partir de signaux observables ;
- analyse mémoire défensive : régions exécutables anormales, modules non associés, pages privées exécutables, indicateurs de code fileless, sans extraction de secrets ;
- contrôle de l'intégrité de fichiers système par comparaison aux catalogues/hash/signatures de confiance ;
- inventaire de l'état Secure Boot, TPM, VBS, Credential Guard et protection LSASS ;
- surveillance des modifications UEFI/boot lorsque les API autorisées le permettent ;
- vérification des paramètres Defender, pare-feu et UAC en lecture seule ;
- détection d'altération de Guardian ;
- watchdog de disponibilité, redémarrage du service et diagnostic ;
- protection contre les arrêts non autorisés par ACL/service control et politiques Windows, sans mécanisme furtif ni blocage de désinstallation administrateur légitime.

## 3.4 Intelligence artificielle et agent

- classification de fichiers ;
- détection d'anomalies ;
- score de risque calibré ;
- explication des facteurs ;
- analyse prédictive prudente ;
- corrélation multi-sources ;
- mémoire locale des indicateurs et incidents ;
- graphe fichiers-processus-registre-réseau ;
- timeline forensique ;
- assistant conversationnel local ;
- mode adaptatif ;
- sandbox instrumentée et estimation IA ;
- apprentissage continu gouverné ;
- détection des attaques contre les modèles IA : prompt injection dans les métadonnées, data poisoning, adversarial inputs, extraction abusive de modèle et contournement des garde-fous.

L'IA est un moteur d'évaluation. Elle ne reçoit jamais un accès arbitraire au système et ne lance pas de commandes libres.

## 3.5 Administration et UX

- tableau de bord ;
- état de protection par moteur ;
- centre de notifications ;
- analyses planifiées ;
- paramètres et profils ;
- gestion des exclusions avec portée, expiration et audit ;
- gestion de quarantaine ;
- rapports PDF/JSON/CSV ;
- mode silencieux qui réduit les notifications sans désactiver les protections ;
- mode hors ligne ;
- assistant local ;
- accessibilité, thèmes et localisation ;
- export de diagnostics expurgés des données sensibles.

---

# 4. Architecture logique

## 4.1 Vue d'ensemble

```text
Guardian.Desktop (WPF / MVVM)
        │ IPC local authentifié
        ▼
Guardian.Service (Windows Service)
        │
        ├── Guardian.Policy       Décisions et règles
        ├── Guardian.Scanner      Orchestration des analyses
        ├── Guardian.Signatures   Définitions et réputation locale
        ├── Guardian.Quarantine   Isolation et restauration
        ├── Guardian.AI           Classification, score, explications
        ├── Guardian.SystemMonitor Processus, registre, démarrage, intégrité
        ├── Guardian.Network      DNS, connexions, métadonnées et règles
        ├── Guardian.Sandbox      Orchestration VM/sandbox isolée
        ├── Guardian.Data         SQLite et migrations
        ├── Guardian.Updater      Mises à jour authentifiées
        └── Guardian.Infrastructure Journalisation, config, crypto, OS
```

## 4.2 Projets de la solution

```text
Guardian/
├── global.json
├── Directory.Build.props
├── Directory.Packages.props
├── Guardian.sln
├── src/
│   ├── Guardian.Desktop/
│   ├── Guardian.Service/
│   ├── Guardian.Contracts/
│   ├── Guardian.Core/
│   ├── Guardian.Policy/
│   ├── Guardian.Scanner/
│   ├── Guardian.Signatures/
│   ├── Guardian.Quarantine/
│   ├── Guardian.AI/
│   ├── Guardian.SystemMonitor/
│   ├── Guardian.Network/
│   ├── Guardian.Sandbox/
│   ├── Guardian.Data/
│   ├── Guardian.Infrastructure/
│   ├── Guardian.Updater/
│   └── Guardian.Windows/
├── tests/
│   ├── Guardian.Core.Tests/
│   ├── Guardian.Scanner.Tests/
│   ├── Guardian.AI.Tests/
│   ├── Guardian.Policy.Tests/
│   ├── Guardian.Network.Tests/
│   ├── Guardian.Integration.Tests/
│   └── Guardian.Security.Tests/
├── docs/
└── .github/workflows/
```

## 4.3 Dépendances

- `Contracts` ne dépend d'aucun module métier.
- `Core` dépend de `Contracts`.
- Les moteurs dépendent de `Contracts` et `Core`, pas les uns des autres.
- `Service` compose les moteurs.
- `Desktop` dépend uniquement des contrats client et du protocole IPC.
- `Data` implémente les interfaces de persistance.
- `Infrastructure` encapsule les API Windows, journalisation et cryptographie.
- `Sandbox` communique avec l'hyperviseur par adaptateurs limités.
- aucune référence circulaire.

## 4.4 Contrats communs

Contrats à définir avant développement parallèle :
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

Chaque contrat précise les entrées/sorties, erreurs, annulation, timeout, privilèges, données personnelles, événements d'audit et tests de contrat.

---

# 5. Environnement et technologies

| Domaine | Choix recommandé |
|---|---|
| Langage | C# |
| Runtime | .NET 10 LTS, épinglé après vérification SDK |
| UI | WPF + MVVM |
| DI | Microsoft.Extensions.DependencyInjection |
| Configuration | Microsoft.Extensions.Configuration |
| Logs | Serilog ou Microsoft.Extensions.Logging avec sinks contrôlés |
| Base | SQLite + EF Core ou Dapper |
| IA inference | ONNX Runtime / ML.NET |
| Entraînement | Pipeline séparé et reproductible ; PyTorch/scikit-learn possibles pour préparer les modèles, export ONNX |
| Crypto | API .NET / Windows CNG ; DPAPI pour secrets locaux nécessaires |
| IPC | Named Pipes avec ACL et authentification du client |
| Système | API Windows documentées, ETW, WMI/CIM selon besoin |
| Réseau | Windows Filtering Platform / Windows Firewall APIs selon cas |
| Tests | xUnit, tests d'intégration VM, tests de contrat |
| CI | GitHub Actions, build, tests, analyse dépendances, scan secrets |
| Packaging | MSIX ou installateur signé selon contraintes du service |

Les dépendances sont centralisées dans `Directory.Packages.props`. Le SDK est épinglé dans `global.json`. Les versions sont validées sur la machine avant génération du dépôt.

---

# 6. Service résident, démarrage et santé

## 6.1 Démarrage

- installation du service Windows via un installateur élevé ;
- démarrage automatique selon la configuration de service retenue ;
- démarrage des moteurs indépendamment de l'interface ;
- récupération après panne configurée ;
- arrêt propre avec timeout ;
- état de santé exposé au tableau de bord ;
- mise à jour transactionnelle et rollback.

## 6.2 Watchdog

Le watchdog surveille la disponibilité du service et de ses composants :
- heartbeat signé/loggé ;
- vérification des processus et versions ;
- redémarrage selon une politique bornée ;
- limitation des boucles de redémarrage ;
- alerte si le service ne peut pas repartir ;
- aucune dissimulation du processus, aucun mécanisme furtif, aucune résistance à la désinstallation administrateur.

## 6.3 Auto-protection

- ACL restrictives sur les binaires, modèles, règles, base et quarantaine ;
- vérification de signature des binaires ;
- hash et manifeste d'intégrité ;
- contrôle des modifications de configuration ;
- mises à jour atomiques ;
- journal d'audit protégé ;
- service exécuté sous identité à privilèges minimaux compatible avec ses fonctions ;
- interface non élevée par défaut.

---

# 7. Moteurs de détection

## 7.1 Scan et signatures

Pipeline :
1. identifier le fichier et son type réel ;
2. vérifier taille et limites ;
3. calculer SHA-256 ;
4. rechercher les signatures locales ;
5. vérifier réputation si le service réseau est autorisé ;
6. analyser les métadonnées et structure ;
7. consulter les règles heuristiques ;
8. soumettre les caractéristiques au modèle IA ;
9. agréger les résultats ;
10. demander une décision au moteur de politiques.

Les archives sont limitées en profondeur, nombre d'entrées, taille décompressée et ratio de compression afin de résister aux bombes de décompression.

## 7.2 Heuristique statique

Signaux :
- incohérence extension/type ;
- signatures de format ;
- imports/API sensibles ;
- entropie anormale ;
- sections PE inhabituelles ;
- macros et scripts intégrés ;
- métadonnées et signature numérique ;
- obfuscation et empaquetage ;
- chemins et noms trompeurs ;
- indicateurs de persistance connus.

Un signal isolé ne suffit pas toujours à déclarer un fichier malveillant.

## 7.3 Analyse comportementale

Événements possibles :
- création/renommage/suppression en rafale ;
- modification de zones de démarrage ;
- création de service ou tâche planifiée ;
- injection ou accès interprocessus anormal ;
- accès inhabituel à des processus sensibles ;
- connexions sortantes périodiques ou destinations à risque ;
- altération des paramètres de sécurité ;
- lancement d'interpréteurs ou scripts dans des contextes suspects.

La corrélation temporelle et le contexte utilisateur réduisent les faux positifs.

## 7.4 Ransomware

Détecter :
- séquences massives d'écriture et renommage ;
- hausse rapide d'entropie ;
- suppression de snapshots ou sauvegardes observables ;
- modifications d'extensions ;
- notes de rançon détectées par signatures ;
- processus touchant de nombreux documents.

Réponse graduée :
1. alerte et collecte de preuves ;
2. limitation ou suspension si l'API et les droits le permettent ;
3. blocage réseau ciblé via règle autorisée ;
4. protection des répertoires et sauvegardes ;
5. quarantaine du binaire si confiance corroborée ;
6. restauration à partir de sauvegardes vérifiées.

Guardian ne promet pas de récupérer des données déjà chiffrées.

## 7.5 Mémoire vive et menaces fileless

Analyse défensive des métadonnées mémoire accessibles :
- régions exécutables privées ;
- modules non signés ou incohérents ;
- différences entre image disque et mémoire lorsque comparaison sûre possible ;
- pages exécutables dans des contextes inhabituels ;
- chaînes/indicateurs malveillants sans collecte de contenu privé ;
- corrélation avec événements de processus et réseau.

Aucune lecture de secrets, mots de passe, clés privées ou contenu de session n'est autorisée.

## 7.6 Rootkits, bootkits et firmware

- contrôle Secure Boot et état du démarrage mesurable ;
- inventaire des pilotes chargés et signatures ;
- comparaison de fichiers système avec catalogues de confiance ;
- contrôle des entrées de démarrage et partitions ;
- vérification des paramètres UEFI accessibles via interfaces documentées ;
- alerte en cas d'écart.

Les analyses firmware profondes nécessitent des outils et interfaces spécifiques au matériel ; l'absence d'anomalie observable n'est pas une preuve d'absence de bootkit.

## 7.7 Processus, injection et anti-keylogger

Guardian observe les indicateurs défensifs :
- modules chargés, signatures et chemins ;
- permissions et accès interprocessus ;
- création de threads distants et régions exécutables suspectes lorsque détectables ;
- hooks et mécanismes de capture observables sans recevoir les événements clavier ;
- comportements d'exfiltration et connexions associées.

Le produit n'installe pas de hook de capture clavier/souris et ne collecte pas le texte saisi.

## 7.8 Protection des identifiants

- vérifier l'état de protection LSASS et Credential Guard ;
- détecter les tentatives d'accès anormales aux processus sensibles ;
- repérer les outils de dumping par signatures et comportements ;
- surveiller les changements de politiques de sécurité ;
- proposer les réglages Windows recommandés.

Guardian ne récupère jamais les identifiants extraits et ne conserve aucun secret utilisateur.

---

# 8. Réseau, DNS et web

## 8.1 Inventaire des connexions

Chaque événement comprend autant que possible :
- PID et identité du processus ;
- chemin et signature du binaire ;
- IP/port local et distant ;
- protocole et horodatage ;
- DNS associé ;
- réputation et score ;
- métadonnées TLS visibles ;
- décision et règle appliquée.

## 8.2 DNS et C2

Détection :
- domaines connus malveillants ;
- domaines ressemblant à des marques ;
- fréquence/périodicité anormale ;
- volumes et tailles atypiques ;
- échecs DNS inhabituels ;
- corrélation processus-domaine ;
- indicateurs de tunneling DNS selon signaux observables.

Aucune détection C2 n'est garantie sur la seule base d'un domaine ou d'une IP.

## 8.3 TLS

Inspection passive des métadonnées visibles. Guardian ne prétend pas lire le contenu HTTPS. Toute inspection par proxy est une fonctionnalité distincte, explicitement configurée et administrée.

## 8.4 Pare-feu

- lire l'état du pare-feu Windows ;
- afficher les règles et connexions pertinentes ;
- proposer une règle de blocage temporaire ;
- appliquer une règle via interface Windows documentée après décision de politique et selon autorisation ;
- journaliser la création, l'expiration et la suppression de chaque règle ;
- ne jamais désactiver le pare-feu Windows.

---

# 9. Intelligence artificielle

## 9.1 Rôle

L'IA évalue les signaux, classe et explique. Elle ne dispose pas de terminal, d'accès libre au système, de capacité d'exécution arbitraire ni d'autorité directe de suppression.

## 9.2 Modèles

- modèle de classification statique des fichiers ;
- modèle d'anomalies comportementales ;
- modèle de corrélation ou de priorisation ;
- modèle local de langage facultatif pour l'assistant, isolé du moteur de décision.

## 9.3 Score de risque

Score composite configurable :
- signature/réputation ;
- heuristique ;
- comportement ;
- IA ;
- provenance et signature numérique ;
- contexte et criticité ;
- corroboration entre sources.

Le score expose la confiance, les facteurs contributeurs, la version du modèle et ses limites.

## 9.4 Apprentissage continu gouverné

Cycle :
1. collecter uniquement des événements autorisés et minimisés ;
2. demander consentement si des données quittent l'appareil ;
3. anonymiser/filtrer les données ;
4. valider les labels ;
5. entraîner dans un pipeline séparé ;
6. mesurer précision, rappel, F1, calibration et faux positifs ;
7. tester la robustesse et le poisoning ;
8. signer le modèle ;
9. déployer progressivement ;
10. surveiller la dérive et permettre rollback.

Aucun modèle ne s'entraîne automatiquement sur les documents privés de l'utilisateur.

## 9.5 Défense contre attaques IA

- traiter les fichiers, métadonnées et textes analysés comme des données non fiables, jamais comme instructions ;
- séparation stricte des prompts et des données ;
- validation de schéma des sorties ;
- limitation des requêtes ;
- défense contre extraction de modèle ;
- détection d'entrées adversariales ;
- validation des jeux d'entraînement ;
- signature et provenance des modèles ;
- tests de jailbreak/prompt injection pour l'assistant ;
- interdiction à l'assistant de déclencher une action système sans passer par le moteur de politiques.

---

# 10. Agent et moteur de politiques

## 10.1 Actions autorisées

`Allow`, `Monitor`, `Warn`, `RequireUserConfirmation`, `Block`, `Quarantine`, `TemporaryNetworkBlock`, `Restore`, `RemoveAfterConfirmation`.

Les actions sont des commandes typées, jamais des scripts libres.

## 10.2 Niveaux d'autonomie

| Niveau | Mode | Actions |
|---|---|---|
| L0 | Observation | Journalisation et alertes |
| L1 | Assisté | Recommandations, confirmation pour actions |
| L2 | Semi-autonome | Quarantaine automatique d'une menace très fiable, non critique et réversible |
| L3 | Autonomie bornée | L2 + remédiations explicitement listées, réversibles et corroborées |

L1 est le défaut. Les éléments système critiques exigent une confirmation humaine et une preuve indépendante. L'IA seule ne déclenche jamais une suppression irréversible.

## 10.3 Garde-fous

- liste blanche d'actions ;
- limites de fréquence ;
- circuit breaker ;
- politique versionnée et signée ;
- journal d'audit ;
- possibilité d'annuler/restaurer ;
- seuils calibrés sur corpus ;
- mode dégradé en cas de moteur indisponible ;
- séparation entre score, décision et exécution.

---

# 11. Sandbox et analyse dynamique

- orchestrateur de VM ;
- image de base propre et versionnée ;
- snapshots ;
- réseau isolé/simulé ;
- quotas et timeout ;
- collecte d'événements système ;
- export des rapports et IOC ;
- destruction ou restauration du snapshot ;
- aucun partage hôte en écriture ;
- validation des artefacts avant import dans Guardian.

La sandbox est une capacité optionnelle nécessitant virtualisation matérielle et édition/configuration compatibles. Si elle n'est pas disponible, Guardian effectue une analyse statique et affiche « analyse dynamique indisponible ».

---

# 12. Quarantaine, restauration et désinfection

- déplacer l'objet dans un répertoire protégé ;
- conserver hash, taille, chemin original, date, moteur et motif ;
- chiffrer le contenu avec une clé protégée par Windows ;
- neutraliser l'exécution ;
- vérifier intégrité avant restauration ;
- restaurer uniquement après analyse et confirmation ;
- suppression définitive selon rétention configurable ;
- journaliser toute action.

Une désinfection interne d'un fichier ne doit être proposée que si un mécanisme fiable et testé existe pour le format concerné. Sinon, quarantaine et restauration depuis une source saine.

---

# 13. Données, stockage et confidentialité

## 13.1 Emplacements

- binaires : `%ProgramFiles%\Guardian\`
- configuration machine : `%ProgramData%\Guardian\config\`
- base : `%ProgramData%\Guardian\data\guardian.db`
- quarantaine : `%ProgramData%\Guardian\quarantine\`
- signatures : `%ProgramData%\Guardian\signatures\`
- modèles : `%ProgramData%\Guardian\models\`
- journaux : `%ProgramData%\Guardian\logs\`
- sauvegardes : `%ProgramData%\Guardian\backup\`
- préférences UI : `%LocalAppData%\Guardian\`

Les chemins sont résolus par API Windows. Les ACL sont documentées et testées.

## 13.2 Tables SQLite minimales

`ScanJobs`, `ScanItems`, `Threats`, `ThreatEvidence`, `QuarantineItems`, `SystemEvents`, `NetworkEvents`, `PolicyDecisions`, `Signatures`, `ModelVersions`, `UpdateHistory`, `Exclusions`, `Settings`, `AuditEvents`, `HealthChecks`, `SandboxRuns`.

## 13.3 Rétention

- durée configurable ;
- purge périodique ;
- export expurgé ;
- aucune conservation de contenu privé inutile ;
- aucune collecte de frappe, mot de passe ou secret ;
- journaux protégés contre injection et falsification autant que possible.

---

# 14. Communication IPC et sécurité

- Named Pipes locales ;
- ACL limitées aux utilisateurs et groupes autorisés ;
- authentification du client et validation de l'identité ;
- messages versionnés et typés ;
- taille maximale et validation de toutes les entrées ;
- timeouts et annulation ;
- aucune commande shell générique ;
- protection contre rejeu si le protocole le nécessite ;
- audit des opérations privilégiées.

---

# 15. Mises à jour et chaîne de confiance

- manifeste signé ;
- vérification de signature avant installation ;
- hash des composants ;
- version et compatibilité ;
- téléchargement atomique ;
- rollback ;
- protection contre downgrade non autorisé ;
- validation de la source ;
- journaux de mise à jour ;
- rotation planifiée des clés de signature ;
- CI de génération d'artefacts ;
- signature de code des binaires publiés.

Une mise à jour dont la signature ou le manifeste échoue est rejetée.

---

# 16. Interface WPF

Pages :
1. Tableau de bord.
2. Analyse rapide / complète / personnalisée.
3. Protection temps réel.
4. Menaces et détails des preuves.
5. Quarantaine.
6. Réseau et connexions.
7. Surveillance système.
8. Historique et rapports.
9. Assistant IA.
10. Graphe d'incident et timeline.
11. Sandbox.
12. Paramètres.
13. Exclusions.
14. Mises à jour.
15. Santé des moteurs et diagnostic.

L'interface reflète les états `Healthy`, `Degraded`, `Stopped`, `OutOfDate`, `Unknown`. Elle ne simule jamais une protection active si le service est arrêté.

---

# 17. Tests et validation

## 17.1 Tests unitaires

- signatures et hash ;
- heuristiques ;
- score IA ;
- règles de politique ;
- transitions d'état ;
- quarantaine/restauration ;
- migrations ;
- validation IPC ;
- parsing réseau.

## 17.2 Tests d'intégration

- service Windows démarré sans UI ;
- IPC et ACL ;
- scan sur corpus bénin et corpus de test inoffensif ;
- détection EICAR dans un environnement de test ;
- quarantaine/restauration ;
- mises à jour signées et invalides ;
- réseau et règles temporaires ;
- panne et redémarrage ;
- mode hors ligne.

## 17.3 Tests de sécurité

- fuzzing des parseurs ;
- archives malformées et bombes de décompression ;
- fichiers volumineux ;
- élévation de privilèges ;
- accès IPC non autorisé ;
- falsification de journaux ;
- rollback/downgrade ;
- prompt injection et data poisoning de test ;
- erreurs de modèle ;
- abus de permissions ;
- tests de compatibilité Defender.

## 17.4 Tests de performance

Mesurer :
- temps de scan ;
- latence d'analyse à l'accès ;
- CPU/RAM au repos et en charge ;
- I/O ;
- taille de base ;
- démarrage du service ;
- délai de détection ;
- impact sur les applications.

## 17.5 Critères de livraison

- build reproductible ;
- tests requis verts ;
- binaires signés ;
- installateur/désinstallateur testés ;
- aucun secret dans le dépôt ;
- documentation à jour ;
- état de protection honnête ;
- plan de rollback ;
- rapport de sécurité ;
- liste des limitations connues.

---

# 18. Ordre d'intégration — application complète

Cet ordre organise les dépendances ; il ne réduit pas le périmètre à un MVP.

1. Dépôt, SDK, conventions et solution complète.
2. Contrats communs et modèles.
3. Infrastructure, configuration, logs, SQLite.
4. Service Windows, IPC, watchdog et santé.
5. Scanner, signatures, heuristiques, quarantaine.
6. Politique et agent.
7. IA locale, évaluation et explications.
8. Surveillance système, mémoire et démarrage.
9. Réseau, DNS, réputation et pare-feu.
10. Sandbox VM.
11. Interface WPF complète.
12. Mise à jour, installateur et désinstallateur.
13. Tests sécurité/performance/compatibilité.
14. Signature et livraison.

---

# 19. Glossaire

- **IOC** : indicateur de compromission.
- **C2** : serveur de commande et contrôle.
- **ETW** : Event Tracing for Windows.
- **WFP** : Windows Filtering Platform.
- **PPL** : Protected Process Light.
- **LSASS** : Local Security Authority Subsystem Service.
- **UEFI/MBR** : mécanismes de démarrage.
- **EDR/XDR** : détection et réponse endpoint / étendue.
- **Sandbox** : environnement isolé d'analyse.
- **Faux positif** : élément sain signalé à tort.
- **Faux négatif** : menace non détectée.

---

# 20. Décisions à valider avant le code

1. Version exacte du SDK .NET installé.
2. Éditions Windows cibles et minimum supporté.
3. Hyperviseur disponible pour la sandbox.
4. Modèle de distribution et signature des binaires.
5. Source et licence des signatures/règles.
6. Politique de données et consentement pour télémétrie facultative.
7. Seuils de réponse automatique.
8. Stratégie de coexistence avec Microsoft Defender.
9. Budget CPU/RAM/stockage.
10. Stratégie de support et mises à jour.

**Règle finale :** une fonctionnalité n'est considérée comme livrée que si elle est implémentée, testée sur les plateformes annoncées, documentée, observable et activable sans compromettre la sécurité de Windows.
