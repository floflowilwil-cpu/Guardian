# Fiche descriptive — classifieur statique Guardian

**Identifiant :** `guardian-static-rules`  
**Version :** `v1.5.0-static-rules`  
**Type :** moteur de règles heuristiques pondérées, écrit à la main  
**État :** expérimental; aucune évaluation quantitative reproductible publiée

## Usage prévu

Produire un signal de triage à partir de caractéristiques statiques fournies par `FileFeatureVector`. Le moteur n'exécute pas les fichiers et n'a pas d'autorité de remédiation. `Guardian.Policy` doit prendre toute décision d'action.

## Fonctionnement réel

`TreeBasedMalwareClassifier` évalue sept règles déterministes sur les entropies, certains indicateurs de sections PE, les chaînes ressemblant à des noms d'API, l'indicateur de packer et la variance des octets. Il additionne leurs contributions et applique une sigmoïde. `ProbabilityCalibrator` applique ensuite une seconde sigmoïde avec des paramètres provisoires non calibrés sur un jeu de données livré. Une signature Authenticode ne modifie pas ce score.

Il ne s'agit pas de Gradient Boosting, de Random Forest, de ML.NET ou d'un modèle ONNX. Les champs de confiance sont des scores heuristiques, pas des intervalles statistiques ni des probabilités certifiées.

## Limites des entrées

- L'extracteur PE actuel ne valide pas Authenticode. Il laisse `HasValidDigitalSignature` à `false` et ne peut donc pas conclure sur la confiance d'un éditeur.
- La recherche d'API inspecte des chaînes ASCII dans le fichier entier; elle ne lit pas la table des imports et ne prouve pas qu'une API est appelée.
- Les caractéristiques `HasTlsCallback`, `HasResources` et `HasDebugInfo` ne sont pas encore analysées par l'extracteur.
- Une haute entropie, des noms de section atypiques ou des API sensibles peuvent apparaître dans des logiciels légitimes.
- Les fichiers non PE ne bénéficient pas d'une analyse sémantique propre à leur format.
- L'analyse statique ne détecte pas toutes les menaces et ne prouve pas l'innocuité d'un résultat `Clean`.

## Évaluation et déploiement

Les métriques chiffrées précédemment associées à ce classifieur ont été retirées faute d'artefacts reproductibles. Le registre expose des valeurs nulles comme champs numériques obligatoires du contrat, mais elles ne signifient pas « 0 % mesuré »; l'architecture indique explicitement « non évalué ». La vérification d'intégrité retourne `false`, car aucun modèle signé n'est embarqué.

Avant tout usage comme barrière de sécurité, il faut publier un corpus autorisé, les étiquettes, les scripts, les versions, les résultats bruts, les erreurs par classe et la calibration. Voir [le rapport d'évaluation](../Guardian_AI_Evaluation_Report.md).
