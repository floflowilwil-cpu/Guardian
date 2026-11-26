# Guardian.AI — architecture et guide d’utilisation

**Responsable de domaine :** Florent  
**État :** implémentation en cours; les capacités décrites ci-dessous sont limitées au code présent.

## Rôle et limites

`Guardian.AI` fournit des analyses défensives locales. Il extrait des caractéristiques statiques, produit une classification heuristique, calcule un score composite, corrèle des signaux et prépare des explications. Il ne lance pas de fichier, ne supprime rien et n'applique pas lui-même de mesure de remédiation. `Guardian.Policy` reste l'autorité de décision.

Les valeurs probabilistes et les seuils ne doivent pas être présentés comme des taux de détection mesurés tant qu'un corpus reproductible, son protocole et ses résultats n'ont pas été publiés.

## Parcours d'une classification de fichier

1. `PeFeatureExtractor` lit le fichier sans l'exécuter, calcule son SHA-256, l'entropie et la variance des octets, puis inspecte quelques champs de la table des sections PE.
2. `ThreatClassifier` peut soumettre les caractéristiques à `IAiSecurityGuard`, puis les transmet au classifieur de règles.
3. `TreeBasedMalwareClassifier` applique des règles déterministes pondérées et convertit leur somme en score par sigmoïde. C'est un classifieur heuristique écrit à la main, pas un modèle ML.NET, ONNX, Random Forest ou Gradient Boosting entraîné.
4. `ProbabilityCalibrator` applique une seconde sigmoïde paramétrée. Ses valeurs par défaut sont provisoires et ne sont pas une calibration validée sur des données documentées.
5. `IsolationForestAnomalyDetector` calcule un signal d'anomalie à partir du vecteur fourni. Il ne charge pas de forêt entraînée sur une population de référence.
6. Le classifieur rend `Clean`, `Suspicious`, `Malicious` ou `Error`, les facteurs heuristiques et les limites connues. Ce verdict n'est pas une décision de remédiation.

Les erreurs de lecture ou d'inférence donnent un résultat `Error`; une annulation demandée par l'appelant est propagée. Les messages retournés ne contiennent pas de chemin local ni de détail d'exception.

## Score de risque composite

`RiskScoringEngine` accepte cinq scores facultatifs compris entre 0 et 1 : réputation/signature, classifieur, heuristiques, comportement et anomalie. Il renormalise les poids sur les sources effectivement présentes, applique un renfort plafonné en cas de corroboration et transforme le score en niveaux de risque. Les valeurs non finies, hors plage ou les nombres d'événements négatifs sont rejetés.

La signature numérique valide et l'identification d'un composant système ne réduisent plus le score composite : elles ne prouvent pas qu'un fichier est inoffensif. Un composant système à risque élevé exige une confirmation humaine. Sans aucune source de score, le résultat est explicitement accompagné d'une réserve et recommande une confirmation plutôt qu'un `Allow` automatique.

Les recommandations restent indicatives. Le moteur de politiques doit appliquer ses propres règles, contrôles de privilèges, confirmations et journalisation.

## Corrélation et mémoire

- `ThreatCorrelator` transforme une collection de `SecuritySignal` en graphe et timeline d'incident.
- `ThreatMemoryService` garde actuellement des signaux et graphes en mémoire du processus. Ce n'est pas un stockage durable; le nettoyage et la confidentialité des champs dépendent de ses règles de filtrage.
- `LocalAssistantService` fournit une réponse locale fondée sur les éléments transmis. Il n'a pas de terminal ni d'accès autonome aux opérations privilégiées.

L'assistant actuel est basé sur des règles et des réponses préparées; aucun LLM local n'est embarqué. `ContinuousLearningEngine` peut accepter avec consentement un nombre borné de retours sans chemin de fichier conservés en mémoire; les empreintes SHA-256 restent présentes. Ces exemples ne sont pas utilisés pour entraîner le classifieur. Le registre de modèle est également en mémoire, ne contient que la version heuristique active, ne vérifie aucun fichier signé et ne peut pas effectuer de rollback vers une ancienne version.

Les événements fournis doivent être validés en amont. La corrélation temporelle indique une association; elle ne prouve pas une causalité.

## Capacités utilisables aujourd'hui

- calculer un hash SHA-256 et des mesures d'entropie/variance;
- inspecter quelques caractéristiques de sections PE et les chaînes ASCII ressemblant à des API sensibles;
- obtenir une classification heuristique et une explication par facteurs;
- combiner des scores déjà produits par d'autres moteurs;
- créer un graphe et une chronologie à partir de signaux existants;
- interroger la mémoire temporaire et l'assistant local.

L'extracteur n'effectue actuellement **pas** une validation complète des fichiers PE, une analyse de table d'import, une validation Authenticode, une analyse réelle des callbacks TLS, des ressources ou des informations de débogage. Il ne valide pas que les noms de section atypiques sont malveillants. Le scan en mémoire complète du fichier implique aussi un coût mémoire proportionnel à sa taille.

## Ce qui reste nécessaire avant une revendication de production

- parseur PE borné et robuste, avec extraction réelle des répertoires/imports;
- validation Authenticode par une API Windows de confiance;
- modèle entraîné et versionné, ou présentation explicite du moteur comme heuristique;
- calibration, seuils et métriques calculés sur corpus documenté, avec séparation apprentissage/validation/test;
- stockage persistant à rétention maîtrisée pour la mémoire des menaces;
- intégration de bout en bout avec `Guardian.Policy`, le scanner et les contrats de service;
- tests de robustesse sur fichiers malformés, tailles extrêmes et signaux non fiables.

Voir aussi [Guardian_AI_Features.md](Guardian_AI_Features.md) et [Guardian_AI_Evaluation_Report.md](Guardian_AI_Evaluation_Report.md).
