# Entraînement du modèle PE Guardian — schéma v1

Ce dossier fixe le contrat des entrées du futur modèle; il ne contient pas de modèle entraîné ni de données. Le schéma C# correspondant est `StaticPeFeatureSchemaV1` dans `src/Guardian.AI/Classification`.

## Entrée attendue

Chaque ligne d'entraînement doit provenir de l'extracteur Guardian correspondant au même schéma et contenir les neuf colonnes, dans l'ordre déclaré par `feature-schema.json`, plus une étiquette binaire `label` (`0` bénin, `1` malveillant) et un identifiant `sha256` servant à dédupliquer et à séparer les échantillons. Ne pas mélanger plusieurs lignes du même hash entre apprentissage, validation et test.

`SuspiciousApiCallCount` compte actuellement des correspondances de chaînes ASCII; ce n'est pas une extraction de la table d'import. Les autres limites d'extraction sont décrites dans `docs/Guardian_AI_Features.md`.

## Données

Le dépôt ne contient pas de corpus étiqueté correspondant à ces neuf caractéristiques. Le jeu EMBER public fournit ses propres vecteurs de caractéristiques PE; ils ne peuvent pas être utilisés directement comme entrée de ce schéma sans une conversion dont la sémantique serait vérifiée. Le dépôt EMBER précise également que la version de l'extracteur et des caractéristiques doit rester cohérente entre entraînement et prédiction : <https://github.com/elastic/ember>.

N'ajoute pas de binaires malveillants au dépôt Guardian. Avant d'utiliser un corpus, vérifie sa licence, sa provenance, la méthode d'étiquetage et les autorisations de conservation. L'évaluation finale doit utiliser un jeu de test indépendant et documenté.

## État

- Contrat de caractéristiques : défini, version 1.
- Adaptateur de modèle : `IStaticMalwareModel`, déjà consommé par `ThreatClassifier`.
- Entraînement : pas encore implémenté; aucun modèle réel n'est livré.
- Export ONNX et chargement C# : prochaine étape après la disponibilité d'un corpus conforme.
