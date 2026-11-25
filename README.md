# Guardian

Guardian est une plateforme de sécurité avancée pour Windows, développée en C# et basée sur .NET 10.

## Objectifs

- Détection des logiciels malveillants.
- Analyse par signatures, heuristiques et comportements.
- Surveillance en temps réel du système.
- Protection contre les ransomwares.
- Analyse réseau et détection des communications suspectes.
- Quarantaine et gestion des menaces.
- Intelligence artificielle locale pour la classification des menaces.
- Interface utilisateur Windows avec WPF.
- Journalisation, mises à jour et protection de l'intégrité.

## Architecture

Le projet est organisé en plusieurs composants indépendants :

- Guardian.Desktop
- Guardian.Service
- Guardian.Contracts
- Guardian.Core
- Guardian.Policy
- Guardian.Scanner
- Guardian.Signatures
- Guardian.Quarantine
- Guardian.AI
- Guardian.SystemMonitor
- Guardian.Network
- Guardian.Data
- Guardian.Infrastructure
- Guardian.Updater
- Guardian.Windows

## Technologies

- C#
- .NET 10 LTS
- WPF
- SQLite
- ML.NET / ONNX
- Git et GitHub

## Documentation

La documentation officielle se trouve dans le dossier `docs/`.

- Documentation technique : `docs/Guardian_Documentation_Technique.md`
- Répartition des responsabilités : `docs/Guardian_Repartition_GitHub.md`

## Équipe

Le projet est développé par une équipe de cinq personnes :

- Florent : IA et classification.
- Alexia : interface WPF.
- Iness : scanner, signatures et quarantaine.
- John : service Windows et surveillance système.
- Ange : réseau, données, infrastructure et mises à jour.

## Développement

Les règles de contribution et d'intégration seront définies dans le dépôt GitHub.

## Sécurité

Guardian privilégie les opérations explicites, auditables et réversibles. Les fonctionnalités sensibles doivent respecter les limites techniques et les règles de sécurité définies dans la documentation.

## Licence

Tous droits réservés. Licence à définir.
