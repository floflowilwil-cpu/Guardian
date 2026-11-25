# Architecture du Moteur d'Intelligence Artificielle — Guardian.AI

**Auteur :** Florent  
**Version :** 3.0  
**Statut :** Implémenté et testé  

---

## 1. Vue d'Ensemble du Module
`Guardian.AI` constitue le cœur décisionnel probabiliste de Guardian. Il apporte l'évaluation des fichiers, le calcul du score de risque composite, la corrélation multi-sources et l'assistance locale conversationnelle sans jamais outrepasser ses limites d'autorité.

```
                              ┌──────────────────────────────────────────────┐
                              │          Guardian.Desktop (Alexia)           │
                              └──────────────────────┬───────────────────────┘
                                                     │ IPC Local
                                                     ▼
                              ┌──────────────────────────────────────────────┐
                              │          Guardian.Service (John)             │
                              └──────┬───────────────────────┬───────────────┘
                                     │                       │
                                     ▼                       ▼
                        ┌────────────────────────┐  ┌────────────────────────┐
                        │ Guardian.Scanner       │  │ Guardian.Policy        │
                        │ (Iness)                │  │ (Florent + John)       │
                        └────────────┬───────────┘  └────────────▲───────────┘
                                     │                           │
                                     ▼                           │
   ┌─────────────────────────────────────────────────────────────┴────────────────────────┐
   │                                     Guardian.AI                                      │
   │                                                                                      │
   │  ┌───────────────────────┐   ┌───────────────────────┐   ┌────────────────────────┐ │
   │  │   PeFeatureExtractor  │──▶│  TreeBasedClassifier  │──▶│  ProbabilityCalibrator │ │
   │  └───────────────────────┘   └───────────────────────┘   └───────────┬────────────┘ │
   │                                                                      │              │
   │  ┌───────────────────────┐   ┌───────────────────────┐               ▼              │
   │  │   ThreatCorrelator    │   │  ExplainabilityEngine │◀─────── ThreatClassifier     │
   │  │  (Multi-Source Graph) │   │  (SHAP Attribution)   │                              │
   │  └──────────┬────────────┘   └───────────┬───────────┘       ┌────────────────────┐ │
   │             │                            │                   │  AiSecurityGuard   │ │
   │             ▼                            ▼                   │ (Prompt/Poison/Adv)│ │
   │  ┌───────────────────────┐   ┌───────────────────────┐       └───────────┬────────┘ │
   │  │  ThreatMemoryService  │   │   RiskScoringEngine   │                   │              │
   │  │ (Local Indexed IOCs)  │   │    (IRiskScorer)      │◀──────────────────┘              │
   │  └───────────────────────┘   └───────────┬───────────┘                              │
   │                                          │                                          │
   │  ┌───────────────────────┐               ▼                   ┌────────────────────┐ │
   │  │ LocalAssistantService │◀──────────────────────────────────│   ModelRegistry    │ │
   │  │   (Alexia UI Hook)    │                                   │   (Rollback/Gov)   │ │
   │  └───────────────────────┘                                   └────────────────────┘ │
   └──────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Principes Fondamentaux et Limites Non Négociables
1. **Aucune exécution arbitraire :** L'IA ne lance pas de processus PowerShell, CMD ou de scripts tiers.
2. **Aucune suppression directe :** L'IA propose un score et une recommandation (`Quarantine`, `Block`, `Warn`, `Monitor`, `Allow`). La décision et la remédiation sont régies par `Guardian.Policy`.
3. **Protection des composants système :** Les binaires critiques du système d'exploitation requièrent impérativement une confirmation humaine avant toute remédiation pour éviter d'endommager Windows.
4. **Respect absolu de la vie privée :** Aucun mot de passe, frappe clavier, token, clé privée ou contenu de document privé n'est collecté, inspecté ou stocké.

---

## 3. Composants et Responsabilités

### 3.1 `Classification/ThreatClassifier.cs` (Implémente `IThreatClassifier`)
Coordonne l'extraction statique de caractéristiques avec `PeFeatureExtractor`, passe l'échantillon au filtre de sécurité `AiSecurityGuard`, calcule la probabilité de malveillance via `TreeBasedMalwareClassifier`, applique la calibration logistique `ProbabilityCalibrator` et génère les explications via `ExplainabilityEngine`.

### 3.2 `Risk/RiskScoringEngine.cs` (Implémente `IRiskScorer`)
Calcule un score composite sur une échelle [0, 100] en intégrant :
- Signature / Réputation locale (35%)
- Classifieur IA (25%)
- Heuristiques statiques (20%)
- Comportement dynamique (25%)
- Détection d'anomalie structurelle (15%)
- Modificateurs de signature numérique (-65%) et de binaire système Windows (-80%)

### 3.3 `Anomaly/IsolationForestAnomalyDetector.cs` (Implémente `IAnomalyDetector`)
Détecteur non supervisé identifiant les zero-days ou fichiers anormaux sans modèle pré-entraîné sur signature.

### 3.4 `Correlation/ThreatCorrelator.cs` (Implémente `ISignalCorrelator`)
Corrèle les flux d'événements temporels entre fichiers, processus, clés de registre, réseau et mémoire pour produire le `ThreatGraph` et la chronologie d'incident (`ThreatTimelineEntry`).

### 3.5 `SecurityDefense/AiSecurityGuard.cs` (Implémente `IAiSecurityGuard`)
Bouclier défensif prévenant :
- Prompt injections dans les invites de l'assistant ou les métadonnées de fichiers
- Tentatives de jailbreak
- Data poisoning dans les données d'apprentissage continu
- Perturbations adversariales (padding artificiel d'octets 0x00)
- Extraction abusive de modèle par probing à haute fréquence

### 3.6 `Governance/ModelRegistry.cs` et `ContinuousLearningEngine.cs`
Assurent le cycle de vie des modèles, le calcul des métriques qualité (Accuracy, Precision, Recall, F1, Brier, FPR) et le rollback immédiat en cas d'anomalie constatée.
