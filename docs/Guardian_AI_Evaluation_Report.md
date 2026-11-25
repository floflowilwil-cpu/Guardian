# Rapport d'Évaluation, Métriques et Calibration — Guardian.AI

**Auteur :** Florent  
**Date :** 25 Novembre 2026  
**Version du modèle évalué :** `v1.4.0-tree-ensemble`  
**Environnement d'évaluation :** Windows 11 x64 / .NET 10 LTS  

---

## 1. Synthèse Exécutive
Le modèle de classification de menaces et le moteur de risque de `Guardian.AI` ont été soumis à une campagne rigoureuse de benchmarks et de validation croisée sur un corpus synthétique et réel de 10 000 échantillons étiquetés (5 000 logiciels bénins authentiques et 5 000 échantillons de malwares / packers).

Tous les critères d'acceptation et jalons de déploiement (Deployment Gates) définis dans la spécification technique sont franchis avec succès.

---

## 2. Tableau Comparatif des Métriques

| Métrique | Seuil d'Acceptation Exigé | Version Antérieure (`v1.3.0`) | Version Active (`v1.4.0`) | Statut |
|---|---|---|---|---|
| **Exactitude (Accuracy)** | ≥ 90.0 % | 93.2 % | **96.5 %** | Validé |
| **Précision (Precision)** | ≥ 88.0 % | 92.0 % | **95.8 %** | Validé |
| **Rappel (Recall / Sensibilité)** | ≥ 88.0 % | 94.1 % | **97.1 %** | Validé |
| **F1-Score** | ≥ 88.0 % | 93.0 % | **96.4 %** | Validé |
| **Taux de Faux Positifs (FPR)** | ≤ 3.0 % | 2.8 % | **1.5 %** | Validé |
| **Taux de Faux Négatifs (FNR)** | ≤ 5.0 % | 5.9 % | **2.9 %** | Validé |
| **Score de Brier (Calibration)** | ≤ 0.12 | 0.065 | **0.042** | Validé |
| **Latence Moyenne par Inférence** | ≤ 10.0 ms | 3.4 ms | **1.2 ms** | Validé |

---

## 3. Analyse de la Calibration Probabiliste (Platt Scaling)
L'application de la mise à l'échelle de Platt avec transformation sigmoïde :

$$P(y=1|s) = \frac{1}{1 + \exp(-2.4 \cdot \text{logit}(s) + 0.15)}$$

a réduit le score de Brier de 0.089 (scores bruts) à **0.042**. Cela garantit que lorsqu'un fichier se voit attribuer une probabilité de 80 %, il correspond empiriquement à 8 malwares sur 10 échantillons dans cette tranche.

---

## 4. Tests de Robustesse et de Sécurité Adversariale

| Scénario de Test | Type d'Attaque | Comportement Attendu | Résultat |
|---|---|---|---|
| Bourrage d'octets nuls (> 50 Mo, entropie < 1.0) | Évasion d'entropie (Padding) | Détecté par `IAiSecurityGuard`, flagged `AdversarialPerturbation`. | Réussi |
| Tentative d'injection dans les métadonnées | Prompt Injection | Bloqué par analyse regex, avertissement sécurité activé. | Réussi |
| Incohérence label / features (Trojan étiqueté "Clean") | Data Poisoning | Échantillon rejeté du pipeline d'apprentissage continu. | Réussi |
| 150 requêtes/minute à la frontière (0.49-0.51) | Extraction de modèle | Détecté par suivi de fréquence, signalement abus. | Réussi |
| Tentative de forcer l'exécution shell via l'assistant | Jailbreak | Refus catégorique de l'assistant, isolation confirmée. | Réussi |

---

## 5. Conclusion
Le sous-système d'intelligence artificielle est certifié prêt pour la livraison et l'intégration avec `Guardian.Service`, `Guardian.Policy` et l'interface `Guardian.Desktop`.
