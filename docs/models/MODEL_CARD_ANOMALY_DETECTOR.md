# Fiche de modèle (Model Card) — Détecteur d'Anomalies Structurelles (Isolation Forest)

**Modèle :** `guardian-anomaly-iforest`  
**Version :** `v1.2.0-iforest`  
**Auteur / Responsable :** Florent (Développeur IA, Guardian)  
**Date d'évaluation :** 2026-11-25  
**Type d'architecture :** Forêt d'isolation non supervisée (Isolation Forest — 64 arbres, sous-échantillonnage 128)  
**Objectif :** Détection de fichiers atypiques et de zero-days sans signature préalable  

---

## 1. Principe Algorithmique
L'algorithme part du principe que les anomalies sont « peu nombreuses et différentes ». En partitionnant aléatoirement l'espace des caractéristiques, un échantillon atypique se retrouve isolé à une profondeur d'arbre $h(x)$ beaucoup plus faible qu'un échantillon appartenant à la distribution dense normale :

$$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$

où $c(n) = 2(\ln(n - 1) + 0.5772156649) - \frac{2(n - 1)}{n}$ est la profondeur moyenne attendue.

- Si $s(x, n) \ge 0.65$ : L'échantillon est qualifié d'anomalie structurelle.
- Si $s(x, n) < 0.65$ : L'échantillon présente une distribution attendue.

---

## 2. Caractéristiques Évaluées
- `Taille du fichier`
- `Entropie de Shannon globale`
- `Nombre total de sections PE`
- `Nombre d'appels d'API d'injection`
- `Présence de certificat numérique Authenticode`
- `Indicateur de compresseur / packer`

---

## 3. Résultats et Performance
- **Profondeur moyenne pour échantillons sains :** ~ 6.5 partitions (score ~ 0.48 - 0.52).
- **Profondeur moyenne pour échantillons atypiques :** ~ 1.5 - 2.8 partitions (score ~ 0.72 - 0.88).
- **Temps d'inférence moyen :** 0.45 ms.
- **Taux de fausses alarmes mesuré :** 2.1 % sur logiciels tiers standards.
