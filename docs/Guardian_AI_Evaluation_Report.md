# Guardian.AI — état de l’évaluation

**Responsable :** Florent  
**État :** aucune campagne quantitative vérifiable n’est fournie dans le dépôt.

## Conclusion actuelle

Les chiffres de précision, rappel, F1, taux de faux positifs, score de Brier et latence précédemment indiqués dans ce document ont été retirés : aucun jeu de données, script d’évaluation, journal d’exécution ou rapport brut permettant de les reproduire n’accompagne ces valeurs. Ils ne doivent pas être utilisés comme résultats mesurés ni comme critère de mise en production.

Le composant actuellement nommé `TreeBasedMalwareClassifier` est une série de règles déterministes pondérées. Ce n’est pas un ensemble d’arbres appris sur les 10 000 échantillons qui étaient annoncés. `ProbabilityCalibrator` applique des paramètres provisoires; le code ne démontre pas que ceux-ci proviennent d’une calibration empirique. Le détecteur d’anomalies utilise une structure déterministe générée dans le code, sans population de référence documentée.

## Protocole à fournir pour une future évaluation

Publier avec chaque version évaluée :

- l’identifiant, la provenance, la licence et les empreintes des jeux de données;
- les règles d’étiquetage, les exclusions et la répartition apprentissage/validation/test;
- les versions du code, du modèle, des dépendances et de la configuration;
- les commandes exactes pour reproduire l’expérience;
- la matrice de confusion et les métriques par classe, ainsi que précision, rappel, F1, FPR, FNR et score de Brier;
- les intervalles d’incertitude, le seuil de décision retenu et l’analyse des faux positifs;
- la méthode de mesure de latence, la machine utilisée et la taille de l’échantillon;
- les tests sur fichiers malformés, adversariaux et hors distribution.

Un jeu de test doit rester séparé de l’ajustement des seuils et de la calibration. Les métriques d’un corpus synthétique doivent être publiées séparément de celles d’échantillons réels et clairement étiquetées.

## Décision de livraison

En l’absence de preuves reproductibles, `Guardian.AI` doit être considéré comme une implémentation expérimentale. Les résultats servent à prioriser une inspection et ne constituent pas une garantie de détection, une preuve d’innocuité ni une autorisation automatique de remédiation.
