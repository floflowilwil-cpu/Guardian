# Guardian.AI — caractéristiques effectivement extraites

`PeFeatureExtractor` réalise une inspection statique simplifiée en mémoire. Il n’exécute pas le fichier. Les caractéristiques sont des indices, pas des verdicts.

| Champ | Calcul actuel | Limite d’interprétation |
|---|---|---|
| `Sha256` | SHA-256 du contenu complet | Identifie le contenu; ne détermine pas sa réputation sans base externe. |
| `FileSizeBytes` | Longueur du tableau d’octets | Aucun plafonnement mémoire n’est appliqué par cette API. |
| `ShannonEntropy` | Entropie de Shannon de tous les octets | Compression, ressources et chiffrement peuvent tous produire une entropie élevée. |
| `ByteDistributionVariance` | Variance calculée sur les fréquences d’octets | Signal statistique brut, sans seuil universel d’innocuité ou de malveillance. |
| `HasPeHeader` | Contrôle `MZ` et `PE\0\0` aux emplacements attendus | Contrôle minimal; ne signifie pas que toute la structure PE est valide. |
| `SectionCount` | Valeur déclarée dans l’en-tête PE | Les tables malformées ou tronquées ne sont pas toutes rejetées comme une erreur explicite. |
| `ExecutableSectionCount` | Bit `IMAGE_SCN_MEM_EXECUTE` des entrées de section accessibles | Indice structurel seulement. |
| `AnomalousSectionNameCount` | Noms absents de la liste courante des noms standard | Les noms inconnus sont fréquents dans les fichiers légitimes; ne pas les traiter comme preuve. |
| `MaxSectionEntropy` | Maximum d’entropie parmi les plages de section bornées | Les plages hors fichier sont ignorées. |
| `IsPackedOrObfuscated` | Noms de packer connus ou entropie élevée | Heuristique rudimentaire; peut produire des faux positifs et négatifs. |
| `SuspiciousApiCallCount` | Recherche de chaînes ASCII prédéfinies dans tout le fichier | Ce n’est pas une analyse de la table d’import; une chaîne présente ne prouve pas un appel. |
| `HasValidDigitalSignature` | Toujours `false` dans cet extracteur | L’API ne vérifie pas Authenticode. Une entrée de certificat PE ne suffirait pas à établir la validité. |
| `HasTlsCallback`, `HasResources`, `HasDebugInfo` | Toujours `false` dans cet extracteur | Ces structures ne sont pas encore analysées; `false` signifie ici « non évalué », pas « absent ». |
| `ImportedLibrariesCount`, `ImportedFunctionsCount` | Toujours `0` dans cet extracteur | La table d’import PE n’est pas encore analysée. |
| `SuspiciousStringRatio` | Toujours `0` pour les PE | Le ratio de chaînes suspectes n’est pas encore calculé. |
| `CustomFeatures.PrintableStringRatio` | Proportion d’octets imprimables | Ratio général de texte imprimable, et non ratio de chaînes malveillantes. |
| `CustomFeatures.CertificateTablePresent` | Présence d’une plage non vide et bornée dans l’entrée de répertoire certificat PE32/PE32+ | Présence potentielle uniquement; aucun certificat, chaîne de confiance, horodatage ou révocation n’est vérifié. |

Pour un fichier non-PE, quelques champs généraux et une recherche textuelle d’indicateurs sont produits. Les caractéristiques PE restent à zéro ou à `false`; ne pas interpréter ces valeurs comme une analyse complète du format.

## Sécurité, confidentialité et usage

- Le fichier est lu entièrement en mémoire. Les consommateurs doivent imposer leurs propres limites de taille et de durée.
- Aucune exécution du binaire n’est effectuée.
- `FilePath` est conservé dans le vecteur retourné; ne pas l’envoyer ni le journaliser sans besoin et autorisation.
- La classification et le score composite restent indicatifs et doivent être suivis d’une décision de `Guardian.Policy`.
- Une signature valide ne rend pas automatiquement un programme sûr; l’extracteur actuel ne valide pas les signatures.

Voir [Guardian_AI_Architecture.md](Guardian_AI_Architecture.md) pour le parcours et les capacités du module.
