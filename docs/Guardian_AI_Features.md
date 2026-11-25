# Spécification et Dictionnaire des Caractéristiques IA — Guardian.AI

**Auteur :** Florent  
**Module :** `Guardian.AI.FeatureExtraction` & `Guardian.Contracts.AI.Models.FileFeatureVector`  
**Version :** 3.0  

---

## 1. Vue d'ensemble du Pipeline d'Extraction
Toutes les caractéristiques sont extraites de manière statique et sécurisée sans exécution du binaire cible. Le fichier est lu en mémoire tampon sous forme de flux d'octets protégés. Aucune commande système n'est invoquée.

---

## 2. Dictionnaire Détaillé des Caractéristiques

| Caractéristique | Type | Description | Signification de Sécurité |
|---|---|---|---|
| `ShannonEntropy` | `double` (0.0 - 8.0) | Entropie globale calculée sur l'ensemble du binaire : $H = -\sum p_i \log_2(p_i)$. | Les fichiers standards se situent entre 4.5 et 6.5. Une entropie > 7.2 indique un chiffrement, une compression ou un packer de malware. |
| `MaxSectionEntropy` | `double` (0.0 - 8.0) | Entropie maximale mesurée sur une section PE individuelle. | Une section avec $H > 7.5$ abrite quasi-systématiquement un payload dissimulé ou du code shellcode chiffré. |
| `FileSizeBytes` | `long` | Taille physique en octets. | Utilisé pour normaliser les ratios et détecter les anomalies de bourrage (overlay padding). |
| `HasPeHeader` | `bool` | Présence d'un en-tête valide DOS `MZ` (0x5A4D) et PE `PE\0\0` (0x00004550). | Différencie les exécutables natifs Windows des scripts ou documents. |
| `SectionCount` | `int` | Nombre total de sections déclarées dans l'en-tête PE. | Les exécutables légitimes possèdent généralement 3 à 7 sections. Moins de 2 ou plus de 10 est suspect. |
| `ExecutableSectionCount` | `int` | Nombre de sections marquées avec le flag `IMAGE_SCN_MEM_EXECUTE` (0x20000000). | Les compilateurs normaux n'émettent qu'une seule section exécutable (`.text`). La présence de plusieurs sections exécutables est un fort indicateur d'injection. |
| `AnomalousSectionNameCount` | `int` | Nombre de sections ne figurant pas dans la liste standard (`.text`, `.data`, `.rdata`, `.rsrc`, `.reloc`, etc.). | Les packers (UPX, Themida, VMProtect) injectent des noms de section non conventionnels (`.upx0`, `.vmp1`). |
| `IsPackedOrObfuscated` | `bool` | Flag synthétique dérivé des noms de section, de l'entropie et de la signature de packer. | Permet d'ajuster immédiatement les poids heuristiques. |
| `SuspiciousApiCallCount` | `int` | Nombre d'occurrences d'API de manipulation mémoire/processus identifiées dans la table d'import. | Détecte : `VirtualAlloc`, `VirtualProtect`, `WriteProcessMemory`, `CreateRemoteThread`, `SetWindowsHookEx`, `InternetOpen`, `WinExec`. |
| `HasValidDigitalSignature` | `bool` | Présence d'une entrée non nulle dans le répertoire de sécurité PE (Authenticode). | Réduit le risque de 70% si présent et intègre. |
| `HasTlsCallback` | `bool` | Présence de callbacks TLS exécutés avant le point d'entrée principal (`AddressOfEntryPoint`). | Fréquemment exploité par les malwares pour déjouer les débogueurs. |
| `ByteDistributionVariance` | `double` | Variance de la fréquence d'apparition des 256 valeurs d'octets. | Un chiffrement parfait produit une variance très basse (< 5000), alors qu'un code clair présente des pics prononcés. |
| `SuspiciousStringRatio` | `double` (0.0 - 1.0) | Proportion de motifs d'URL, de commandes shell ou de clés de registre dans les chaînes imprimables. | Indicateur heuristique de fonctionnalités de dropper ou de C2. |

---

## 3. Confidentialité et Données Personnelles
Aucune caractéristique n'extrait de nom d'utilisateur, de chemin de document personnel, de mot de passe, de secret ou de jeton. Les chemins sont anonymisés au niveau du simple nom de fichier lors des cycles d'apprentissage continu.
