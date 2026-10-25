# Examen des errata de FIPS 203

La référence est le texte publié le 13 août 2024, conservé dans `references/NIST.FIPS.203.pdf`. Son empreinte SHA-256 est inscrite dans `references/manifest.json`, ainsi que celle du fichier officiel `fips-203-potential-updates.xlsx` examiné pour ce jalon.

## Corrections recensées

| Date d’identification | Emplacement | Point relevé | Traitement du projet |
|---|---|---|---|
| 31 mars 2025 | Annexe A | La liste des puissances de zeta contient aussi l’entrée i=0, bien que les algorithmes 9 et 10 emploient i=1 à 127 | Conserver cette entrée et l’indexation décrite ; documenter sa fonction d’alignement |
| 17 octobre 2025 | Section 5.3, algorithme 15, ligne 7 | Le commentaire de décodage mentionne v alors que le calcul porte sur w | Employer w dans la documentation du décodage |

Les deux entrées présentes dans le fichier examiné clarifient des commentaires et l’interprétation des indices. Elles ne modifient pas les opérations arithmétiques. Le NIST présente ce tableau comme des corrections potentielles, et non comme une nouvelle édition officielle. [Page officielle de FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).

## Référence figée

Le projet utilise le PDF original et ces deux clarifications. Toute édition ultérieure doit être examinée et introduite par une décision versionnée ; les fichiers conservés ne doivent pas être remplacés silencieusement.

Le témoin 1024 utilise la version exacte `ml-kem 0.3.3` de RustCrypto. La comparaison avec les sorties ACVP permet de vérifier ses résultats sur les cas retenus, sans établir une preuve générale de correction de son code.

