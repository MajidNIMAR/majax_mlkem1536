# Références figées

`manifest.json` conserve les URLs, tailles et empreintes SHA-256 du PDF FIPS 203, du fichier d’errata examiné et des six fichiers ACVP utilisés. Le commit NIST ACVP et la version exacte de la bibliothèque de référence sont également enregistrés.

La commande suivante vérifie les fichiers, la version et le checksum du paquet `ml-kem` dans `Cargo.lock`, ainsi que la couverture sélectionnée :

```powershell
.\scripts\dev.ps1 sources
```

Les données ACVP sont conservées octet pour octet, y compris leurs fins de ligne. `.gitattributes` désactive leur conversion automatique. L’examen du fichier d’errata est décrit dans `docs/ERRATA_FIPS203.md`.

Les licences du paquet RustCrypto sont conservées dans ce répertoire. La notice NIST relative aux données ACVP se trouve dans `vectors/nist-acvp/NIST-NOTICE.txt`.

`correctness-2026/manifest.json` et sa copie HTML figent une source primaire supplémentaire sur les dépendances du bruit : Duriez et Tommasini, arXiv:2609.09983v1, sous CC BY 4.0. L'étude `run-004` en donne le contexte et l'attribution, sans transférer ses chiffres au rang 6 ni déclarer sa chaîne de certificats reproduite. Le vérificateur `research/verify_u_dependency_results.py` contrôle cette copie et son manifeste ; le manifeste initial n'a pas été modifié.

