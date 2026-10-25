# Environnement de développement du KEM 1536

Le dépôt est organisé comme un espace de travail Cargo avec trois composants : `kem1536` pour la bibliothèque de travail, `kem1536-cli` pour les commandes locales et `kem1024-reference` pour le témoin standardisé. Le cœur cryptographique du rang 6 reste à construire.

## Installation locale sous Windows

Depuis le dossier NIST, avec PowerShell :

```powershell
.\scripts\bootstrap.ps1
.\scripts\research-setup.ps1
.\scripts\dev.ps1 doctor
.\scripts\dev.ps1 check
```

Si la politique PowerShell locale bloque le lancement des scripts, utiliser une autorisation limitée à ce processus :

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\dev.ps1 check
```

Rust 1.91.1 et ses outils sont installés sous `.tools/`. La cible Windows utilise `x86_64-pc-windows-gnu` et ses outils de liaison fournis par Rust. Le démarrage ne nécessite pas d’installer Visual Studio. Le `PATH` et les emplacements Rust sont configurés uniquement dans le processus du script.

Pour l’import de `bcryptprimitives.dll` utilisé par l’aléa système, le démarrage installe aussi `llvm-tools-preview`. Une copie de `llvm-ar.exe` est nommée `dlltool.exe` dans `.tools/native-tools/`, conformément au fonctionnement multicommande de cet outil LLVM. Les répertoires nécessaires à ses bibliothèques d’exécution sont ajoutés au chemin du processus. Aucune primitive d’aléa n’est remplacée par un générateur de simulation.

Python 3.11 ou ultérieur doit être disponible comme commande `python`. La vérification du profil et les tests d’arithmétique exacte utilisent seulement sa bibliothèque standard. La contre-vérification numérique J2 utilise NumPy 2.3.5 dans `.tools/research-venv`, préparé par `scripts/research-setup.ps1`. Aucune dépendance Python n’est installée globalement par ce script.

## Commandes courantes

| Commande PowerShell | Fonction |
|---|---|
| `.\scripts\dev.ps1 doctor` | Versions des outils |
| `.\scripts\dev.ps1 check` | Sources, formatage, Clippy, tests Rust/Python, profil et résultats figés |
| `.\scripts\dev.ps1 build` | Compilation de la bibliothèque et du programme |
| `.\scripts\dev.ps1 test` | Tests Rust |
| `.\scripts\dev.ps1 profile` | Profil et tailles, en JSON |
| `.\scripts\dev.ps1 status` | État réel de l’implémentation |
| `.\scripts\dev.ps1 fmt` | Application du formatage Rust |
| `.\scripts\dev.ps1 sources` | Empreintes, version de référence et couverture des vecteurs |
| `.\scripts\dev.ps1 reference` | Vérification ACVP du témoin et rapport JSON |
| `.\scripts\research-setup.ps1` | Environnement NumPy local et outils d’analyse figés |
| `.\scripts\dev.ps1 analysis` | Huit calculs de bruit, contre-vérification et 24 estimations d’attaque |
| `.\scripts\bootstrap-modern.ps1` | Sage 10.7 local sous WSL et sources figées de la comparaison moderne |
| `.\scripts\dev.ps1 modern` | Comparaison moderne, avec limites de temps et conservation des erreurs |

`Cargo.lock` doit être conservé. Les versions des dépendances directes sont fixées dans le manifeste. Après une modification volontaire des dépendances, régénérer le verrouillage et relancer les contrôles avant de conserver le nouveau fichier.

## Environnement Ubuntu

La procédure équivalente est préparée pour une validation ultérieure sous Ubuntu :

```bash
bash scripts/bootstrap.sh
bash scripts/research-setup.sh
bash scripts/dev.sh check
```

Elle nécessite Bash, curl, Python 3.11 ou ultérieur et un compilateur/éditeur de liens système, habituellement fourni par `build-essential` sous Ubuntu. Elle utilise également `.tools/`. Ne pas partager les binaires de ce répertoire entre les hôtes Windows et Linux ; utiliser deux clones source distincts.

Le workflow GitHub Actions décrit les contrôles Windows et Ubuntu. Sa présence ne signifie pas qu’il a déjà été exécuté sur GitHub.

## Prochaines étapes

1. J0 réalisé : références figées, errata examinés et contrat algorithmique initial documenté.
2. J1 réalisé sous Windows : témoin ML-KEM-1024, comparaison octet pour octet avec 145 cas officiels et contrôles complémentaires.
3. J2 en cours : bruit calculé et première comparaison primal/dual conservée. P0 échoue à C05 ; les variantes et analyses modernes/hybrides restent à poursuivre.
4. J3 à réaliser : implémenter le rang 6 et construire des vecteurs propres au projet.

Les changements de paramètres sous un même identifiant P0 sont volontairement refusés par les outils. Toute évolution doit mettre à jour la spécification, le profil, les vecteurs et les contrôles concernés.

Consulter `RAPPORT_RECHERCHE.md` et mettre à jour `JOURNAL_RECHERCHE.md` à chaque étape significative. L’instantané `results/j2/run-001/` correspond aux scripts enregistrés lors de sa création. Une modification de ces scripts exige un nouvel instantané et une mise à jour explicite de la vérification de l’état actif ; les résultats précédents et leur code restent dans Git.

Sous Linux, la préparation équivalente des études initiales est `bash scripts/research-setup.sh`, puis `bash scripts/dev.sh analysis`. Cette procédure complète Rust/Python reste à exécuter sur Linux. Le Python 3.10 système de WSL Ubuntu 22.04 n'a pas été modifié ; la nouvelle chaîne Sage utilise son propre Python 3.12.

## Études modernes sous WSL

La comparaison moderne emploie Sage 10.7 et un Python dédié, sans remplacer le Python système de WSL. Les 158 paquets nécessaires sont figés dans `research/sage-linux-explicit.txt`, avec leurs SHA-256 dans `research/sage-linux-packages.json`. Les archives persistantes sont conservées dans `.tools/downloads/sage-packages/`.

Sous Windows, le script de préparation monte un espace temporaire Linux sous `NIST/.tools/sage-ram/`. Cela évite les collisions de noms Linux et la lenteur des opérations de métadonnées sur NTFS. Ce cache en mémoire est limité à 6 Gio et disparaît à l'arrêt de WSL. Un processus WSL masqué, borné à deux heures, le garde disponible entre les commandes de la séance ; son identifiant est dans `.tools/sage-keeper.pid`. Il n'exécute aucune recherche future. Les sources, rapports et résultats restent sur disque dans NIST.

Les scripts emploient `CONDA_PKGS_DIRS` pour limiter le cache de paquets au projet, sans lire les fichiers de configuration mamba globaux. Les premières tentatives d'installation directe sur NTFS et un essai d'image ext4 n'ont pas été retenus. L'image temporaire `.tools/sage-runtime.ext4` est conservée après refus automatique de son nettoyage ; elle n'est pas utilisée par la procédure finale.

Le panneau moderne utilise une cible, deux budgets d'échantillons, aucune limite de mémoire exponentielle et un modèle GSA explicite. Les détails et limites des modèles sont dans `VEILLE_ATTAQUES_2026.md`. Une sortie d'erreur ou un dépassement de temps n'est pas transformé en estimation favorable. Les tentatives d'export corrigées sont conservées dans les données.

