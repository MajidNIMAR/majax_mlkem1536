# Distribution reproductible M04

La procédure M04 construit deux fois le binaire applicatif R1 à partir
d'un même instantané source et compare les SHA-256 des exécutables. Elle
préserve leurs noms de symboles pour que l'analyse de code machine porte
sur **les mêmes octets que le binaire distribué**. Les interfaces
`research-vectors` restent désactivées.

`release-003` reste l'expérience de double compilation. Le rempaquetage
`release-004` actualise les sources de documentation, d'outils de revue et
de tests d'intégration en réutilisant ses mêmes exécutables, après contrôle
strict des entrées de production. **Il n'effectue aucune nouvelle
compilation.** Les deux opérations ont des schémas de provenance distincts.

## Ce que contrôle la procédure

1. L'inventaire Git fournit les fichiers suivis dans leur état de travail
   et les nouveaux fichiers non ignorés. Les fichiers supprimés sont
   absents ; les changements non commités sont enregistrés par empreintes.
   `.git`, les caches d'outils, les anciens produits de compilation et les
   sorties temporaires ne sont pas des entrées de construction.
   Les cinq exclusions exactes de `research/export_publication.py` sont
   également appliquées et listées : `AGENTS.md`, l'ancien
   `PUBLICATION_PROVENANCE.json` et les trois copies externes sans licence
   de `references/coded-dual-audit/*.py.txt`. Les URL et empreintes de ces
   références restent présentes ; `fetch_reference_copies.py` les retrouve
   directement depuis leur amont pour les vérifications de recherche.
2. L'instantané est copié et vérifié ; une seconde lecture détecte une
   modification concurrente pendant l'export. Son manifeste nomme le HEAD
   de départ et précise qu'il peut contenir des modifications de travail.
   Le manifeste de fichiers, et non ce seul HEAD, identifie donc la source
   exacte. Les révisions des deux dépôts restent distinctes.
3. Chaque cible reçoit deux répertoires source **et deux répertoires de
   compilation distincts**. `--frozen --offline` impose le verrou Cargo
   existant et utilise le cache local déjà disponible. Aucune sortie du
   premier build ne sert de cache de compilation au second.
4. Rust est fixé à **1.91.1**. Les chemins source, target, Cargo et rustup
   sont neutralisés avec `--remap-path-prefix`. `SOURCE_DATE_EPOCH` reprend
   la date du commit de départ. Les options Rust sont transmises par
   `CARGO_ENCODED_RUSTFLAGS`, séparées par l'octet 31 pour préserver les
   chemins Windows contenant des espaces.
5. Le linker GNU Windows reçoit `--no-insert-timestamp` et les objets
   d'amorçage fournis par le toolchain Rust. Le linker Linux reçoit
   `--build-id=none`. `strip=debuginfo` conserve les noms de symboles utiles
   à la revue du binaire. Les compilations sont limitées à deux tâches.
6. Les deux exécutables doivent être identiques octet par octet. Chacun
   exécute 16 échanges frais et 16 contrôles de rejet implicite. La
   commande de vecteurs de recherche doit rester indisponible.
7. Cargo fournit les artefacts effectivement compilés, les fonctionnalités
   activées et le graphe résolu. L'inventaire associe les versions et les
   checksums de `Cargo.lock`, puis distingue les dépendances normales du
   programme des outils de compilation et macros procédurales. Le graphe
   normal n'est pas une attribution de tous les symboles survivant à
   l'élimination de code mort du linker.
8. Les imports PE de Windows et les entrées `NEEDED`/versions GLIBC de
   Linux sont relevés sur le binaire livré. Les bibliothèques système
   restent des prérequis ; elles ne sont pas intégrées au paquet.

Cette isolation concerne les répertoires, sur **le même hôte et les mêmes
caches de dépendances**. Elle n'est pas une expérience en conteneurs, une
installation depuis une machine vierge ni une reproduction par un tiers.
Docker n'est pas nécessaire et aucun service Docker n'est démarré,
arrêté ou reconfiguré par ces scripts. Une distribution WSL déjà installée
est appelée pour Linux et l'inspection PE ; la campagne de recherche
existante n'est pas arrêtée ou reconfigurée.

## Commandes

Les outils locaux Rust et Python doivent déjà être installés par les
scripts d'amorçage du projet. Pour les deux cibles :

```powershell
# Préparer un nouvel instantané, sans compilation.
.\scripts\reproduce-release.ps1 prepare -RunId r1-001

# Compiler l'instantané préparé sous Windows et sous WSL Linux.
.\scripts\reproduce-release.ps1 all -RunId r1-001

# Recontrôler ensuite les sources et les paquets conservés.
.\scripts\reproduce-release.ps1 verify -RunId r1-001

# Actualiser les sources non compilées, en réutilisant une preuve existante.
.\scripts\reproduce-release.ps1 repackage -RunId release-004 -ReferenceRunId release-003
```

`all` prépare l'instantané s'il n'existe pas. Les actions `windows` et
`linux` permettent de traiter une seule cible. Une cible existante n'est
pas écrasée : choisir un nouvel identifiant après une modification du code
ou une tentative incomplète. Le script ne compile pas les fichiers du
répertoire de travail après l'export ; il compile l'instantané vérifié.

Le helper Linux peut aussi être appelé directement depuis WSL :

```bash
bash scripts/reproduce-release-linux.sh \
  "$PWD/artifacts/generated/m04-distribution/r1-001"
```

La préparation utilise l'inventaire Git et s'exécute donc depuis un clone
ou un dépôt de travail. Une archive source extraite sans `.git` reste
compilable avec Cargo et les scripts d'amorçage ; elle ne fournit pas à
elle seule l'inventaire Git nécessaire à une nouvelle action `prepare`.
Le paquet conserve séparément le manifeste et l'archive de l'instantané
ayant produit les exécutables.

L'action `repackage` refuse la moindre différence, y compris ajout ou
suppression de fichier, dans `Cargo.toml`, `Cargo.lock`, les fichiers de
toolchain/configuration, tous les `crates/**/src`, manifestes et `build.rs`
éventuels, les profils et vecteurs. Elle inclut également
`references/manifest.json` et `fuzz/fixtures/cases.bin`, puis vérifie la
fermeture des `include_str!`/`include_bytes!` littéraux. Le jeu d'entrées
contrôlé est volontairement plus large que le seul code finalement lié.

Les différences non compilées sont listées par leurs empreintes avant et
après dans `compiled-input-equality.json`. Les manifestes et la provenance
de construction du paquet antérieur sont conservés avec cette preuve.
`verify` recalcule leur cohérence avec la source courante et les binaires
livrés. Les rapports corrigés de tests d'intégration peuvent être joints
sans être présentés comme de nouvelles compilations des binaires livrés.

Ubuntu 22.04 et son Python 3.10 sont pris en charge sans paquet Python
global ajouté. Les quatre champs scalaires utiles du verrou Cargo sont
lus dans sa syntaxe générée ; la résolution du graphe est effectuée par
Cargo lui-même. Toute dépendance manquante dans le cache provoque un
échec explicite de `--offline`.

## Contenu d'un paquet

Chaque archive de cible contient :

- `bin/kem1536` ou `bin/kem1536.exe`, sans interfaces déterministes de
  recherche ;
- `source.tar.gz`, l'ensemble de la source sélectionnée, y compris
  bibliothèque Rust, spécification, rapports et exemple consommateur
  lorsqu'il est présent dans l'instantané ;
- `source-manifest.json`, `provenance.json` et `SHA256SUMS.json` ;
- `LICENSE`, `NOTICE`, `SECURITY.md` et `THIRD_PARTY_NOTICES.md` ;
- `dependencies.json`, les textes de licence des dépendances compilées,
  les mentions de la bibliothèque standard et les textes des licences du
  toolchain ;
- les deux rapports d'autotest et un mode d'emploi `USAGE.md`.

Le verrou du workspace principal et les paquets compilés décrivent le
CLI livré. L'exemple consommateur dans `examples/r1-channel-demo` dispose
d'un workspace/verrou autonome ; ses dépendances optionnelles ne sont
pas présentées comme intégrées au CLI lorsqu'elles n'y sont pas compilées.
Les dépendances ne sont pas vendored : un autre poste doit pouvoir les
télécharger ou disposer d'un cache compatible.

Les archives sont produites avec ordre des chemins, permissions, UID/GID
et date de compression déterministes. Le vérificateur contrôle également
les octets de chaque fichier **dans** les archives, pas seulement ceux des
répertoires de travail. L'identité des exécutables sur un hôte ne démontre
pas la sécurité du compilateur ni l'identité sur d'autres hôtes.

## Emplacement et état

Les entrées exportées, journaux, inventaires et paquets sont conservés dans
`artifacts/generated/m04-distribution/<identifiant>/`. Ce répertoire est
ignoré par Git et reste sous NIST. Aucun ancien résultat figé n'est modifié.

La présence des scripts ou la réussite de leurs tests unitaires ne vaut
pas réussite des doubles compilations : celle-ci exige les fichiers
`windows/result.json` et/ou `linux/result.json`, avec
`two_isolated_builds_identical=true`, puis un rejeu réussi de `verify`.
Les résultats observés doivent être ajoutés au rapport avec leurs
empreintes et leur révision exacte après l'exécution.

## Résultats observés — release-003

Les **deux compilations Windows et les deux compilations Linux réussissent**
avec des répertoires source et target neufs pour chacune. Les exécutables
de chaque paire ont le même SHA-256. Les 16 échanges frais et 16 contrôles
de rejet passent pour chacun des quatre exécutables ; les commandes de
vecteurs de recherche sont indisponibles. Les noms de symboles sont
conservés dans les exécutables effectivement empaquetés.

L'instantané public contient 729 fichiers, sur la base du commit
`78f5faff017d99a2b323efda17f37a3146f63340`, avec les nouveaux fichiers
de travail enregistrés par le manifeste. Les cinq exclusions de l'export
public sont absentes. Les sources Rust sont identiques à celles de
l'essai préparatoire release-002.

| Cible | SHA-256 de l'exécutable livré | Inventaire compilé |
|---|---|---|
| x86_64-pc-windows-gnu | `ea80bc3a7f49ba287cf0958be1e7eceabe55cfc8882cdabc2517b6c58712ca65` | 51 paquets, dont 44 dans le graphe normal et 7 de compilation seulement |
| x86_64-unknown-linux-gnu | `e025ab71066ba63d3efccf6eb28f5e91a4050d151ea83f4fb1aab4320ced71c9` | 52 paquets, dont 45 dans le graphe normal et 7 de compilation seulement |

L'inventaire PE contient sept imports système :
`api-ms-win-core-synch-l1-2-0.dll`, `bcryptprimitives.dll`, `KERNEL32.dll`,
`msvcrt.dll`, `ntdll.dll`, `USERENV.dll`, `WS2_32.dll`. L'ELF demande
`ld-linux-x86-64.so.2`, `libc.so.6` et `libgcc_s.so.1` ; la plus haute
version de symbole GLIBC relevée est **2.34**. Cela décrit ce binaire, sans
certifier toutes les versions ou configurations de ces systèmes.

Les archives finales, sous `artifacts/generated/m04-distribution/release-003/`,
sont :

- `source.tar.gz` :
  `cc07a8d9474f891b40864c7dd432c226c0472c6d1cb3f224d35312ae0fc51318` ;
- `windows/kem1536-r1-x86_64-pc-windows-gnu.tar.gz` :
  `5a6c9cedc79d956e34af3a1415cf423702d6e1f7a55347ff5cd0a1464eb5c706` ;
- `linux/kem1536-r1-x86_64-unknown-linux-gnu.tar.gz` :
  `42be71986552233cf64f359498694cd07111e28436581b97c31139254a0fc231`.

Le manifeste source a pour empreinte
`b316ad7e2c9212840c2007f29a6f859c0806821d809fef8cd09b7771643922d8`.
Les fichiers `result.json` de chaque cible, les inventaires Cargo, les
journaux et les rapports d'autotest conservent le détail des exécutions.
Le contrôleur complet termine avec le code **0** ; les vérifications
globales retrouvent `verified_release_targets=["windows","linux"]`, y
compris les octets des fichiers contenus dans les deux archives finales.
Quatre tests du dispositif de distribution réussissent sous Python Windows
3.13 et sous Python WSL 3.10 : altération de fichiers, traversées de
chemins/exclusions publiques, stabilité des archives et séparation des
macros/dépendances normales. Les syntaxes PowerShell et Bash sont vérifiées.

Deux essais préparatoires restent conservés localement. `release-001` a
été arrêté sur son seul arbre de compilation après détection des copies
externes à exclure de l'archive publique. `release-002` a produit deux
exécutables Windows identiques, puis révélé une conversion de chemins WSL
incorrecte ; celle-ci est corrigée dans les scripts inclus à `release-003`.
Ces essais ne sont pas les paquets finaux à distribuer. La campagne M03
existante et ses processus n'ont pas été interrompus.

## Paquets sources actualisés — release-004

Le rempaquetage `release-004` termine avec le code **0**. Il contient
**732 fichiers source publics**, dont les corrections des tests de contrat
et de l'outil d'analyse des effacements. Il conserve les deux exécutables
de `release-003` et ne lance **aucune nouvelle compilation**.

La comparaison contrôle **30 entrées de compilation** : leurs ensembles et
leurs SHA-256 sont exactement identiques entre les manifestes 003 et 004,
y compris les inclusions de profils, vecteurs, manifeste de référence et
fixture indiquées plus haut. Chaque ajout, suppression ou changement de ces
entrées aurait interdit la réutilisation. Les changements non compilés
sont intégralement énumérés dans la preuve. Les tests corrigés de contrat
passent séparément, 2/2 sous Windows et 2/2 sous Linux ; leurs journaux sont
joints aux nouveaux paquets.

Les paquets courants à distribuer sont sous
`artifacts/generated/m04-distribution/release-004/` :

| Fichier | SHA-256 |
|---|---|
| `source.tar.gz` | `1db47a22dfd27a06f583b036a603fb0c21c0f8b1df242f65ef2c12caeed12cd9` |
| `windows/kem1536-r1-x86_64-pc-windows-gnu.tar.gz` | `38c4e97fad694a4a0764f8ddcdf7cec811507a55c85203be12d183e673be97a7` |
| `linux/kem1536-r1-x86_64-unknown-linux-gnu.tar.gz` | `16731b39d6c22bf2b0fec8f9edb6e8a96fb6dd79e59966b3c3d22a3dc73da666` |

Les hashes des binaires restent ceux de la table 003. La provenance 004
indique `new_compilations_in_this_run=0` et rattache explicitement les
preuves des doubles compilations à `reference_double_build_run=release-003`.
Les manifestes et la provenance de construction 003 sont copiés dans
`validation/` sans modifier l'expérience originale. Le vérificateur
recalcule aussi cette chaîne et retrouve les deux cibles, ainsi que les
octets internes de leurs archives.

Un cinquième test du dispositif contrôle spécifiquement le refus de
réutilisation après modification, ajout ou suppression d'une entrée de
compilation, tout en autorisant des corrections de tests/docs/outils. Les
**5/5 tests** réussissent sous Python Windows et WSL.
