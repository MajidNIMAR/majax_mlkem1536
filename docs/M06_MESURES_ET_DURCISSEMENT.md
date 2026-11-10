# M06 — Mesures comparatives et durcissement du cœur accumulé

10 novembre 2026. Le cœur M06 accumule les produits dans le domaine NTT
et transforme une seule fois les opérandes réutilisés. Cette étude mesure
son effet sur le moteur complet, puis vérifie le code figé par une campagne
finie. Elle ne modifie ni les formats R1 ni les paramètres cryptographiques.

## Sources et chaîne commune

La référence est exactement le commit Git
`693c6a305b5143b9b00b912353bbae153cad4e4f`, capturé par `git archive`
avant le changement du cœur. L'archive initiale, ses 32 fichiers et leurs
empreintes sont conservés dans `baseline-snapshot.json` et
`baseline-source.tar`. Le harnais de mesure ajouté ensuite est identique
dans les deux instantanés et identifié séparément par `harness.json`.

Le candidat M06 mesuré est figé aux empreintes SHA-256 suivantes :

- `dev_kem.rs` : `eb7635eedc73c3db93d7baa81a86817157969a82890f797acfb3694a767e0262` ;
- `engine_poly.rs` : `ffe7b50dfebfe8d9998296672bd1973a8376a02cb06f2338418e27f23a392ac2`.

Les builds sont séparés et utilisent Rust **1.91.1**, commit
`ed61e7d7e242494fb7057f2657300d9e77bb4fcb`, LLVM 21.1.2, en mode release
verrouillé et hors ligne, sur WSL2 Ubuntu 22.04, AMD Ryzen 7 2700.
L'option commune `-Zemit-stack-sizes` ajoute les métadonnées de frames LLVM ;
`RUSTC_BOOTSTRAP` est réservé à cette option de mesure. Les compilations
de production gardent leur propre procédure. Les sources et les verrous
ont été contrôlés après chaque build.

Le contrôleur réellement utilisé pour les mesures est conservé dans
`measurement-controller.py`, avec son empreinte. La copie `controller.py`
figée avant les builds conserve la préparation antérieure. Aucun
environnement arbitraire ni ligne de commande d'autres processus n'est
collecté : le reçu de charge contient seulement PID, nom et pourcentage
CPU rapportés par `ps`, ainsi que `/proc/loadavg`.

## Protocole exécuté

Les deux binaires tournent séquentiellement sur le même CPU logique
Linux **10**. Cinq séries contiennent chacune **2000 observations par
opération et par version**, après 100 échauffements par opération. L'ordre
des versions est alterné AB, BA, AB, BA, AB ; l'ordre des trois opérations
tourne aussi selon la série. Cela donne **60 000 observations**, soit
10 000 pour chacune des six cellules.

KeyGen et Encaps comprennent l'appel au générateur aléatoire du système.
Les échanges sont validés après l'arrêt du chronomètre. Les objets
retournés sont également détruits après cet arrêt. L'allocation de la
banque d'observations et l'écriture JSON sont hors chronomètre.
Les contrôleurs de cette étape n'ont lancé aucun fuzzing ou build lourd
pendant les mesures. La fréquence et l'activité générale de l'hôte Windows
ne sont pas isolées ; la correspondance avec un cœur physique exclusif
n'est pas démontrée. Les pourcentages `ps` ne sont pas une mesure
instantanée de toute la charge de l'hôte.

Les distributions brutes, l'ordre réel des exécutions, les sources et les
binaires sont figés dans
[`results/engine/m06-measurements-001`](../results/engine/m06-measurements-001).
Le vérificateur recalcule les statistiques, contrôle les empreintes et
rejette les observations manquantes ou dupliquées. Aucun échantillon
extrême n'est supprimé.

| Opération | Médiane référence, µs | Médiane M06, µs | Rapport des médianes référence/M06 | p95 référence, µs | p95 M06, µs |
|---|---:|---:|---:|---:|---:|
| KeyGen | 912,009 | 508,664 | 1,79 | 1045,463 | 591,919 |
| Encaps | 1045,195 | 560,313 | 1,87 | 1292,152 | 674,465 |
| Decaps valide | 1207,790 | 686,917 | 1,76 | 1400,962 | 799,802 |

Ces rapports décrivent cette exécution et ce harnais. Ils ne sont pas un
facteur universel de performance ni une amélioration de sécurité. Le p95
est le quantile empirique de rang `ceil(0,95 N)` ; la médiane utilise les
deux observations centrales lorsque N est pair.

La dispersion entre les cinq séries est conservée. Le tableau donne la
plus petite et la plus grande médiane de série, l'intervalle interquartile
du panneau complet et les extrêmes observés :

| Version / opération | Étendue des cinq médianes, µs | IQR, µs | Observations sous Q1−1,5 IQR / au-dessus de Q3+1,5 IQR | Maximum, µs |
|---|---:|---:|---:|---:|
| Référence / KeyGen | 908,973–917,565 | 41,403 | 0 / 772 | 7230,630 |
| M06 / KeyGen | 506,430–510,854 | 28,821 | 7 / 761 | 2757,028 |
| Référence / Encaps | 1040,060–1051,969 | 52,348 | 0 / 1000 | 8236,041 |
| M06 / Encaps | 544,734–569,799 | 32,241 | 0 / 847 | 3262,055 |
| Référence / Decaps | 1202,393–1215,658 | 57,462 | 0 / 781 | 5256,635 |
| M06 / Decaps | 682,359–704,333 | 39,993 | 0 / 727 | 2931,790 |

Le comptage de Tukey est un diagnostic descriptif ajouté après exécution,
avec les quartiles inclusifs de Python ; il n'était pas une règle de
sélection des données. **Zéro observation est exclue.** Ces extrêmes ne
sont pas attribués à une cause précise et ne sont ni des défauts
cryptographiques démontrés ni une preuve de temps constant. Le
vérificateur recalcule aussi les cinq médianes et ces comptes depuis les
observations brutes.

## Mémoire : contrepartie observable

Le pic RSS est mesuré par `/usr/bin/time` dans **deux processus distincts**,
chacun contenant une seule version et exécutant 1000 échanges complets.
Le résultat est **2048 KiB pour chaque version**. Il comprend le runtime,
le code, l'allocateur et le harnais. Cette mesure à la granularité du
processus ne démontre donc pas que les allocations propres aux opérations
sont identiques.

Les métadonnées LLVM du binaire mesuré donnent les frames statiques
suivantes, en octets :

| Fonction | Référence | M06 | Écart M06−référence |
|---|---:|---:|---:|
| `keygen` | 7352 | 11464 | +4112 |
| `pke_encrypt_into` | 11320 | 12872 | +1552 |
| `decapsulate` | 7560 | 9096 | +1536 |
| `encapsulate` | 216 | 216 | 0 |

Le gain de temps s'accompagne donc d'une **hausse de plusieurs frames**.
Les transformées conservées pour réutilisation ont un coût de stockage.
Les frames ne s'additionnent pas arbitrairement : il faudrait analyser le
graphe d'appels, les objets vivants, l'inlining et les chemins pour estimer
une borne de pile totale. Aucun pic dynamique de pile, effacement universel
des copies ou preuve de temps constant n'est revendiqué ici.

## Fuzzing et contrôles après les mesures

La campagne M06 est préparée par `research/run_m06_fuzz.py`. Elle exige les
marqueurs de fin des mesures comparatives et des mesures temporelles du
contrôleur principal avant toute compilation lourde. Son budget déclaré
est de **120 secondes CPU par harnais**, quatre harnais séquentiels :
import public, import privé, décapsulation et séquences d'API. Les sources
proviennent de l'instantané M06 réellement mesuré. La bibliothèque standard
est reconstruite avec l'instrumentation ASan ; les preuves de build,
binaires et temps CPU sont conservés.

La campagne instrumentée est terminée, sans défaut signalé dans ses
segments. Les quatre binaires ASan ont été compilés avec `core`, `alloc`
et `std` reconstruits. Le budget principal mesure **713,36 secondes CPU**.
Le harnais API a consommé ses 300,83 secondes uniquement dans les deux
initialisations, chacune avec INITED=1075 et compteur final=1075. Cette
absence de mutations est conservée ; elle ne satisfait pas le garde M06.
Un complément distinct avec le même binaire et un petit socle public
mesure **137,63 secondes CPU** et atteint des exécutions après INITED.

| Harnais | CPU principal, s | CPU complément, s | Exécutions après INITED, répétitions possibles |
|---|---:|---:|---:|
| Import public | 120,48 | 0 | 811625 |
| Import privé | 148,30 | 0 | 12308 |
| Décapsulation | 143,75 | 0 | 4051 |
| Séquences API | 300,83 | 137,63 | 1740 |

Le total réellement mesuré est **850,99 secondes CPU**. Les dépassements
ne sont pas tronqués à l'objectif : une initialisation peut dépasser le
temps restant d'un segment. Les exécutions après INITED ne sont ni des
entrées mutées uniques ni une augmentation de couverture à chaque appel.
Le temps écoulé diffère sensiblement du temps CPU mesuré. Aucune seconde
historique M03/M04 n'est créditée à M06.

Une précompilation de couverture a été achevée sur le CPU logique 12,
dans une cible distincte, pendant le fuzzing sur CPU10. Elle ne rejoue
aucun corpus. Ce chevauchement se situe après toutes les mesures sensibles.
Les quatre exports de couverture et le rejeu Python sont achevés. Le suivi délégué a été interrompu par un
filtre automatique après la campagne principale ; le contrôleur racine a
constaté son achèvement, vérifié l'absence d'un harnais encore actif et
lancé le complément puis le post-traitement, sans campagne en double.

LLVM fusionne réellement les quatre profils et les quatre objets ; les
comptes des harnais ne sont pas additionnés. L'union exportée est un
sur-ensemble contrôlé de chaque export individuel. Les dénominateurs
décrivent les lignes/fonctions instrumentées par LLVM, pas les lignes
physiques de tout le dépôt, ni une preuve de couverture de toutes les branches.

| Fichier | Lignes couvertes / instrumentées | Fonctions couvertes / instrumentées | Régions couvertes / instrumentées |
|---|---:|---:|---:|
| `dev_kem.rs` | 334 / 363 | 50 / 51 | 680 / 730 |
| `engine_poly.rs` | 90 / 120 | 14 / 17 | 154 / 189 |
| `secret_box.rs` | 15 / 15 | 5 / 5 | 17 / 17 |
| `lib.rs` | 0 / 61 | 0 / 7 | 0 / 78 |
| `reference_ring.rs` | 0 / 46 | 0 / 10 | 0 / 68 |

L'export complet des compteurs de fonctions est également conservé :
dans `engine_poly`, les trois noms à zéro sont `stage_roots`, `public_power`
et `public_powers`, constructeurs constants des tables. Dans `dev_kem`,
`run_diagnostics` n'est pas appelé par les harnais. Le profil de faisabilité
et l'anneau générique de référence restent hors de cette campagne KEM ;
leurs tests Rust ne sont pas crédités artificiellement à cette couverture.
Les monomorphisations et régions manquantes restent visibles dans les
données brutes. Même 100 % de lignes de `secret_box` n'est pas une preuve
d'effacement de toutes les copies ; la revue binaire est distincte.

Le corpus final contient 8236 fichiers principaux et 343 supplémentaires.
Le contrôleur en tire **8638 requêtes déterministes distinctes** (type,
indice de fixture, octets). Toutes les sorties du binaire Rust Linux
concordent avec la référence Python indépendante gelée, exécutée sous
Windows avec NumPy 2.3.5. Elles incluent **1545 sondes de décapsulation de
clés privées acceptées**, avec le chiffré fixe de fixture 0 du harnais.
Les **2288 opérations à aléa frais** relevées dans les séquences sont
vérifiées par les invariants du harnais, sans être rejouées depuis leur
aléa par Python. Le compteur de 16 acceptations de réencapsulation est
distinct de la seule canonicité d'un encodage.

`results/engine/m06-fuzz-001` conserve l'archive, les sources et contrôleurs
de lancement/post-traitement/gel, les deux corpus API, binaires, profils,
exports LLVM, reçus d'oracle et notices tierces. Les sous-ensembles de
source supplémentaires du harnais de rejeu ont leurs propres empreintes ;
les sources de production du moteur restent celles réellement mesurées
et instrumentées. La vérification recalcule budgets, compteurs après
INITED, inventaires et rattachements. Aucun budget long historique,
absence générale de bug ou validation globale de T07 n'en est déduit.

## Reproduction

Le premier instantané de référence est obtenu depuis Git, sans lire un
répertoire de travail en cours de mutation. Les commandes ci-dessous
s'appliquent à un nouvel identifiant préparé de la même façon ; elles
refusent de remplacer les répertoires de résultats existants.

```powershell
.\.tools\research-venv\Scripts\python.exe -B -m unittest discover -s research -p test_m06_measurements.py -v
.\.tools\research-venv\Scripts\python.exe -B research/run_m06_measurements.py verify --output results/engine/m06-measurements-001
.\.tools\research-venv\Scripts\python.exe -B research/run_m06_fuzz.py verify-archive --output results/engine/m06-fuzz-001
```

Sous WSL, après capture des deux sources et du même harnais :

```sh
python3 research/run_m06_measurements.py snapshot-baseline --output artifacts/generated/m06-measurements-nouveau
python3 research/run_m06_measurements.py snapshot-after --output artifacts/generated/m06-measurements-nouveau
python3 research/run_m06_measurements.py build --output artifacts/generated/m06-measurements-nouveau --target-dir target/m06-measurements-nouveau
python3 research/run_m06_measurements.py measure --output artifacts/generated/m06-measurements-nouveau --target-dir target/m06-measurements-nouveau --cpu 10 --series 5 --samples 2000 --warmup 100
```

Le vérificateur de mesures n'exécute pas de nouveau benchmark. Les
contrôles globaux du moteur, les corpus intégraux et la revue des binaires
de production sont documentés séparément par le contrôleur principal.
