# M15 — lot reproductible de conformité arithmétique sous Windows

Ce lot permet de rejouer **31 obligations SMT**, un **certificat algébrique
NTT** et **21 tests de composants** à partir des sources du dépôt. Il porte
sur l'arithmétique et sa liaison à certains corps Rust du profil
`KEM1536-DEV-Q7681-R1`. [PROOF.md](PROOF.md) précise les théorèmes, leurs
préconditions et les dépendances de confiance.

Ce premier lot publie les instruments, entrées et résultats nécessaires à
ce périmètre M15 délimité. L'installation complète et le rejeu ont réussi
depuis un clone indépendant, avec un cache initialement absent, puis une
seconde fois hors ligne. Cet essai utilise le même PC Windows et CPython
3.13.7 ; il ne constitue pas un essai sur une machine ou un système vierge.

Le job GitHub Actions `m15-reproducibility-windows` installe le solveur et
exécute ces contrôles pour la révision courante, séparément des contrôles
habituels du moteur sous Windows et Ubuntu. Son résultat et ses journaux
font foi pour le commit examiné : consulter [les exécutions de la CI](https://github.com/MajidNIMAR/mlkem-1536-core/actions/workflows/ci.yml).
La préparation du job ne suffit pas à attester sa réussite.

## Prérequis et périmètre

- Windows x64 et CPython 3.13 x64, accessible par `python` dans PowerShell.
- Une copie complète du dépôt **contenant ce lot**, avec ses fichiers à
  leur emplacement prévu. Les commandes ci-dessous partent de sa racine.
- Un accès réseau pour la première installation du solveur, sauf si le
  wheel exact est déjà présent dans le cache local.

Le lot lit les deux sources déjà publiques
[engine_poly.rs](../../../../crates/kem1536/src/engine_poly.rs) et
[dev_kem.rs](../../../../crates/kem1536/src/dev_kem.rs). Leurs empreintes
sont contrôlées : les résultats se rapportent à ces octets précis. Les
sources sélectionnées sont celles de la référence publique
`8b21a051d6de29055395c0c4427a753bcd9576a5`, mais ce commit antérieur ne
contient pas ce nouveau paquet. Il faut donc utiliser une révision qui
inclut le paquet et conserve les entrées liées par son manifeste.

Aucun compilateur Rust, binaire du moteur, clé applicative ou autre lot
privé M11–M14 n'est nécessaire pour ce rejeu. Les 21 tests de composants
sélectionnés ici ne représentent pas les 82 tests annoncés pour l'ensemble
des travaux privés M11–M15.

Le manifeste conserve l'empreinte du lot testé depuis la copie neuve. La
présentation et les métadonnées de publication ont ensuite été actualisées ;
les instruments et les 78 entrées scientifiques sélectionnées restent
identiques. Le lot actuel et ses deux entrées Rust sont contrôlés par son
propre manifeste, puis par le job de la révision publiée.

## Installation verrouillée du solveur

Depuis la racine du dépôt :

```powershell
python -I -S -B research/reproducibility/m15/implementation/setup_windows.py
```

Le programme utilise le wheel officiel Windows x64 de `z3-solver 4.15.4.0`,
identifié par [solver-source.json](solver-source.json), le reçu PyPI
[pypi-release.json](pypi-release.json) et [solver.lock.json](solver.lock.json).
Il contrôle les octets téléchargés et les membres installés. Le wheel
attendu mesure 16 259 597 octets et son SHA-256 est :

```text
00e35b02632ed085ea8199fb230f6015e6fc40554a6680c097bd5f060e827431
```

L'installation reste dans `.tools/m15-proof/site-packages/`, avec le wheel
en cache sous `.tools/m15-proof/`. Elle ne modifie pas les paquets Python
globaux. Les reçus d'installation sont placés dans
`.tools/m15-proof/setup-receipts/`. Conserver le wheel et les fichiers
installés : le contrôle de la chaîne d'outils compare le paquet installé
au wheel épinglé.

Une fois le wheel exact disponible dans le cache, une installation sans
réseau s'effectue ainsi :

```powershell
python -I -S -B research/reproducibility/m15/implementation/setup_windows.py --offline
```

Les options `-I -S -B` isolent l'interpréteur des personnalisations Python
usuelles et évitent l'écriture de fichiers de bytecode. Les points d'entrée
ajoutent explicitement leur répertoire contrôlé pour charger les modules
du lot. Le rejeu utilise des préfixes de cache neufs pour ignorer les anciens
bytecodes et contrôle l'origine des modules Z3 et de son image native chargée.
Python lui-même et les composants système de Windows restent des dépendances
de confiance ; le lot ne qualifie pas tout l'environnement d'exécution.

## Une commande pour le rejeu

Après l'installation :

```powershell
python -I -S -B research/reproducibility/m15/implementation/verify.py
```

Ce point d'entrée effectue les contrôles du manifeste et de la chaîne
d'outils, rejoue les 31 obligations SMT, vérifie le certificat NTT et lance
les 21 tests de composants. Il ne télécharge ni n'installe de dépendance.
Chaque exécution conserve ses journaux et son reçu dans un sous-répertoire
distinct de `.tools/m15-proof/replay-receipts/`.

Un succès exige la réussite de toutes ces étapes. Pour le SMT, les
obligations sont reconstruites depuis les sources, comparées aux assertions
capturées, puis soumises à nouveau à Z3. Un timeout ou une absence d'erreur
ne remplace pas un résultat `UNSAT`.

Pour contrôler seulement l'intégrité du paquet et des entrées Rust, sans
installation de Z3 et sans réseau :

```powershell
python -I -S -B research/reproducibility/m15/implementation/verify.py --check-only
```

Ce dernier mode ne rejoue aucune preuve ni aucun test scientifique. Sa
réussite atteste uniquement les contrôles d'intégrité annoncés, et non les
31 résultats SMT, le certificat NTT ou les 21 tests.

Les contrôles des outils d'empaquetage se lancent séparément :

```powershell
python -I -S -B research/reproducibility/m15/implementation/test_tools.py
```

Ces 18 tests examinent notamment les refus d'entrées modifiées, les chemins,
le cache du solveur, l'extraction et l'isolation Python. Leurs petits jeux
d'essai restent dans `.tools/m15-proof/support-fixtures/`. Ils sont distincts
des 21 tests scientifiques et d'un rejeu depuis une copie neuve.

## Contenu et limites de la preuve

[MANIFEST.json](MANIFEST.json) lie les fichiers du paquet et les entrées
source. L'empreinte de ce manifeste doit être rattachée à une révision de
confiance du dépôt ; un manifeste local ne constitue pas une signature.
La sélection scientifique retient `acquisition-005/`, avec les
31 fichiers SMT-LIB et les 31 objets de preuve Z3 correspondants, ainsi que
`ntt-certificate-002.json`. Les instruments, reçus et révisions nécessaires
à l'explication de ce lot sont également conservés. Les notes
`REVISION_002.md` à `REVISION_005.md` décrivent son évolution ; les anciens
lots et journaux qu'elles mentionnent restent conservés ailleurs et ne
font pas partie de cette sélection.

Les objets de preuve Z3 ne sont pas vérifiés par un second noyau
indépendant. Le solveur épinglé, le traducteur source restreint et la liaison
du gabarit NTT à son interprétation appartiennent à la base de confiance.
Les tests de composants contrôlent notamment la non-vacuité des domaines
et le comportement face à des mutations synthétiques ; celles-ci ne
décrivent pas des défauts constatés du moteur.

Les conclusions s'appliquent à tout le domaine déclaré des fonctions et
du réseau traités, sous les préconditions détaillées dans
[PROOF.md](PROOF.md). Elles ne couvrent pas l'ensemble PKE/KEM, les clés
importées en général, les dépendances, la compilation, le temps constant
ou l'effacement universels. Elles ne ferment pas l'argument de sécurité
cryptographique **C01**, qui reste distinct et ouvert.

Les conditions d'utilisation et les attributions figurent dans
[THIRD_PARTY.md](THIRD_PARTY.md) et dans les notices du dépôt.

## Journaux de la CI

Le job Windows conserve un artefact `m15-lot1-windows-<run_id>-<run_attempt>` contenant
les reçus JSON et journaux des étapes, y compris ceux disponibles en cas
d'échec. Il exclut le wheel, les bibliothèques natives du solveur et les
fixtures locales. Ces journaux complètent les entrées scientifiques suivies
dans Git ; ils ne constituent pas une vérification par un second noyau de
preuve ni une qualification des autres plateformes.
