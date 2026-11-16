# M09 — distribution et décision de promotion

16 novembre 2026. La distribution scalaire **002** est qualifiée en interne
et ses paquets sont disponibles dans le [recueil public M09](../results/engine/m09-001/distribution.tar.gz).
Le [check local complet](../results/engine/m09-verification-001/) et le
[suivi du lecteur de stockage](../results/engine/m09-reader-review-001/)
sont clos. La [CI neuve 43806407492](https://github.com/MajidNIMAR/majax_mlkem1536/actions/runs/43806407492)
réussit sur Windows et Ubuntu, au commit testé
`fdd323dcf840b0d12fd43a446acffbd0cce83d7b`, avec les 439 tests Python
exécutés sur chaque OS, aucun ignoré. Le [reçu public](../results/publication/r6-m09-001/)
lie les cartes d'export, 37 entrées compilables et images originales.
Le [reçu de promotion locale](../results/engine/m09-canonical-001/) constate
la copie de l'original Windows M09 vers `target/release/kem1536.exe` puis
16 échanges/rejets frais et cinq refus normaux. Son SHA-256 est
`9eb95fb2cb9a8531a216012b4cff71d6b10d1a7951285d9d3c666f8186002255`.
Ce remplacement séparé ne modifie ni les archives 001 rejetées ni M08.

## Préparatifs historiques et rejet de 001

Le premier jeu d'images M09 (`m09-final-001`) est
**REJECTED_FOR_PROMOTION**. La revue Windows a identifié une nouvelle
copie de coefficients via les sauvegardes ABI XMM de la transformée
auto-vectorisée. Les contrôles de construction et de distribution ci-dessous
ne lèvent pas ce rejet. À cette décision de rejet, le binaire habituel
M08 avait été conservé.

`research/m09_distribution.py` prépare de nouvelles archives à partir
des seules sources capturées sous `m09-final-001/source`, sans compiler
l'arbre actif. Chaque archive conserve le CLI original, ses sources
compactes, les licences des dépendances compilées et les notices de la
chaîne Rust 1.91.1. Les graphes Cargo normaux et de compilation ne sont
pas une attribution des symboles réellement liés.

Une répétition CLI par OS utilise une cible nouvelle, les mêmes outils,
caches et chemin source. Linux retrouve les octets bruts exacts ; Windows
ne diffère qu'aux champs timestamp COFF et checksum PE, masqués dans des
copies temporaires. Les originaux et répétitions restent inchangés.
Ce n'est pas une reproduction par un tiers.

Les quatre CLI (original/répétition × Windows/Linux) passent chacun 16
échanges frais, 16 rejets implicites et cinq refus normaux de commandes
réservées à la recherche. Les dépendances natives sont inspectées dans
les tables PE et les entrées ELF NEEDED/versions GLIBC. Les bibliothèques
système sont des prérequis, pas des composants livrés.

Les cinq images de diagnostic par OS disposent de notices séparées,
construites à partir de l'union conservatrice des graphes Cargo verrouillés
des workspaces principal, consommateur et probe. Cette union n'affirme ni
que chaque paquet a été compilé dans chaque image, ni qu'il a été lié.
Elle identifie explicitement les images originales et leurs sources.

Le dossier `artifacts/generated/m09-distribution-001` conserve les archives,
recettes, messages Cargo, métadonnées, licences, preuves de comparaison et
smokes. Les paquets portent `PROMOTION_STATUS.json` et la décision négative.
Le lecteur `verify --output <dossier>` ne lance aucun compilateur, binaire
ou processus externe ; le gel global M09 peut le rejouer sur une extraction
temporaire des mêmes données. Aucun audit externe ou preuve universelle
de temps constant/d'effacement n'est déduit de la distribution.

La variante scalaire correctrice a un snapshot et une distribution distincts.
Le contrôleur sélectionne leurs nouveaux dossiers avec `--build-root`,
`--output` et `--target-root`. Préparer les sources et répéter la construction
ne qualifie pas cette variante. Pour terminer une archive avec le statut
`QUALIFIED_INTERNAL`, `finish` exige un reçu de l'agent principal liant le
profil, le manifeste source exact, les deux CLI originaux, les trois
contrôles latence/mémoire/revue binaire et au moins trois fichiers de preuve
par empreinte. Ces fichiers et le reçu sont copiés dans la distribution et
recontrôlés par son lecteur hors ligne. Ce statut désigne un périmètre
interne mesuré et revu ; C01, l'audit externe et les garanties universelles
restent des obligations séparées. L'archive rejetée001 conserve son statut.

## Distribution scalaire002

Le reçu `artifacts/generated/m09-acceptance-002.json` lie six preuves et le
manifeste source
`0829c8112ce771072c63ae07ae5a7f32cc7a06cf91531950047ddd4685cea3eb`.
Après vérification de ce reçu, la distribution002 est fermée avec le
statut **QUALIFIED_INTERNAL**. Le lecteur pur normal et `python -O`
passent ; les sept tests de limites des comparaisons et du gate passent.
La qualification du projet complet et la CI restent des reçus distincts.

| Produit | Octets | SHA-256 |
|---|---:|---|
| Windows GNU x86-64 ZIP | 4 342 837 | `277cc74bc79f0ee112e0fa22d213b266f38b7fc792fc4d5dde3fdad50cea8731` |
| Linux x86-64 tar.gz | 3 606 683 | `3d91dd3f6704ea533c08b6ee02e836ef5751fc6d9bb71d1095b0906cd3d9235c` |
| Sources compactes tar.gz, 61 fichiers | 1 375 429 | `e912670f89f46f41b1878d9ac4f1c9ec3e865972c8295a70a3ad6a1374ba8df7` |

Les paquets Windows/Linux ont respectivement 140/142 membres. Leurs
CLI originaux sont `9eb95fb2…6002255` et `7cc2368a…41fd01` ; les
empreintes complètes et celles des répétitions sont dans leurs provenances.
Linux retrouve les octets exacts ; Windows conserve sa comparaison limitée
aux deux champs PE. Aucun remplacement du binaire habituel n'a été
effectué par le contrôleur de distribution.

Les inventaires CLI comprennent 51/52 paquets compilés et 111/113 textes
de licence, chaîne comprise. Les notices de diagnostic restent séparées :
59/60 paquets résolus en union conservatrice et 121/123 textes. Il ne
s'agit pas d'attributions des symboles liés. Les prérequis Linux constatés
sont `ld-linux-x86-64.so.2`, `libc.so.6`, `libgcc_s.so.1`, avec une version
GLIBC maximale importée 2.34. Windows n'importe que les sept DLL système
énumérées dans `dependencies.json` ; le répertoire PE d'importations
différées est absent.

Le compact garde l'addendum tel qu'il existait dans le snapshot compilé,
avant l'ajout rétrospectif de son tableau de résultats. Le reçu de reprise
du setup conserve cet écart documentaire, sans changer les 57 entrées du
snapshot. Le gel global M09 conserve les deux décisions de distribution.

## Contrôles locaux et clôture publique

Le check complet local conserve ses versions de contrôle avant le
durcissement du lecteur : 438 tests Python, fmt, Clippy strict, tests Rust
par défaut et toutes fonctionnalités, puis les rejeux requis. Le suivi
distinct du lecteur vérifie notamment les parties même si une archive
complète existe à côté, avec quatre tests ciblés et la suite de 439 tests
Python. Les 37 entrées compilables qualifiées et les acquisitions sont
inchangées ; les récépissés locaux liés en tête de ce document donnent les
versions exactes et leurs empreintes.

Une première exécution publique verte a laissé un test de distribution
optionnel non exécuté. Le correctif de test du commit source local
`d616912fddd1e303c171678d0c6690286b570d38` relit désormais le recueil publié,
sans dépendre du chantier local ignoré par Git ; ses sept tests ciblés
passent. La seconde CI utilise le commit public indiqué en tête du document.
Son [reçu final](../results/publication/r6-m09-001/) relie les résultats
Windows/Ubuntu, le commit testé, les cartes d'export, les 37 entrées
compilables et les images originales. La [promotion du binaire habituel](../results/engine/m09-canonical-001/)
est constatée par sa copie et son contrôle natif, sans attribuer un nouvel
audit ou une nouvelle campagne à cette opération.


## Accès depuis le dépôt public

Les chemins `artifacts/generated` ci-dessus décrivent le chantier local.
La copie publique intégrale est le [recueil de distribution M09](../results/engine/m09-001/distribution.tar.gz),
lié à la provenance et au lecteur de `results/engine/m09-001`. Il contient
les archives finales à sa racine :

- `majax-r6-m09-x86_64-pc-windows-gnu.zip` ;
- `majax-r6-m09-x86_64-unknown-linux-gnu.tar.gz` ;
- `source.tar.gz`.

Après vérification du recueil, ces trois membres peuvent être extraits avec
un lecteur tar standard dans un nouveau dossier sous `target`. Les paquets
incluent leurs empreintes, sources et licences ; le lecteur Python du projet
rejoue en plus les liens aux acquisitions. Le dossier de données conserve
également les préparatifs rejetés001, clairement distincts des paquets002.
