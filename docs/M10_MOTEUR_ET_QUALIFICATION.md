# M10 — bilan interne du moteur et de sa qualification

16 novembre 2026. État lors de cette rédaction : les raccords de sécurité,
la décision de paramètres, le durcissement PC 003, ses contrôles fonctionnels,
mesures et répétitions locales sont documentés. La campagne longue neuve
`m10-fuzz-001` a atteint ses quatre budgets CPU conservateurs après INITED,
sans défaut observé. La couverture source/branches et le rejeu indépendant
du nouveau corpus sont achevés, avec leurs reçus distincts. La distribution
et le rejeu des 10 908 membres scellés sont vérifiés. Le check local Windows
complet passe, avec 514 tests Python sans aucun ignoré. La CI neuve
Windows/Ubuntu et la promotion canonique restent en attente de leurs
résultats effectifs.

Ce bilan suit le [protocole M10](PROTOCOLE_M10.md) et porte sur les quatre
chantiers autorisés. La revue cryptographique extérieure est différée ;
ce document constitue un bilan interne. C01 reste ouvert et aucun niveau
global équivalent ou supérieur à ML-KEM-1024 n'est déclaré.

## Profil et sources du candidat 003

Le profil reste `KEM1536-DEV-Q7681-R1` : rang 6, degré 256, q=7681,
CBD(3), u exact et v comprimé sur cinq bits. Les formats, domaines, octets
déterministes et l'interface publique à entropie OS sont conservés. Le secret
partagé et les espaces de graines/messages restent de 256 bits.

Le manifeste de `artifacts/generated/m10-final-003/source.json` couvre
56 fichiers, sous SHA-256
`67084be5ab1cde058661104b16e738138db7993dec001ac39625feb830b2810d`.
La capture est rattachée au commit
`a9de81f3e1173b1f60ebe16a7e37aa104e99bd36`. Le source `dev_kem.rs`
compilé porte l'empreinte
`7b64b6e1adf18d5a3e0b66e6c95eb392aebb24c20077c74aadd304fcadc43d32`.
L'identité de la capture complète, les reçus de construction et les empreintes
des images précisent la réalisation étudiée ; le seul nom d'un commit
ne remplace pas cette liaison.

Les cibles de qualification sont Windows GNU x86-64 et Linux GNU x86-64,
avec Rust 1.91.1 et dépendances verrouillées. Android et l'intégration
Messenger restent différés. Le code de production conserve
`unsafe_code=forbid` ; les interfaces déterministes restent réservées aux
tests et à `research-vectors`.

## 1. Argument de sécurité : raccords nouveaux et obligations restantes

L'[étude de composition M10](SECURITE_M10.md) traite le programme à matrice
publique semée et bruits semés, avec conventions d'avantage et ressources
explicites. Elle distingue les oracles idéaux classiques, leur accès
quantique et les primitives SHA3/SHAKE concrètes.

La simulation de matrice explique les mêmes flots bruts que le moteur,
y compris mots rejetés, bits hauts ignorés par Parse et préfixes partiels.
Elle relie les deux hybrides PKE aux instances MLWE(6,6) et MLWE(7,6),
dont le second garde six polynômes secrets. Avec un plafond de simulation
de 512 candidats par cellule, les 36 cellules demandent au plus 18432 mots,
soit 36864 octets de préfixes. Le majorant d'abandon de cette simulation
idéale satisfait `2^-540 < t_L <= 2^-539`. Ce compte inclut un coût de
simulation ; il n'est pas une mesure de la mémoire ou du temps du moteur.

Le couplage des bruits reçoit un hybride QROM explicite par normes. Les
compteurs sont ceux du distingueur CPA et de sa simulation, avec leurs
appels auxiliaires. Les cartes de ressources comptent aussi chiffrements,
lectures XOF, domaines N/KG/A, tables, temps et mémoire. Le raccord FO
classique conserve son terme de correction et ses conventions. Deux voies
FO quantiques, GYY et MRE, sont examinées avec leurs conditions et pertes.

Les contrôles finis nouveaux comprennent notamment 203360 préfixes de
matrice transformés, 49149 flots de candidats, 40320 paires oracle/circuit
quantique, 1536 cas du pont contrôlé et 6248 bandes aléatoires de KEM réduits.
Ces nombres décrivent des modèles finis et leurs contrôles, sans constituer
une énumération des adversaires du KEM R1. Le raccord lexical de sécurité
aux fonctions de production comporte 17 ancrages ; il est distinct du pont
de correction à 78 ancrages de la réalisation 003.

**C01 demeure ouvert.** Les obligations principales restent la calibration
des deux avantages MLWE aux ressources des réductions, l'instanciation
complète des circuits et appels QROM avec une marge utilisable, les hypothèses
calculatoires examinées pour les SHA3/SHAKE fixes et la revue cryptographique
indépendante différée. Le rang ne fournit pas automatiquement ces garanties.
Le support réduit d'une matrice produite par une fonction fixée interdit
également de lui attribuer une uniformité statistique complète ; cela
ne démontre pas à lui seul un distingueur efficace.

## 2. Paramètres : 40 estimations et maintien de R1 pour le développement

La [décision de paramètres M10](DECISION_PARAMETRES_M10.md) repose sur
40 estimations neuves : deux profils, deux jeux finis d'échantillons,
deux modèles de coût et cinq familles. L'estimateur est épinglé à
`malb/lattice-estimator@7d59f866655362ea8eab803dbc833710c2bc362a`.
Les 40 travaux donnent des coûts finis, sans exception, expiration ni
remplacement, sous un plafond de 300 secondes murales par travail.

Les 20 paires préenregistrées sont favorables au proxy R1 dans leurs
conventions respectives. Les familles sont uSVP, BDD, hybride primal MITM,
dual simple et dual hybride MATZOV. Les modèles sont MATZOV classique et
une sensibilité de réduction BCSS23 ; cette dernière n'est pas une estimation
complète des portes d'une attaque quantique.

Pour le jeu key, les plus petits `log2(rop)` de ce panneau sont ceux du
dual hybride MATZOV :

| Modèle du panneau | ML-KEM-1024 | R1 | Écart conditionnel |
|---|---:|---:|---:|
| MATZOV classique | 262,336 | 383,773 | +121,437 |
| Sensibilité BCSS23 | 214,789 | 325,958 | +111,169 |

Ces valeurs sont des sorties heuristiques sous contrats déclarés. Les
succès, la mémoire, les hypothèses structurées du module et les ressources
des réductions empêchent de les transformer en un niveau global en bits.
Dix sorties classiques R1 extrapolent la réduction au-delà de β=1024.
Les hybrides primaux retiennent ζ=0 dans cette exécution, sans démontrer
un optimum global. Une réoptimisation sous plafond RAM et la traduction
des analyses modernes de scores restent ouvertes.

La décision est de **conserver R1 pour le développement**, sans nouveau
profil ni gel cryptographique final. La marge de correction historique
run-004 est rattachée avec sa population et ses hypothèses : environ
`2^-310,086` dans le modèle CBD, contre le seuil historique `2^-174,8`.
Son transfert en oracle idéal ne certifie pas chaque clé fixée, SHAKE
concret ou une recherche adaptative d'échecs. Les essais du moteur
ne mesurent pas directement une probabilité aussi rare.

Les espaces de graines/messages de 256 bits et les 32 octets de sortie
restent une limite commune. Le modèle de recherche multi-cibles conserve
le coût des prédicats et distingue graines communes, messages sous une
même clé et messages sous des clés différentes. Le format a un coût réel :
clé publique 2528, chiffré 2656 et clé privée développée 5088 octets ; une
clé publique plus un chiffré représente 2048 octets supplémentaires par
rapport aux formats ML-KEM-1024. Aucune nouvelle comparaison de vitesse
entre les réalisations de ces deux KEM n'est fournie par ce panneau.

## 3. Durcissement : trois itérations et images effectivement examinées

La [revue du cycle secret M10](REVUE_CYCLE_SECRET_M10.md) conserve les
constats négatifs et le chemin de correction. Les captures sont distinctes :

| Capture | Builds de qualification | Résultat fonctionnel | Décision issue de la revue |
|---|---:|---|---|
| Baseline M09 recompilée | 12 | Référence de comparaison | Sources prépatch conservées |
| Candidat 001 | 12 | Corpus complets concordants | REJECTED_FOR_PROMOTION : état SHAKE déplacé et source locale de sortie de 32 octets |
| Candidat 002 | 12 | Corpus complets concordants | REJECTED_FOR_PROMOTION : SHAKE corrigé, source locale de sortie de 32 octets encore présente |
| Candidat 003 | 12 | Corpus complets concordants | BOUNDED_REVIEW_PASS sur les quatre images PC par défaut |

Le total est **48 builds de qualification**, six sortes d'image par OS :
CLI par défaut, consommateur, recherche, diagnostic temporel, latence et
sonde mémoire. Les répétitions de distribution décrites plus bas sont
deux constructions supplémentaires comptées séparément. Les travaux
ASan/couverture ont leur propre comptabilité.

Le passage à `derive_into` et `xof_into` écrit les dérivations dans les
propriétaires existants. `CtAssign` remplace la sélection retournant un
tableau rempli, avec une vue empruntée sur la clé favorable. La revue 001
a ensuite tracé l'état SHAKE absorbé original restant en pile après son
déplacement : dans N, la graine de 32 octets apparaissait littéralement à état+23..54,
car 56 octets étaient absorbés avant toute saturation du taux 136. Ce défaut
préexistait dans les quatre images baseline M09 et persistait dans 001.

002 conserve l'état sous emprunt avec `finalize_xof_reset`, permettant sa
remise à zéro et son effacement. La source locale de la sortie Decaps
restait cependant copiée vers la sortie ABI sans essuyage ultérieur.
003 effectue une copie explicite vers la sortie tout en conservant le
destructeur du propriétaire local. Les quatre images 003 montrent les
effacements de l'état SHAKE et du lecteur, puis 32 stores zéro couvrant
la source locale de sortie sélectionnée. Encaps écrit G32 directement
dans son tuple de sortie, puis efface G64.

La réalisation finale s'identifie par
`M10-borrowed-XOF-copied-output-3`, avec **78 ancrages**. Les variantes
M10 à 75/77 ancrages et les contrats historiques restent relus sur leurs
sources figées. Le pont ne constitue pas une preuve formelle de Rust.
Les invariants scalaires de transform M09 restent satisfaits dans 003 ;
le cœur polynomial et les formats R1 sont inchangés.

Les quatre images par défaut sont liées au manifeste 003, à leurs reçus
de build et à leur SHA-256. La revue se rejoue à partir des listings
conservés, sans exécuter le moteur. Elle laisse explicites le masque sensible
de validité stocké en pile, les registres, les sauvegardes SIMD héritées,
les appels indirects non résolus, les dépendances et les copies de l'appelant.
**La correction de ces résidus ciblés ne ferme pas l'effacement ou le
temps constant de tout le programme.**

## 4. Qualification : campagne, couverture et rejeu acquis, clôture en attente

### Corpus des trois itérations

Chaque itération 001, 002 et 003 a reçu une validation neuve sur Windows
et Linux : 1000 vecteurs, 10000 rejets appariés, 10000 mutations, 20000 entrées
de format et 88576 sondes du consommateur par OS et par itération.
Les accords sont conservés dans les trois `validation.json`, avec les
sources et contrôleurs effectivement exécutés. Les sondes du consommateur
énumèrent des cas de coefficient isolé et d'alignement ; elles ne couvrent
pas l'espace complet des vecteurs ou des clés.

Les validations de 001 et 002 restent attachées aux images refusées à la
promotion.003 possède ses propres validations. Les données historiques
R1 sont des témoins d'accord, sans crédit de fuzzing ou de campagne longue
transféré. Les 12 compilations d'une itération, les rejeux fonctionnels et
les exécutions de harnais restent des unités distinctes.

### Comparaison mesurée M09 → M10-003

`artifacts/generated/m10-final-003/measurements/evaluation.json` rapporte
40000 observations de latence : cinq séries AB/BA par OS, 500 observations
par opération/version/série, 100 échauffements et CPU 10. La référence M09
et le candidat 003 sont nouvellement construits et mesurés. Pour chaque
ligne ci-dessous, 2500 observations par version contribuent aux quantiles.

Les budgets préenregistrés sont un rapport de médianes au plus 1,05 et
un rapport p95 au plus 1,20. Aucun gain minimal n'est requis pour ce chantier
de durcissement. **Toutes les lignes passent leurs deux budgets.** Les
variations du tableau sont celles du candidat par rapport à la référence.

| OS | Opération | Médiane M09, ns | Médiane M10, ns | Variation | p95 M09, ns | p95 M10, ns | Variation p95 |
|---|---|---:|---:|---:|---:|---:|---:|
| Windows | KeyGen | 423300 | 423800 | +0,118 % | 638000 | 597600 | −6,332 % |
| Windows | Encaps | 461900 | 462600 | +0,152 % | 662400 | 645300 | −2,582 % |
| Windows | Decaps valide | 569400 | 570300 | +0,158 % | 895500 | 882700 | −1,429 % |
| Windows | Decaps rejet | 572500 | 568700 | −0,664 % | 827100 | 785900 | −4,981 % |
| Linux | KeyGen | 458424 | 468485,5 | +2,195 % | 668214 | 690995 | +3,409 % |
| Linux | Encaps | 511709 | 489647 | −4,311 % | 810152 | 709102 | −12,473 % |
| Linux | Decaps valide | 624547 | 628541 | +0,640 % | 935785 | 965244 | +3,148 % |
| Linux | Decaps rejet | 628019 | 601482,5 | −4,225 % | 993928 | 886192 | −10,839 % |

Le durcissement respecte donc les budgets malgré des médianes légèrement
plus hautes pour certaines opérations et plus basses pour d'autres.
La fréquence n'est pas fixée et l'isolation globale de l'hôte n'est pas
démontrée. Ces observations ne sont ni un gain universel de vitesse ni
une preuve de temps constant.

### Mémoire demandée et pile touchée

Les 432 observations de mémoire sont neuves : 216 pour la référence et 216
pour le candidat, avec 18 opérations, deux peintures et trois répétitions
par OS/version. Aucun ancien échantillon de mémoire n'est réutilisé.
Les 14 opérations utiles passent leurs budgets : maximum de pile touchée
au plus référence+1024 octets, sans hausse des allocations demandées.

| OS | Opération | Maximum M09, octets | Maximum M10, octets | Écart |
|---|---|---:|---:|---:|
| Windows | KeyGen | 7792 | 7792 | 0 |
| Windows | Encaps | 7672 | 7688 | **+16** |
| Windows | Decaps valide | 13048 | 12824 | **−224** |
| Windows | Decaps rejet | 13048 | 12824 | **−224** |
| Linux | KeyGen | 7192 | 7192 | 0 |
| Linux | Encaps | 7400 | 7400 | 0 |
| Linux | Decaps valide | 12696 | 12472 | **−224** |
| Linux | Decaps rejet | 12696 | 12472 | **−224** |

La hausse Encaps Windows de 16 octets est conservée comme coût ; elle ne
disparaît pas derrière la baisse Decaps. Les autres opérations utiles
gardent leurs maxima observés. La sonde mesure la pile touchée dans sa
fenêtre et les allocations demandées suivies ; elle ne fournit ni RSS,
ni borne universelle de pile, ni preuve d'absence de copies secrètes.
Un maximum observé à zéro ne signifie pas une opération sans pile.

### Diagnostic temporel neuf

Les deux fichiers `timing/{windows,linux}/analysis.json` de 003 totalisent
32000 observations : huit clés fraîches, cinq classes, 400 observations
par clé/classe/OS, 50 échauffements par classe et 32 contrastes par OS.
Aucun échantillon extrême n'est retiré. Les maxima de |t| sont :

| Cible | Maximum absolu de t | Seuil d'enquête | Franchissements |
|---|---:|---:|---:|
| Windows | 1,746352348 | 4,5 | 0 |
| Linux | 1,355093932 | 4,5 | 0 |

L'absence de franchissement est un résultat de diagnostic fini, sans
contrôle de comparaisons multiples ni preuve de temps constant.

### Distribution et répétitions locales

`artifacts/generated/m10-distribution-001` conserve les paquets des deux
CLI 003 originales et une nouvelle construction répétée par OS, sous les
mêmes outils, caches et chemin source. Linux est identique octet pour
octet, SHA-256
`1d8c015a849f4e53f5f83b0c734a1fadb98a9ff7084e8fdce1cf3747795935f2`.

Windows diffère en brut. Les comparaisons temporairement normalisées
ignorent exclusivement `COFF_TimeDateStamp` et `OptionalHeader_CheckSum`
et donnent le SHA-256 commun
`5316cc6f35f8f3a6f8d08054e82d1632d7d9bc678315094bd62b84d44115e88b`.
Les images brutes sont conservées et ne sont pas modifiées pour obtenir
ce résultat. Original et répétition exécutent chacun 16 échanges frais,
16 rejets implicites et les cinq refus attendus des commandes de recherche,
sur chaque OS. Cette répétition locale n'est pas une reproduction par tiers.

### Campagne longue : quatre budgets atteints

La campagne `artifacts/generated/m10-fuzz-001`, liée au candidat 003 et
au marqueur `m10-acceptance-001`, est terminée. Son reçu `verification.json`
confirme **8041,14 secondes CPU nouvelles au total**, dont **7408,48 secondes
CPU conservatrices après INITED**, en **33 segments**. Chacun des quatre
harnais atteint séparément le budget préenregistré de 1800 secondes après
INITED. Aucun défaut, échec de worker ou artefact d'échec n'est observé.

| Harnais | CPU | Segments | CPU total, s | Borne CPU après INITED, s | Exécutions après INITED | Entrées dédupliquées |
|---|---:|---:|---:|---:|---:|---:|
| import_public | 8 | 7 | 1807,33 | 1804,15 | 30628776 | 899 |
| import_private | 12 | 8 | 1889,04 | 1839,06 | 2119985 | 1022 |
| decapsulate | 14 | 8 | 2009,96 | 1945,84 | 423197 | 886 |
| api_sequence | 6 | 10 | 2334,81 | 1819,43 | 25273 | 1161 |
| Total | — | 33 | 8041,14 | 7408,48 | 33197231 | 3968 |

Le total CPU inclut l'initialisation ; seule la borne après INITED compte
pour les budgets. Chaque segment soustrait une borne haute observée du CPU
initial et 0,02 seconde couvrant l'arrondi GNU time. Sans observation valide,
son crédit est nul. Les initialisations, compilations, anciennes campagnes
et rejeux n'apportent aucun crédit aux 7408,48 secondes. Les segments
demandent 300 secondes murales à libFuzzer ; cette demande n'est pas un
plafond strict de durée observée. La borne mesure l'intervalle de processus
après INITED, pas exclusivement les instructions de mutation.

Les 33197231 exécutions incluent les répétitions. Les **3968 entrées**
sont dédupliquées par octets/SHA-256 **au sein de chaque harnais**, sans
promesse d'unicité entre harnais. Les corpus bruts sont conservés, avec
leur correspondance vers les corpus récoltés. Cette qualification utilise
Rust 1.91.1, ASan, la std reconstruite, des cibles de compilation neuves et
les contrôleurs capturés ; elle ne transfère aucun résultat M08/M09.

### Couverture LLVM : union réelle et classification des zéros

Le reçu `postprocessing/postprocess.json` confirme l'export de couverture
et le rejeu indépendant, sans modification de la source de campagne.
Les quatre objets de couverture sont neufs et distincts des binaires
ASan/std reconstruite de la campagne principale. Ils utilisent la std
distribuée : cargo-fuzz 0.13.1 refuse `--build-std` dans son mode coverage.
Les profils sont fusionnés et l'export conserve les quatre objets ; les
fractions des harnais, qui se recouvrent, ne sont pas additionnées.

L'union de `postprocessing/coverage-summary.json` porte sur les cinq fichiers
du cœur effectivement mappés par LLVM, compteurs nuls compris :

| Fichier | Lignes | Fonctions source | Régions | Branches LLVM |
|---|---:|---:|---:|---:|
| dev_kem.rs | 384/417 | 56/57 | 736/793 | 14/20 |
| engine_poly.rs | 93/130 | 14/17 | 154/199 | 4/4 |
| lib.rs | 0/61 | 0/7 | 0/78 | 0/14 |
| reference_ring.rs | 0/46 | 0/10 | 0/68 | 0/0 |
| secret_box.rs | 15/15 | 5/5 | 17/17 | 0/0 |
| **Union** | **492/669** | **75/96** | **907/1155** | **18/38** |

Les lignes représentent environ 73,54 % de ce périmètre mappé ;
`dev_kem.rs` atteint environ 92,09 %. Les **112 mappings de fonctions LLVM**
comprennent **25 instances à compteur nul**. Ils distinguent des
instanciations génériques et ne sont pas le dénominateur des 96 fonctions
source du résumé. Un compte 0/0 ne fournit aucun pourcentage de couverture.
Les exports complets, les mappings nuls et les côtés de branches non
observés restent conservés. Leur lecture dans la source 003 donne :

- **Profil historique et oracle algébrique hors parcours des harnais :**
  les sept mappings de profil de `lib.rs` et les dix de `reference_ring.rs`
  sont nuls. Les quatre harnais ciblent les API R1 et leur arithmétique
  spécialisée ; ils n'appellent ni le parseur de profil P0 ni l'anneau
  générique de référence. Ces fichiers restent dans les dénominateurs.
- **Tables publiques évaluées à la compilation :** les trois fonctions
  `public_power`, `public_powers` et `stage_twiddles` construisent les
  constantes NTT. Leurs mappings d'exécution et certains tuples de branche
  restent nuls, même si le résumé de branches d'`engine_poly.rs` affiche 4/4.
  Ce résumé n'affirme pas que chaque tuple de branche du JSON est non nul.
- **Diagnostic non appelé :** `run_diagnostics` est la seule fonction source
  non couverte de `dev_kem.rs`. Les harnais réalisent leurs contrôles via
  les API et n'appellent pas ce wrapper ; ses retours `SelfTestFailure`
  restent donc aussi à zéro.
- **Chemins défensifs non forcés dans cette acquisition :** les échecs
  d'aléa OS dans les deux instanciations de `fill_entropy_into`, leur
  effacement puis propagation par KeyGen/Encaps, et l'erreur de longueur
  du validateur interne ne sont pas parcourus. Les appelants fournissent
  à ce validateur des tranches de longueur déjà fixée. La région du panic
  de `row_nonce` reste nulle, ses appels utilisant des lignes bornées par
  le rang. Les tests séparés d'injection d'échec ne sont pas crédités à
  ces compteurs LLVM.
- **Instanciations d'effacement :** quatre mappings spécialisés de
  `SecretBox::wipe`/`Drop` pour les tailles 5088 et 2656 restent à zéro,
  malgré les 5/5 fonctions source agrégées de `secret_box.rs`. Une fonction
  agrégée couverte ne signifie pas que toutes ses instanciations le sont,
  ni que chaque copie secrète a été effacée.

Ces catégories expliquent les 25 instances nulles sans les retirer du
résultat. Les branches et régions non parcourues ne deviennent pas des
chemins prouvés impossibles. Cette couverture ne démontre ni tous les
chemins, ni le temps constant, ni l'effacement global ; les arêtes
libFuzzer restent une métrique distincte. Les dénominateurs de M08/M09
ne sont pas réutilisés pour annoncer un gain de couverture apparié.

### Rejeu indépendant du corpus récolté

Le reçu `oracle-replay.json` conserve **4263 requêtes déterministes
distinctes** issues des 3968 entrées récoltées. Une entrée `api_sequence`
peut produire plusieurs demandes ; ces deux comptes mesurent donc des
objets différents. Toutes les réponses Rust/Python concordent. Le rejeu
comprend **641 imports privés acceptés avec sonde indépendante de
décapsulation** et **16 acceptations de ré-encryption** observées par
la référence pour les demandes de chiffré.

Les **1887 opérations à aléa frais encodées dans le corpus** sont comptées
séparément ; elles ne sont pas recréées par l'oracle déterministe. Elles
ne sont ni 1887 requêtes déterministes supplémentaires ni le nombre total
de leurs exécutions durant le fuzzing avec répétitions.

Le binaire de rejeu Linux est nouvellement compilé depuis la source
capturée, en release ordinaire, sans `research-vectors`. Il est confronté
à Python sous Windows, NumPy 2.3.5, avec l'oracle R1 gelé. Les reçus lient
le corpus, les contrôleurs, les sources et le transcript. Les identités
principales sont :

| Élément | SHA-256 |
|---|---|
| Oracle Python gelé | `41b754345d86f30115ccb6f1f1615ccbc4107496dc9fedd5ddf23dd9921f881d` |
| Binaire Rust du rejeu | `3fab896b2d2036a516d2a2d06525ac23a9a62089cf5541e5697c9ce894d24e3c` |
| Transcript comprimé | `446be88e61a39bef3b9f6ddaed777db9ae3692f329d53cdd53c3686d0ec422b3` |
| Reçu oracle | `44fe1bf03a4bfe6780d0fb813cb6e066d68e725e5aa7d6adfee2214be25d56a1` |

Ce rejeu fournit un accord indépendant sur ces entrées synthétiques,
sans audit externe ou preuve de sécurité globale. Les noms et schémas
M08 des instruments réutilisés décrivent leur format ; l'acquisition,
les objets de couverture et ce corpus sont propres à M10.

### Recueil scellé et contrôles de clôture

Les paquets de distribution sont désormais `QUALIFIED_INTERNAL`. Le premier
rejeu global a révélé un défaut d'adaptateur : le miroir des fichiers ne
créait pas les quatre dossiers d'incidents vides exigés par le lecteur de
campagne. Le [recueil de correction](../results/engine/m10-reader-adapter-001/)
conserve l'échec, les sources avant/après et le nouveau rejeu. La correction
crée seulement ces dossiers temporaires, en préservant tout fichier archivé.
Les données, archives et contrôleurs d'acquisition ne sont pas modifiés.

Le [recueil moteur](../results/engine/m10-001/) conserve neuf groupes et
10 908 membres. Le rejeu global corrigé passe sans nouvelle acquisition,
exécution de moteur ou compilation. Les groupes et leur provenance sont
inchangés par l'adaptation.

### Check complet local Windows acquis

Le [recueil du check M10](../results/engine/m10-verification-001/) conserve
le contrôle complet `scripts/dev.ps1 check`, terminé le 16 novembre 2026
à 14:42:39 UTC avec **exit code 0**. Les **514 tests Python** se terminent
par `OK`, sans aucun test ignoré. Les tests Rust, le formatage, Clippy strict
et les rejeux requis des preuves passent dans cette même exécution locale.
Ce résultat est distinct de la CI hébergée sur deux OS.

Les **313 entrées enregistrées de sources et contrôles** sont identiques
avant et après le check. Le scellage relie également les **37 entrées
compilables qualifiées** au source 003 et aux reçus de build : **31** figurent
dans ce contrôle avant/après ; les **six autres** sont contrôlées au moment
du scellage. Ces six fichiers appartiennent aux instruments
`m08-import-consumer` et `m08-memory-probe` : leur `Cargo.toml`, leur
`Cargo.lock` et leur `src/main.rs`. La liste exacte et les empreintes sont
conservées dans `verification.json`. Ils ne sont pas présentés comme ayant
bénéficié d'un contrôle avant/après absent du reçu.

Le journal complet porte le SHA-256
`cd2c5d759c79c4a78905695e98fd6bce768116de6fb96d2b34d1fd17b9ceabbe`.
Le recueil conserve le journal, les contrôles, les inventaires, les reçus
et leurs liens au manifeste 003. Son scellage ne relance ni tests,
compilation, moteur ou fuzzing et n'ajoute aucun temps de campagne.

La **CI neuve Windows/Ubuntu et la promotion canonique restent en attente**
de leurs résultats effectifs. M09 reste la référence livrée ; les acquis
locaux ne leur donnent pas par avance un statut de succès. C01, la sélection
cryptographique finale et les garanties globales de temps constant ou
d'effacement restent ouverts.
