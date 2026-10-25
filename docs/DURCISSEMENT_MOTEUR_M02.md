# M02 — Durcissement du moteur R1

25 octobre 2026. [Protocole](PROTOCOLE_DURCISSEMENT_M02.md) préenregistré
au commit 63fd895, code du cœur et des classes expérimentales au commit
6dae419 avant mesure. [Résultats](../results/engine/hardening-001/summary.json).
Les domaines, paramètres et octets de R1 restent identiques. La démarche
traite des défauts d'implémentation ; elle ne constitue pas une preuve
IND-CCA ou un audit indépendant de la construction.

## Corrections de mémoire et d'interface

Le premier moteur construisait le dk développé en agrandissant un Vec
qui contenait déjà s. Une réallocation pouvait laisser l'ancien buffer
hors de portée de l'effacement final. Le dk est désormais construit
directement dans une allocation fixe de 5088 octets, initialisée à zéro,
sans méthode d'agrandissement. Son propriétaire efface les octets avant
libération. L'export explicite produit un buffer effacé à taille finale,
rempli par copie, sans croissance ultérieure dans le moteur.

Les vecteurs s,r,e,u,t sont des tableaux de six polynômes. Chaque polynôme
possède un tableau de 256 coefficients effacé au drop. Les accumulateurs
de multiplication sont protégés de la même manière. Le bruit SHAKE et
la sortie SHA3-512 sont écrits dans des propriétaires de taille fixe ;
la sortie intermédiaire du digest est effacée après copie.

Le déchiffrement n'alloue plus un vecteur de coefficients secret et la
réencapsulation est écrite dans un tableau temporaire effacé de 2656
octets. La partie ek de dk est empruntée. Il n'existe plus d'allocation
dynamique **explicite dans le code du dépôt** sur le chemin Decaps ;
cette observation de source ne vaut pas comptage global de l'allocateur
ou preuve sur toutes les bibliothèques.

L'import examine l'ensemble des coefficients avant de décider la
canonicité. Les opérations internes sur les objets validés n'utilisent
plus ce contrôle comme branche dépendant des coefficients secrets.
Les longueurs et formats sont garantis par les types avant ces appels.
Les chiffrés bien dimensionnés non canoniques continuent à produire le
secret de remplacement, sans drapeau de rejet dans l'API applicative.

L'effacement s'appuie sur [zeroize 1.9.1](https://docs.rs/zeroize/1.9.1/zeroize/).
Il protège les emplacements possédés traités explicitement. Il ne garantit
pas la disparition de copies antérieures, des registres, des pages de
swap ou des copies introduites par le compilateur. Les buffers d'import
appartiennent à l'appelant. Le test du propriétaire fixe vérifie son
effacement sur mémoire encore vivante ; il ne lit jamais après libération.

## Arithmétique spécialisée et bornes

Le moteur emploie maintenant un module privé spécialisé en q=7681 ;
l'arithmétique générique reste un oracle distinct. Les corrections de
résidu utilisent des soustractions enveloppantes et une sélection par
bits. La réduction large utilise la réciproque entière
`mu=floor(2^64/q)`, et la compression la version à 32 bits.

Pour x dans [0,2^64), `floor(x*mu/2^64)` est le quotient correct ou
le quotient moins un. Le résidu provisoire est donc dans [0,2q), corrigé
par une soustraction bornée. Une multiplication négacyclique additionne
256 produits de coefficients canoniques ; sa valeur absolue est au plus
256(q−1)^2. Ajouter l'offset 256q², multiple de q, rend l'entrée de
réduction non négative et inférieure à 2^35. Les intermédiaires signés
restent très loin de la limite i64.

Les tests contrôlent tous les résidus inférieurs à 2q, tous les numérateurs
inférieurs à 2^18 utilisés par la compression, 100000 entrées larges
synthétiques, les frontières u64 et plusieurs convolutions face à l'oracle
générique. La seule branche de la double boucle de multiplication dépend
des indices publics i,j, pas des coefficients.

Deux sondes scalaires ont été examinées dans l'assembleur release des
deux cibles, Rust 1.91.1/LLVM 21.1.2 : 15/14 instructions sous Windows,
13/12 sous Linux pour réduction/quotient. Aucune division ni branche
conditionnelle n'apparaît **dans ces deux sondes** ; des mouvements
conditionnels de registres sont présents. Ce contrôle ne couvre pas
l'intégralité du binaire, les bibliothèques, les autres processeurs ou
les futurs compilateurs. Les extraits sont conservés dans assembly.json.

## Confrontation et entrées malveillantes

Sur Windows x86-64 et Linux x86-64/Ubuntu 22.04 sous WSL2 :

| Contrôle par plateforme | Résultat |
|---|---|
| 1000 vecteurs complets M01 | Tous les champs identiques aux corpus figés |
| 10000 remplacements M01 | Tous identiques aux données vérifiées par Python |
| 20000 entrées d'import de trois types | 17010 longueurs incorrectes rejetées, 2990 entrées de longueur exacte ; aucun panic observé |
| 10000 mutations de chiffrés | Même sortie Rust sur les deux plateformes, toutes confrontées à l'oracle Python |

Les 993 imports acceptés dans la campagne de formats sont des objets
chiffrés de bonne longueur ; leur import ne certifie pas une encapsulation
honnête. La campagne compare les résultats des deux plateformes et
vérifie l'égalité des octets pour tout import accepté.

Le corpus malveillant comporte cinq classes de 2000 cas : premier
coefficient non canonique, chiffré nul canonique, altération d'un bit
de v, données canoniques arbitraires, coefficient q placé dans le vecteur.
Il contient **5351 chiffrés distincts** ; les répétitions sont conservées,
notamment dans la classe nulle et les altérations possibles de v.
Les 10000 décapsulations sont rejetées dans l'oracle indépendant, avec
secret de remplacement identique. Les flags d'acceptation de l'oracle
ne sont produits que par le build de recherche et une clé synthétique
publique. Aucun indicateur de rejet applicatif n'a été ajouté.

Les données, sorties et classes sont dans mutations.jsonl.gz ; elles
se rapportent au cas synthétique 0, pas à des clés réelles. Ce test de
mutations borné ne remplace pas un fuzzing de 24 h à couverture guidée.

## Linux et contrôle mémoire

La chaîne Linux est installée localement sous .tools, sans remplacement
des outils globaux. Après bootstrap, rust-toolchain.toml sélectionne
**Rust 1.91.1**, comme sur Windows ; les journaux enregistrent la version
effective. Les tests standards et avec recherche passent sous Linux.

Un build distinct utilise AddressSanitizer et la détection de fuites
mémoire, avec `RUSTC_BOOTSTRAP=1` uniquement pour activer le sanitizer
de cette chaîne de test. La bibliothèque standard précompilée n'est
pas réinstrumentée ; l'assembleur des dépendances n'est pas couvert par
une instrumentation Rust. Les options sont isolées dans target/linux-asan
et ne sont pas celles du build applicatif. Les tests instrumentés passent
sans erreur signalée. Le binaire release instrumenté traite ensuite
20000 entrées de format et les 10000 mutations complètes : mêmes sorties
que les corpus vérifiés, codes de sortie nuls et stderr vide. Le rapport
et les journaux sont conservés sous `evidence/` dans l'instantané M02.

## Diagnostic temporel préenregistré

La campagne conserve 100 échauffements puis 6000 observations, 2000 dans
chacune des classes honnête, rejet canonique nul et rejet non canonique.
L'ordre mélangé et la graine publique sont fixés dans le code avant
mesure. Les autres calculs lourds de la campagne étaient terminés.

| Classes | t de Welch observé | Seuil préétabli | Signal |
|---|---:|---:|---|
| Honnête / nul canonique | 2,716 | 4,5 en valeur absolue | Non |
| Honnête / non canonique | 3,027 | 4,5 en valeur absolue | Non |
| Nul canonique / non canonique | 0,371 | 4,5 en valeur absolue | Non |

Les moyennes observées sont environ 2,677 / 2,648 / 2,645 ms ; les médianes
sont voisines de 2,574 ms. Ces durées incluent le code et l'environnement
de mesure de cet hôte ; elles ne sont pas une comparaison de performance
normalisée. Les durées brutes et leur ordre sont conservés.

**Aucun dépassement du seuil dans ces trois tests**, sans preuve de temps
constant. Une clé, trois entrées fixes, un hôte Windows, des observations
finies et un environnement OS/CPU non isolé limitent cette expérience.
Les tests statistiques comprennent un témoin analytique et le parseur
d'assembleur un contrôle négatif avec branche introduite.

## Reproduction et reste à faire

```powershell
.\scripts\engine.ps1 check
.\scripts\engine.ps1 asm
.tools/research-venv/Scripts/python.exe research/validate_hardening_m02.py
wsl -d Ubuntu-22.04 -- bash scripts/hardening-linux.sh test-default
wsl -d Ubuntu-22.04 -- bash scripts/hardening-linux.sh test
wsl -d Ubuntu-22.04 -- bash scripts/hardening-linux.sh asan
```

Les campagnes intégrales sont distinctes du contrôle courant : `check`
vérifie les empreintes de M02, recalcule les statistiques des 6000 mesures
et rejoue 16 mutations via l'oracle archivé. Les sources, versions, options
et empreintes sont conservées ; les données M01 et les vingt études J2
restent inchangées.

La vérification finale `scripts/dev.ps1 check` réussit : rustfmt, Clippy,
28 tests Rust dans chaque configuration (29 distincts), 89 tests Python,
vingt instantanés J2 et auto-test frais R1. Le journal complet est archivé
dans `evidence/windows-full-check.log`, le bilan dans `evidence/checks.json`.

Le binaire release applicatif final est compilé sans research-vectors,
avec auto-test frais réussi et cinq commandes de recherche indisponibles.
Son empreinte et les journaux sont conservés dans `evidence/application.json`.
Les empreintes des builds de recherche restent distinctes et inchangées.

Restent ouverts le fuzzing long à couverture guidée, une analyse temporelle
plus large et l'inspection complète du binaire, les protections de pages,
l'audit des dépendances et de la construction, le million de parcours avant
gel, les benchmarks P01 et la revue externe. WSL vérifie la cible Linux
sur cet hôte, sans remplacer une campagne sur plusieurs machines natives.
J2 et la validation globale de J3/J4 ne sont pas clos par cette étape.
