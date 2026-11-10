# M05 — Comparaison expérimentale de R1 avec d'autres constructions

26 octobre 2026. Cette étape exécute des estimations supplémentaires pour
R1, ML-KEM-1024, Aigis-Enc mode 4, une version historique de Kyber et
KINDI-512-3-2-1. Un point de paramètres issu d'un article est conservé
séparément. Elle compare des **problèmes mathématiques et des proxys
déclarés**, et ne classe pas la sécurité globale des KEM.

## Versions, distributions et problèmes observables

| Point | Degré / rang | Dimension aplatie | q | Secret idéal | Erreur de clé idéale | Clé publique observée |
|---|---:|---:|---:|---|---|---|
| R1 | 256 / 6 | 1536 | 7681 | CBD(3) | CBD(3) | Relation exacte, encodage canonique 13 bits |
| ML-KEM-1024 | 256 / 4 | 1024 | 3329 | CBD(2) | CBD(2) | Relation exacte après inversion de la représentation NTT |
| Aigis-Enc mode 4 | 256 / 4 | 1024 | 7681 | CBD(3) | **CBD(8)** | Compression au plus proche sur 11 bits |
| Kyber historique k=4 | 256 / 4 | 1024 | 7681 | CBD(3) | CBD(3) | Compression au plus proche sur 11 bits |
| KINDI-512-3-2-1 | **512 / 3** | 1536 | **8192** | **Uniforme sur {−2,−1,0,1}** | Même loi uniforme | Suppression du bit faible, soit 12 bits publiés |
| Point « Kyber1536 » de l'article | 256 / 6 | 1536 | 3329 | CBD(2) | CBD(2) | Construction simplifiée de l'article, arrondis omis ; aucun code KEM associé exécuté ici |

CBD(η) a une variance η/2. Les deux lois asymétriques d'Aigis ne sont pas
remplacées par une même η. La loi de KINDI provient du décodage de deux bits
uniformes, puis de la soustraction de 2 : sa moyenne vaut **−1/2** et sa
variance **5/4**. Ce n'est pas CBD(2). Le degré 512 de KINDI n'est pas
remplacé par le degré 256 de Kyber ; leur même dimension aplatie n'efface
pas leurs structures algébriques différentes.

Les paramètres et algorithmes sont rattachés aux sources suivantes :

- Aigis : [PQMagic au commit b9ea5ce134966b8f90d637bab97178a92ae130f3](https://github.com/pqcrypto-cn/PQMagic/tree/b9ea5ce134966b8f90d637bab97178a92ae130f3/kem/aigis-enc/std), notamment `params.h`, `owcpa.c`, `polyvec.c`, `cbd.c` et `kem.c`. Le commit remplace la référence mouvante `main`.
- Kyber historique : [code au commit ca375e3e3391360a863efd4122b14e396c994dde](https://github.com/pq-crystals/kyber/tree/ca375e3e3391360a863efd4122b14e396c994dde/ref). Le jeu k=4 emploie η=3 et les précisions pk/u/v=11/11/3. Le nom de ligne n'identifie pas toutes les versions de Kyber parues depuis 2017.
- KINDI : [archive primaire NIST de première ronde](https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/round-1/submissions/KINDI.zip), 12 376 347 octets, SHA-256 `ed51557337dee49deeda4d97c057ef65e98074a49af683eb621660f271b6963c`. Le répertoire examiné est `KINDI/Reference_Implementation/kem/KINDI-512-3-2-1/`, y compris `params.h`, `core.c`, `poly.c`, `poly_encode.c`, `gen_randomness.c` et `kem.c`.
- R1 : [spécification versionnée](SPECIFICATION_DEV_Q7681_R1.md). Le témoin normalisé est [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).
- Le point de rang 6 à q=3329 figure dans la table 4 de [Boudgoust et Scholl, ePrint 2023/016](https://eprint.iacr.org/2023/016). Ses quatre paramètres coïncident avec le point de bruit historique P0 du projet. Le PDF a été consulté dans l'index web ; le téléchargement direct a renvoyé HTTP 403 et aucune empreinte locale du PDF n'est inventée. Les nombres du point et le profil local témoin sont conservés.

Les empreintes individuelles des fichiers primaires sont enregistrées dans
`primary-sources.json`. Le code C de ces projets est **lu**, puis les
paramètres sont transcrits dans un modèle ; il n'est pas compilé ou exécuté
par cette étude. Les sources étrangères complètes ne sont pas redistribuées
dans l'instantané : seuls leurs URL, versions et empreintes y figurent.

[kyber-py](https://github.com/GiacomoPope/kyber-py) relève d'une autre catégorie : une réalisation paramétrable de
profils Kyber/ML-KEM, et non une nouvelle construction cryptographique par
le seul changement de son dictionnaire de paramètres. Le tableau ne lui
attribue donc pas une ligne de sécurité supplémentaire identique à celle
du profil qu'il implémente.

### Pourquoi les clés comprimées ne sont pas du MLWE exact

Dans le jeu idéal, avant sérialisation, on écrit `b=A·s+e mod q`. R1 et
ML-KEM-1024 rendent cette relation accessible par une représentation exacte
ou exactement inversible. L'anneau et les développements depuis les graines
restent cependant modélisés : une expansion de 256 ou 512 bits n'est pas une
collection informationnellement indépendante d'autant de coefficients.

Pour Aigis et l'ancien Kyber, l'objet effectivement publié est
`y=C_11(A·s+e mod q)`. Sa reconstruction vérifie
`D_11(y)=A·s+e+δ(A·s+e) mod q`. Le terme δ dépend de l'entrée. Une formulation
exacte de l'observation conserve les cellules du quantificateur :

```text
Pr[y_j | A,s] = somme_e Pr[e_j=e] · 1{ C_pk((A·s)_j+e mod q) = y_j }.
```

Cette expression est distincte d'un échantillon LWE à erreur indépendante
augmentée. Dans les idéalisations de lois iid, elle décrit les coefficients
conditionnellement à A et s ; elle ne démontre pas une indépendance des
erreurs reconstruites une fois ces variables marginalisées.

Dans KINDI, `y=floor((A·r+e mod 8192)/2)`. Les équations observables portent
sur ces intervalles de deux résidus, pas sur la valeur exacte avant
troncature. q est une puissance de deux : les phénomènes algébriques propres
à ce module composite ne sont pas couverts par l'estimateur LWE générique.

L'estimateur accepte `ND.Uniform(-2,1)` et conserve sa moyenne −1/2. Ses
formules géométriques emploient principalement l'écart type ; elles ne
certifient pas ici une transformation de centrage de KINDI. En particulier,
diviser par 2 dans `Z/8192Z` n'est pas une opération inversible. Une lecture
par classe affine ou approximation réelle doit rester une hypothèse du
proxy, pas une égalité avec un nouveau secret entier centré.

## Arrondis : calcul exact local, substitution d'attaque conditionnelle

Le programme énumère tous les résidus des trois quantificateurs de clé,
soit **23 554 valeurs** au total. Pour q=7681 et 11 bits, 511 cellules
contiennent trois résidus et 1537 en contiennent quatre. L'erreur de
reconstruction, sous une entrée supposée uniforme, est dans [−2,2], avec
les poids entiers suivants sur le dénominateur 7681 :

| δ | −2 | −1 | 0 | 1 | 2 |
|---|---:|---:|---:|---:|---:|
| Poids | 768 | 2048 | 2048 | 2048 | 769 |

Sa moyenne est 2/7681 et sa variance 78684160/58997761. La convolution
**indépendante supposée** avec l'erreur donne une variance d'environ 5,33368
pour Aigis et 2,83368 pour Kyber historique. Les fractions exactes et les
PMF complètes sont conservées ; aucune approximation gaussienne ne sert à
calculer ces fractions.

Cette marginale ne valide pas l'indépendance dans le schéma. Le programme
calcule aussi la loi exacte de `e+δ(a+e)` pour quatre signaux fixés a. Ces
lois changent avec a. Pour KINDI, l'exemple est particulièrement direct :

| Signal fixé modulo 2 | Erreur reconstruite | Moyenne | Variance |
|---|---|---:|---:|
| 0 | Uniforme sur {−2,0} | −1 | 1 |
| 1 | Poids 1/4,1/2,1/4 sur {−3,−1,1} | −1 | 2 |
| Proxy indépendant marginal | Convolution de U{−2,−1,0,1} et U{−1,0} | −1 | 3/2 |

Une même variance marginale ne fournit donc pas la loi conditionnelle
requise par une attaque. Ces vérifications finies n'estiment ni un taux
d'échec du KEM ni une probabilité de succès de récupération de clé.

## Protocole d'estimation

Tous les travaux emploient
[`malb/lattice-estimator@f31b86fe490ab11abb4a69efa13007583791e10a`](https://github.com/malb/lattice-estimator/tree/f31b86fe490ab11abb4a69efa13007583791e10a),
SageMath 10.7 et la chaîne Python du projet. Chaque travail fixe une cible,
aucun oracle de fuite, une mémoire exponentielle sans plafond et sa propre
convention de succès. Les trois familles sont uSVP, BDD et dual hybride
MATZOV. La GSA est fixée pour les deux familles primales.

Le nom `LWE.dual_hybrid` désigne l'implémentation MATZOV dans cette version,
avec son paramètre interne μ=0,5. Il ne donne pas un succès de récupération
certifié à 99 %. Les conditions de succès géométriques des primaux sont
distinctes. Aucun minimum global ne mélange ces conventions.

Deux budgets restent séparés :

- `key` : nk coefficients, matrice abstraite de k lignes de blocs sur k
  colonnes ;
- `ideal_k_plus_1` : n(k+1) coefficients, matrice abstraite (k+1)×k.

Pour R1, cela donne les deux jeux **D_(6,6)** et **D_(7,6)** : 1536 et 1792
coefficients. Pour KINDI, les tailles sont 1536 et **2048**, grâce à son
degré 512. Le second budget représente un jeu idéal distinct ; il ne
déclare pas que les lignes d'un chiffré comprimé réel fournissent des
échantillons LWE propres et indépendants. Les lignes de blocs ne sont
pas des nombres de cibles ou de rotations.

Deux panneaux d'entrée sont exécutés :

1. `before_serialization_LWE_proxy` : distributions prescrites avant
   compression. Pour les clés comprimées, cela donne au modèle une
   information absente de la clé publiée. Un coût d'attaque de ce problème
   ne se transforme pas en borne inférieure ou en coût d'attaque du KEM réel.
2. `independent_rounding_Gaussian_moment_proxy` : pour les trois clés
   comprimées seulement, ajout indépendant de la marginale d'arrondi, puis
   substitution de l'erreur par un descripteur gaussien de mêmes moments.
   Les deux approximations sont explicites. Ce panneau n'est pas une
   correction validée du premier.

Le modèle classique est le coût de réduction fini MATZOV. Le dépassement
de β=1024, limite déclarée de son ajustement, est indiqué par travail. Le
second modèle utilise la sensibilité BCSS23 `2^(0,2563 β)` pour la réduction,
en gardant le reste de l'estimateur : ce n'est pas une attaque quantique
complète optimisée, ni un nombre de portes physiques. Les champs mémoire
gardent les unités de l'estimateur ; `N` est une quantité de vecteurs et
ne devient pas un nombre d'octets. Les compromis sous mémoire bornée ne
sont pas calculés ici.

Le pilote limité contient 15 travaux classiques sur cinq profils au budget
de clé. Le panneau complet comporte **108 travaux** : six points avant
sérialisation et trois sensibilités arrondies, chacun avec deux budgets,
deux modèles et trois familles. Les erreurs, sorties non finies et délais
dépassés sont enregistrés ; aucune autre famille ne remplace silencieusement
une sortie manquante.

## Exécutions et résultats

Le pilote `artifacts/generated/m05-comparison-pilot-001` a terminé ses
15 travaux, tous avec un coût fini, en **204,37 secondes** à deux travailleurs.
Le travail le plus long a pris 75,02 secondes. Il ne sert pas de point de
départ pour choisir seulement les résultats favorables.

Le panneau complet `artifacts/generated/m05-comparison-full-001` a terminé
ses **108 travaux**, tous avec un coût fini, en **690,37 secondes** à quatre
travailleurs. Le travail le plus long a pris **109,15 secondes**, sous le
délai fixé de 180 secondes. Sage 10.7 et Python 3.12.15 ont été employés
sous WSL2 Ubuntu 22.04. Aucune récupération de clé réelle n'est exécutée :
ces durées sont celles du calcul des estimations.

Les sorties sont conservées dans
[`results/security/m05-comparison-001`](../results/security/m05-comparison-001).
L'instantané contient 229 fichiers, dont les 108 entrées, les 108 sorties,
les sources du travailleur réellement exécuté et les reçus des sources.
Les **36** croisements avec les mêmes points de `run-002`, à conventions
identiques, retrouvent exactement les valeurs `log2(rop)` conservées
(écart numérique calculé 0). Ce contrôle détecte une régression de
transcription ou de chaîne ; il ne valide pas le modèle d'attaque.

### Relations idéales avant sérialisation

Les valeurs ci-dessous sont `log2(rop)` de l'estimateur au budget `key`,
arrondies à deux décimales pour la lecture. Chaque colonne garde sa famille
et son contrat de succès. Les trois colonnes ne sont pas réduites à un
« niveau de sécurité ».

| Point idéal avant sérialisation | uSVP classique | BDD classique | Dual hybride classique | uSVP sensibilité quantique | BDD sensibilité quantique | Dual hybride sensibilité quantique |
|---|---:|---:|---:|---:|---:|---:|
| R1 | 402,82 | 398,26 | 383,77 | 340,11 | 341,12 | 325,96 |
| ML-KEM-1024 | 275,10 | 270,72 | 262,34 | 224,01 | 224,88 | 214,79 |
| Aigis-Enc mode 4, relation non comprimée | 277,69 | 273,35 | 265,23 | 226,31 | 227,19 | 217,90 |
| Kyber historique k=4, relation non comprimée | 263,21 | 259,17 | 253,36 | 212,99 | 213,86 | 206,09 |
| KINDI-512-3-2-1, relation non tronquée | 392,17 | 387,73 | 373,50 | 330,37 | 331,37 | 316,28 |
| Point d'article de rang 6 à q=3329 | 419,82 | 414,92 | 397,03 | 355,74 | 356,67 | 338,84 |

Les **54 paires** qui ne diffèrent que par `key` contre
`ideal_k_plus_1` produisent la même valeur `log2(rop)` dans cette exécution.
Le plafond supplémentaire de lignes n'améliore donc pas l'optimum trouvé
par ces fonctions sur ces entrées. Les entrées et résultats des deux jeux
restent séparés : cette égalité numérique ne prouve ni leur équivalence
mathématique ni la disponibilité d'une ligne propre supplémentaire dans
le chiffré réel. Un exemple explicite est le dual hybride MATZOV de R1 :
le champ `problem` conserve bien `m=1536` ou `m=1792` selon le jeu, tandis
que le champ de sortie `m` choisit **1536** dans les deux optimisations
(voir `comparison.json`, lignes R1/dual_hybrid/MATZOV-classical).

### Sensibilité gaussienne à l'arrondi indépendant supposé

Ce second tableau change à la fois le modèle de dépendance et la forme
de la loi d'erreur. Il sert à mesurer la sensibilité des formules à ce
choix déclaré ; il ne donne pas le coût corrigé d'une attaque sur les
clés publiées.

| Proxy de moments après arrondi supposé indépendant, budget key | uSVP classique | BDD classique | Dual hybride classique | uSVP sensibilité quantique | BDD sensibilité quantique | Dual hybride sensibilité quantique |
|---|---:|---:|---:|---:|---:|---:|
| Aigis-Enc mode 4 | 282,15 | 277,76 | 269,58 | 230,41 | 231,34 | 221,99 |
| Kyber historique k=4 | 272,41 | 268,25 | 260,75 | 221,44 | 222,32 | 213,17 |
| KINDI-512-3-2-1 | 395,82 | 391,37 | 376,82 | 333,70 | 334,70 | 319,52 |

Dans ces six conventions, l'augmentation du coût par rapport au panneau
précédent est un effet de cette substitution, pas une marge de sécurité
certifiée. Les lois conditionnelles différentes calculées plus haut
interdisent précisément de transformer ce résultat en correction
universelle par ajout de variance.

### Ressources et extrapolations

Les **24 sorties classiques** correspondant à R1, au point de rang 6 à
q=3329 et aux deux panneaux KINDI emploient une dimension de réduction
supérieure à 1024. Elles dépassent la plage déclarée de l'ajustement fini
classique. Les sorties quantiques restent une formule asymptotique, sans
validation pratique supplémentaire lorsque cette dimension augmente.

Le tableau suivant expose les ressources du dual hybride avant
sérialisation, au budget de clé. `N` est le nombre de vecteurs demandé
par le modèle, sans conversion en octets ni promesse de mémoire réalisable.

| Point | β classique / β auxiliaire | log2(N) classique | β sensibilité quantique / β auxiliaire | log2(N) sensibilité quantique |
|---|---:|---:|---:|---:|
| R1 | 1254 / 1215 | 250,82 | 1271 / 1271 | 262,26 |
| ML-KEM-1024 | 823 / 804 | 165,94 | 838 / 838 | 173,64 |
| KINDI-512-3-2-1 non tronqué | 1218 / 1180 | 244,02 | 1234 / 1234 | 255,32 |
| Point d'article de rang 6 à q=3329 | 1302 / 1260 | 260,84 | 1322 / 1322 | 273,91 |

Ces fonctions ne retournent pas de champ `mem` pour les travaux exécutés.
Il n'existe donc pas ici de mesure ou de majorant du pic mémoire total.
`N`, les dimensions et les autres champs effectivement retournés sont
conservés intégralement dans `comparison.json`. Le coût d'une recherche
générique sur les graines ou messages, les attaques algébriques propres
aux anneaux et les limites de la transformation CCA restent des analyses
distinctes. Un coût de réseau supérieur à 2^256 ne les remplace pas.

### Décision pour le moteur

1. **Conserver R1 comme moteur expérimental à corriger et analyser.** À
   conventions identiques, ses proxys de clé sont plus coûteux que les
   trois témoins de rang 4 et que le proxy KINDI étudié. Cela fournit un
   résultat comparatif conditionnel, sans supériorité globale ni transfert
   des garanties de ML-KEM-1024.
2. **Retirer toute idée de domination du rang 6 à q=3329.** Ce point
   présente des coûts plus élevés que R1 dans chacune des six colonnes
   du premier tableau. Le choix q=7681 améliore le compromis de correction
   étudié par J2 ; il ne compense pas automatiquement l'effet de q sur les
   attaques. Le point de départ P0 à q=3329 demeure incompatible avec
   l'objectif de décapsulation dans le modèle J2 conservé : ce résultat
   d'attaque n'autorise pas à le substituer au moteur.
3. **Conserver la clé publique exacte de R1 comme propriété de construction
   vérifiable.** Elle évite le défaut de modélisation causé ici par une
   quantification de clé oubliée. Ce constat ne démontre aucune domination
   de sécurité sur une construction comprimée correctement analysée.
4. **Garder les obligations de sécurité concrète ouvertes.** La correction
   et les coûts de réseaux ne donnent pas encore les avantages CPA des
   deux jeux ni la réduction CCA concrète exigée par
   [l'analyse M05 de R1](SECURITE_CONCRETE_R1_M05.md). L'exécution de ce
   panneau termine la comparaison annoncée ; elle ne doit pas entraîner
   une nouvelle campagne de moments J2 sans décision de construction.

## Portée face aux attaques récentes et à la sécurité CCA

Les [limites d'applicabilité des attaques récentes](APPLICABILITE_ATTAQUES_M05.md)
restent en vigueur : scores, covariances, compression et listes ne reçoivent
aucun facteur correctif forfaitaire à partir d'un article portant sur une
autre référence. Le plateau de coûts d'une clé publique n'évalue pas les
oracles d'échec, fautes, fuites d'implémentation ou la transformation KEM.

[CryptanalysisBench, arXiv:2607.18538v2 du 29 juillet 2026](https://arxiv.org/html/2607.18538v2)
rapporte une attaque par réaction de déchiffrement sur KINDI et une erreur
dans sa preuve CCA. Le [script du benchmark au commit f55e8abb009d2a85e30db91d011eee8b24f13edb](https://github.com/ethz-spylab/cryptanalysis-benchmark/blob/f55e8abb009d2a85e30db91d011eee8b24f13edb/algorithms/T2_kindi/environment/algorithm_src/build_cli.sh)
choisit **KINDI-256-3-4-2**, pas le jeu 512-3-2-1 comparé ici. Le code NIST
du jeu 512 examiné vérifie le message récupéré, sans réencapsulation ; nous
ne reproduisons pas l'attaque sur ce jeu et ne transférons pas son verdict
automatiquement. Cette publication suffit à rappeler pourquoi nos coûts
de proxy de clé ne constituent pas une garantie CCA de la famille. R1
réencapsule et compare les octets ; l'attaque rapportée n'est pas transférée
à R1 par ressemblance de paramètres.

Aigis-Enc+ du concours NGCC 2026 est également une autre construction et
un autre code que le mode 4 de PQMagic figé ici. Les signalements qui le
concernent ne sont pas réétiquetés comme des attaques reproduites contre
ce comparateur. Aucun résultat de cette étude ne justifie de déployer
un de ces candidats expérimentaux.

## Reproduction et conservation

Le programme est [`research/compare_experimental_kems_m05.py`](../research/compare_experimental_kems_m05.py).
Les tests unitaires ordinaires ne requièrent ni Sage ni téléchargement :

```powershell
.\.tools\research-venv\Scripts\python.exe -m unittest discover -s research -p test_compare_experimental_kems_m05.py -v
.\.tools\research-venv\Scripts\python.exe research/compare_experimental_kems_m05.py --prepare --fetch-sources --output artifacts/generated/m05-comparison-nouveau
```

Après préparation du runtime local par `scripts/bootstrap-modern.ps1`,
le calcul emploie le Python Sage, avec les mêmes variables DOT_SAGE,
XDG_CACHE_HOME, TMPDIR et CONDA_PKGS_DIRS que `scripts/modern.sh` :

```sh
.tools/micromamba-bootstrap/bin/micromamba --no-rc -r .tools/sage-ram/mamba run -p .tools/sage-ram/env python research/compare_experimental_kems_m05.py --run --output artifacts/generated/m05-comparison-nouveau --workers 4 --timeout 180
```

Le contrôleur lance les travailleurs depuis les **sources archivées** au
moment de préparer le panneau. Leur empreinte figure dans chaque sortie.
Les sources et manifestes de l'estimateur sont également vérifiés ; aucun
pickle, objet natif fourni ou code C des candidats n'est exécuté.

```powershell
.\.tools\research-venv\Scripts\python.exe research/compare_experimental_kems_m05.py --verify --output artifacts/generated/m05-comparison-nouveau
.\.tools\research-venv\Scripts\python.exe research/compare_experimental_kems_m05.py --freeze --output artifacts/generated/m05-comparison-nouveau
```

La congélation vise le nouvel identifiant
`results/security/m05-comparison-001` et refuse un dossier existant. Les
instantanés historiques ne sont pas remplacés. Le vérificateur ordinaire
contrôle les empreintes, l'intégralité des travaux, les conventions et les
diagnostics rationnels ; il ne relance pas Sage.
