# H08 — Lois CBD(2)/CBD(3) et réseaux de dimensions 3/5

Étape du 25 octobre 2026, suivant le [protocole préenregistré](PROTOCOLE_H08.md)
au commit `128c463`. Elle prolonge [H07](LLL_ET_FAMILLE_ELARGIE.md), avec de
nouveaux modules et sans modifier les quatorze instantanés antérieurs.

## Architectures et objets comparés

Le module reste q=17. Deux formes sont fixées, avec huit matrices chacune :

| Forme | Échantillons m | Secrets liés au réseau l | Secrets liés au code | Dimension du réseau | Variables secrètes et erreurs |
|---|---:|---:|---:|---:|---:|
| Contrôle | 2 | 1 | 4 | 3 | 7 |
| Extension | 3 | 2 | 4 | 5 | 9 |

Les matrices du contrôle sont celles de H07, identifiants 0..7. La seconde
forme a une étiquette publique SHAKE distincte, fixée avant observation.
Pour chaque matrice, les trois distributions CBD(η), η=1,2,3, sont testées
sans changer la géométrie publique. Secret et erreurs ont le même η.

Les sources de vecteurs sont la référence exhaustive du quotient et LLL
exact suivi d'une boîte de coefficients [-2,2]. Les listes ont N=4,8,12.
Les familles répétée et pondérée, et les critères euclidien et CBD, sont
ceux des études précédentes. Cela définit **1152 panneaux**. Le critère
CBD conserve son poids entier de H05 : multiplier son coût réel par le
même η positif sur toutes les coordonnées ne change pas son minimiseur.

## Réduction et relation duale

Le nouveau module `lll_dimensions.py` généralise la réduction rationnelle
de H07, sans modifier ce dernier. La base est `[I_m | A_l]` au-dessus de
`[0 | q I_l]`, de déterminant q^l. Le certificat conserve R=UB, det(U)=±1,
trace, réduction en taille et inégalités de Lovasz à δ=3/4. La dimension 3
est calibrée sur l'ancien module, et la dimension 5 dispose du même contrôle.

Les combinaisons bornées sont projetées et dédupliquées à signe près comme
dans H07. La référence énumère tout Z_q^m non nul à signe près. Le vecteur
x a désormais l coordonnées ; chaque vecteur vérifie `A_l^T y≡x mod q`.
Le décodage de `A_f^T y` donne c et r. À la vraie hypothèse `u=G^T s_f` :

`y^T b−c u ≡ y^T e+x^T s_l+r^T s_f mod q`.

Le score complet conserve ces trois contributions, sur toutes les hypothèses
u. Les bases réduites restent petites ; leur certificat ne justifie ni un
coût BKZ ni une hypothèse de génération de liste en grande dimension.

## Loi entière sur un groupe fini

Énumérer littéralement les bits du plus grand cas demanderait 2^54 issues.
On calcule à la place leur loi jointe exacte sur `(b,u)` dans Z_q^(m+1).
Le groupe a 4913 états au contrôle et 83521 à l'extension. Chaque variable
ajoute un multiple de sa colonne publique et du coefficient de G associé.
La récurrence additionne les poids entiers des transitions CBD ; aucune
indépendance artificielle entre coordonnées de l'observation n'est introduite.

Les poids CBD sont `binom(2η,η+v)` pour v de −η à η. Pour ν=m+l+4 variables,
le dénominateur total est `D=2^(2ην)`. Le plus grand est D=2^54. À chaque
étape, la masse entière est vérifiée. Les entrées et tous les sous-totaux
non négatifs sont majorés par D, inférieur à 2^63. Les budgets dépassant
le domaine prévu sont refusés avant l'allocation. Les calculs de loi et
de comptage d'événements utilisent donc des entiers 64 bits exacts.

La seconde méthode est différente : elle traite les secrets puis les
erreurs, avec η couches Bernoulli positives puis η négatives par variable.
Elle utilise des permutations d'indices, au lieu des poids binomiaux et
décalages multidimensionnels du calcul principal. Elle couvre toutes les
issues de bits par récurrence, sans prétendre les parcourir littéralement.
Des petits modèles CBD(1/2/3), entièrement énumérés par états et poids de
bits, contrôlent l'égalité des lois.

## Scores, décisions et moments

Les tables publiques de score ne dépendent pas d'η lorsque la banque de
vecteurs et le code sont fixés. Leur partage exige l'égalité de toutes
les données exactes de la banque. La loi LWE et les probabilités sont,
elles, recalculées pour chaque η.

Tous les candidats sont évalués. Les histogrammes de phases sont en
entiers ; les tables de cosinus encadrées de run-013 donnent des scores
entiers à l'échelle 2^48. Les rangs et les franchissements des seuils 0
et 1/2 sont certifiés comme dans H06. Un intervalle non résolu provoque
un arrêt, sans départage flottant. Une DFT directe est aussi comparée
numériquement à toutes les valeurs de score.

La moyenne et les covariances utilisent désormais
`Φη(a)=∏ cos(π a_i/q)^(2η)` pour les coefficients a=(y,x,r). Elles sont
confrontées aux moments de la loi entière sur tous les décalages faux
et vrai. Ces moments et le contrôle DFT restent numériques ; les
probabilités de rang, seuil et départage uniforme sont des fractions exactes.

La vraie hypothèse devinée reste u, pas nécessairement le secret complet.
Le témoin uniforme b est distinct de la loi des faux candidats LWE.
Ses deux premiers moments ne suffisent pas à justifier une queue normale.

## Résultats de la famille

L'étude [run-015](../results/j2/run-015/summary.json) conserve 16 matrices,
1152 panneaux et **155 banques de scores distinctes**, chacune évaluée sous
les trois distributions. Les **96 lois jointes** sont calculées exactement.
Les **192 calibrations CBD(1) en dimension 3** retrouvent les probabilités
de rang et de seuil de H07 sans écart rationnel.

La source LLL suivie de la boîte bornée retrouve les listes de référence :

| Dimension | N=4 | N=8 | N=12 |
|---|---:|---:|---:|
| 3, huit matrices de contrôle | 7/8 | 6/8 | 4/8 |
| 5, huit nouvelles matrices | 8/8 | 8/8 | 8/8 |

Ces accords portent sur les préfixes demandés, pas sur l'exhaustivité de
la boîte. En dimension 5, elle conserve entre 1179 et 1307 représentants,
sur les 2456 du quotient complet à signe près. La comparaison entre les
deux dimensions porte sur des architectures et matrices différentes ;
elle ne mesure pas à elle seule un effet causal de la dimension.

Pour le code pondéré, dimension 5, N=12, la source LLL et la référence
donnent ici les mêmes banques. Les moyennes de succès strict sur huit
matrices sont :

| Distribution | Euclidien | Critère CBD | CBD meilleur / moins bon / égal |
|---|---:|---:|---:|
| CBD(1) | 34,7583 % | 34,6821 % | 1 / 2 / 5 |
| CBD(2) | 13,2684 % | 13,2067 % | 0 / 3 / 5 |
| CBD(3) | 8,2826 % | 8,2560 % | 0 / 3 / 5 |

Dans les trois pertes de chacune des strates CBD(2) et CBD(3), la moyenne
du vrai score augmente avec le critère CBD. L'absence de domination du
critère fondé sur ce seul biais se maintient donc avec les distributions
étudiées ici, et pas seulement dans CBD(1). Pour le code répété, dimension
5/N=12, CBD(2) et CBD(3) donnent chacun quatre gains et quatre pertes : il
n'existe pas non plus d'ordre uniforme en faveur de l'euclidien.

La variation du taux de récupération de u avec η décrit cette attaque
réduite et ces lois secrètes. Ce n'est pas une mesure de sécurité globale
ni une comparaison d'attaques au module 7681.

Le témoin public uniforme est indépendant d'η. En dimension 5, sa queue
moyenne au seuil 1/2 est :

| N | Queue réelle moyenne | Normale de mêmes moments |
|---|---:|---:|
| 4 | 10,6045 % | 7,8650 % |
| 8 | 4,7069 % | 2,2750 % |
| 12 | 3,1447 % | 0,7153 % |

À N=12, la variance vaut 1/24 mais le rapport des queues vaut environ
4,40 dans cette famille. Ce témoin ne fournit aucun facteur correctif
universel pour les listes et paramètres réels.

## Reproduction et dépendances

Le calcul et sa seconde méthode utilisent NumPy **2.3.5**, déjà installé
dans `.tools/research-venv`, et verrouillé par
`research/requirements-cbd-dimensions.txt`. Aucune installation globale ou
modification des sources figées n'est nécessaire. Le contrôle `check`
utilise désormais le Python de cet environnement pour les tests de
recherche et pour les deux nouveaux vérificateurs ; les autres contrôles
historiques restent présents.

Les empreintes de tableaux incluent forme, type entier et ordre d'octets
explicites : int64 little-endian pour les lois et scores entiers, uint8
pour les comptes de phases. Les lois et tables exactes sont reconstructibles.
Les banques, panneaux, matrices, témoins et résultats restent conservés.

`run_higher_cbd.py --output <nouveau-dossier>` refuse tout écrasement.
`verify_higher_cbd_results.py` rejoue le calcul complet ;
`verify_higher_cbd_independent.py` contrôle les réductions, lois par couches
de bits, phases par produit matriciel, événements et moments, sans importer
l'arithmétique du projet. Les deux utilisent le runtime local verrouillé.

La généralisation vers CBD(2)/CBD(3) rapproche les distributions des scénarios
étudiés mais q=17 et les dimensions 3/5 restent réduits. Aucun coût d'attaque
réel, rotation MLWE, profil du rang 6, seuil C05 ou propriété CCA n'est validé
par ce jalon ; J2 reste ouvert.
