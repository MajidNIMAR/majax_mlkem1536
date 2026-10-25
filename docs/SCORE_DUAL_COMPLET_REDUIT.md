# H06 — Score dual complet dans un modèle LWE fini

Étude du 24 octobre 2026, figée dans [run-013](../results/j2/run-013/study.json),
après le [protocole](PROTOCOLE_H06.md) enregistré au commit `3cbbd7c`.
Le mot « complet » concerne les contributions au score et toutes les
hypothèses de ce modèle réduit. Il ne désigne pas une attaque complète
contre les paramètres du rang 6.

## Construction et identité de phase

Quatre matrices publiques A, deux pour chacun des modules q=5 et q=17,
sont produites par des étiquettes SHAKE fixes avant observation des résultats.
Chaque A a deux lignes et cinq colonnes, séparées en une colonne A_l et
quatre colonnes A_f. Le secret s a cinq coordonnées et l'erreur e deux,
toutes iid-CBD(1). L'échantillon public est `b=A s+e mod q`.

Tous les y non nuls de Z_q² sont représentés dans le cube centré. Un seul
représentant de chaque paire ±y est gardé. Poser `x=centre(A_l^T y)` donne
la relation duale effective `A_l^T y≡x mod q`. Les représentants sont triés
par `||y||²+x²`, puis lexicographiquement. Les deux listes imbriquées gardent
les 4 ou 8 premiers. Cette construction est une énumération de représentants
d'un petit quotient du réseau, sans crible ni BKZ et sans calibration d'un
coût de réduction à grande dimension.

Le vecteur `t=A_f^T y` est décodé dans un code de longueur 4 et dimension 1,
avec générateur G, symbole c et résidu `r=centre(t−G c)`. Les familles
répétée et pondérée et les critères euclidien et CBD de H05 sont comparés.
À q=5, le choix de base de la famille pondérée donne 1 : les deux familles
coïncident alors. Les 32 panneaux sont des contrôles déterministes, dont
plusieurs identiques, pas 32 expériences indépendantes.

La vraie hypothèse de Fourier est `u_vrai=G^T s_f mod q`. Pour chaque u :

`S_b(u) = (1/N) Σ_y cos(2π(y^T b−c_y u)/q)`.

À la vraie hypothèse, l'identité exacte modulo q est :

`y^T b−c_y u_vrai ≡ y^T e+x_y s_l+r_y^T s_f`.

Le score comprend donc le bruit des échantillons, la coordonnée du secret
associée au réseau et les quatre coordonnées associées au décodeur. Les
**419 904 identités de phase** sont contrôlées sur les états distincts CBD
et tous les vecteurs des panneaux. Deviner u ne reconstitue pas nécessairement
le secret complet s.

## Fourier, lois et décisions certifiées

Pour chaque b possible et chacun des q candidats, conserver l'histogramme
des phases symétrisé par `p↔q−p`. Sa valeur est une combinaison entière des
cosinus de `2πd/q`. Les mêmes scores sont retrouvés par une DFT directe de
l'accumulateur `H(c)=Σ_{y:c_y=c}exp(2πi y^T b/q)` :

`S_b(u)=Re(Σ_c H(c)exp(−2πi c u/q))/N`.

Le contrôle DFT est numérique, avec un écart maximal d'environ 8,22×10^-15.
Il n'y a pas d'FFT optimisée dans cette expérience. Les décisions de rang
et de seuil ne reposent pas sur ce contrôle flottant.

Les cosinus sont encadrés à 192 bits puis quantifiés par partie entière
sur l'échelle `K=2^48`. Si T est leur somme entière pour N termes, le
numérateur réel du score appartient à `[T/K,(T+N)/K)`. Des intervalles
séparés certifient l'ordre des scores et les franchissements des seuils 0
et 1/2. Deux histogrammes symétrisés identiques certifient une égalité.
Le programme s'arrête si des histogrammes distincts ne peuvent pas être
ordonnés ; aucun tel cas non résolu n'est rencontré ici.

Les 2187 états distincts de (e,s) ont des poids entiers, de somme 16384
par matrice. La loi jointe de `(b,u_vrai)` est donc conservée exactement.
Les probabilités de rang et de seuil sont des fractions exactes. Les
distributions de scores sont stockées comme histogrammes de combinaisons
de cosinus avec poids entiers ; leurs moments affichés restent numériques.

## Résultat : meilleure moyenne, classement parfois moins bon

Au premier cas q=17, code pondéré et liste N=8 :

| Quantité | Critère euclidien | Critère CBD |
|---|---:|---:|
| Moyenne du vrai score | 0,409555761 | 0,410652443 |
| Variance du vrai score | 0,066655061 | 0,068712060 |
| Variance en omettant les covariances entre termes | 0,041428734 | 0,041295451 |
| Probabilité que le vrai candidat soit strictement premier | 2929/8192 ≈35,7544 % | 1311/4096 ≈32,0068 % |
| Au moins un faux score ≥1/2 | 4303/8192 ≈52,5269 % | 2499/4096 ≈61,0107 % |

Le critère CBD améliore la moyenne du vrai score mais son succès au
classement baisse de **3,7476 points de pourcentage** dans ce cas. Les faux
scores et les dépendances comptent aussi. La seule amélioration du biais
auxiliaire de H05 n'est donc pas un critère suffisant d'utilité d'attaque.

L'effet n'est pas uniforme : au second cas q=17, contrôle répété, N=8,
le succès strict passe de 11,5356 % à 14,7949 % avec CBD ; dans le code
pondéré de ce même cas, les deux critères donnent les mêmes résultats.
Tous les panneaux, y compris les résultats identiques et négatifs, sont
conservés. Ces proportions sont celles des lois finies fixées, sans moyenne
sur des matrices uniformes ni extrapolation aux paramètres cryptographiques.

Le vrai candidat peut aussi être ex aequo au maximum. L'étude sépare
succès strict, appartenance à l'argmax et succès si le départage entre ex
aequo est uniforme. Ces trois quantités ne sont pas interchangées.

## Covariances complètes et faux candidats

Pour le vecteur de coefficients `a_y=(y,x_y,r_y)`, poser
`Φ(a)=∏ cos(π a_i/q)^2`. Pour le candidat décalé de d par rapport au vrai,
la moyenne d'un terme vaut `Φ(a_y)cos(2πc_y d/q)`. Le produit de deux termes
a pour espérance :

`[Φ(a_y−a_z)cos(2π(c_y−c_z)d/q) + Φ(a_y+a_z)cos(2π(c_y+c_z)d/q)]/2`.

Soustraire le produit des moyennes donne la covariance. La somme de toutes
les covariances, divisée par N², donne la variance du score. Ces formules
sont confrontées à la loi énumérée pour chaque décalage, vrai ou faux.
La vérification indépendante retrouve les moments à environ 1,70×10^-15
près dans les calculs affichés.

Au seuil 1/2, la probabilité qu'au moins un candidat faux le franchisse ne
se déduit pas du seul produit des probabilités marginales :

| Cas q=17, N=8 | Probabilité jointe réelle | Hypothèse d'indépendance des événements | Borne d'union exacte |
|---|---:|---:|---:|
| Matrice 0, pondéré euclidien | 52,5269 % | 54,0966 % | 74,3286 % |
| Matrice 0, pondéré CBD | 61,0107 % | 58,6043 % | 83,5083 % |
| Matrice 1, pondéré euclidien | 27,4170 % | 24,5365 % | 27,8198 % |

Le produit peut surestimer ou sous-estimer le résultat. La borne d'union
emploie ici les probabilités marginales exactes ; elle reste valable sans
indépendance. Les probabilités de seuil ne sont pas les probabilités de
classement : un faux candidat sous 1/2 peut dépasser le vrai, et inversement.

## Témoin uniforme : bonne variance, queue différente

Le témoin tire b uniformément dans Z_q² et fixe u=0, indépendamment. Ce
n'est pas la loi d'un faux candidat dans l'expérience LWE corrélée au vrai u.
Comme les y sont non nuls et distincts à signe près, l'orthogonalité des
caractères donne une moyenne nulle et une variance exactement **1/(2N)**,
sans indépendance des termes.

Pour q=17, première matrice, N=8, cette variance est 1/16. Pourtant :

- probabilité réelle `Pr[S_b(0)≥1/2]` : **19/289 ≈6,5744 %** ;
- approximation normale de même moyenne et variance : **≈2,2750 %**.

L'écart vaut un facteur d'environ 2,89 sur cette queue. À la seconde matrice,
la probabilité réelle est 1/17≈5,8824 %. Les petites listes et alphabets
finis de ce témoin ne valident ni n'invalident quantitativement une heuristique
à grande dimension. Ils démontrent dans ce modèle que l'accord des deux
premiers moments ne suffit pas à justifier une queue normale.

## Vérifications et suite

Un programme indépendant, sans import de l'arithmétique du projet :

- régénère les quatre matrices et les listes duales, puis les choix des codes ;
- énumère littéralement **65 536 configurations de 14 bits CBD**, au lieu
  de reprendre les poids des 2187 états distincts ;
- retrouve les lois jointes, les **80 608 scores** de toutes les hypothèses,
  leurs événements de rang et de seuil et leurs distributions exactes.

Un second contrôle, mpmath.iv à 160 décimales, retrouve les cellules entières
des **24 entrées transcendantes** utilisées, valeurs en zéro comprises.
Les trois provenances relient les sources et sorties. Les douze instantanés
antérieurs sont préservés.

Ce jalon fournit une chaîne complète et contrôlable sur un modèle réduit.
La suite devra tester la stabilité sur une famille plus large de matrices
et de tailles de liste, puis une génération de vecteurs issue d'une réduction
de réseau dans un cadre toujours vérifiable. Les distributions MLWE, les
rotations, les ressources, les très grandes listes et les paramètres réels
restent des travaux distincts. Aucune révision forfaitaire de run-009 n'est
faite à partir du facteur 2,89 ou des taux de succès du petit modèle.

Aucun coût global de sécurité, seuil C05, profil ou propriété CCA du KEM
n'est validé par cette expérience ; J2 reste ouvert.

## Reproduction

`research/full_dual_toy.py` contient la chaîne standard Python.
`run_full_dual_toy.py --output <nouveau-dossier>` utilise le runtime Sage
local uniquement pour les tables encadrées et refuse tout écrasement.
`verify_full_dual_toy_results.py` rejoue le calcul ;
`verify_full_dual_toy_independent.py` effectue la seconde énumération.
Ces deux programmes sont intégrés à la tâche `check`, sans Sage ou NumPy.
`verify_full_dual_toy_intervals.py --run <nouvelle-étude>` produit le contrôle
mpmath.iv dans un dossier où ses sorties n'existent pas encore.

## Complément exécuté : famille élargie et réduction

[run-014](LLL_ET_FAMILLE_ELARGIE.md) étend ce modèle à 32 matrices, listes
4/8/12 et génération de candidats à partir d'une base LLL exacte. Les
contre-exemples de classement et de queues persistent ; la boîte bornée
après réduction manque parfois des préfixes de l'oracle exhaustif.
Les données de run-013 restent l'étude initiale, préservée.
