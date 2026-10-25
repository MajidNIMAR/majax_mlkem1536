# H07 — Famille LWE élargie et vecteurs issus de LLL

Étape engagée le 24 octobre 2026 et validée le 25, suivant le [protocole H07](PROTOCOLE_H07.md)
préenregistré au commit `9dfeefa`. Elle prolonge le
[score complet réduit](SCORE_DUAL_COMPLET_REDUIT.md), sans modifier les
paramètres du KEM ni les instantanés précédents.

## Famille et protocole de comparaison

Les modules restent q=5 et q=17, avec seize identifiants de matrices par
module au lieu de deux : 32 matrices 2×5 fixées par le même flux public
SHAKE de H06. Les identifiants 0/1 conservent les matrices précédentes.
Les cinq coordonnées du secret et deux erreurs suivent CBD(1). Les lois
de `(b,u_vrai)` sont entièrement énumérées, avec dénominateur 16384.

Les listes ont désormais 4, 8 et 12 vecteurs. Pour chaque matrice et taille,
on compare deux sources de vecteurs, deux familles de codes et deux critères
de décodage : **768 panneaux**. Les codes de longueur 4/dimension 1 restent
ceux de H06. Les familles répétée et pondérée coïncident à q=5. La seconde
source de vecteurs peut également retrouver exactement la référence : les
panneaux ne sont donc pas des réplications indépendantes.

## Réduction exacte et portée des vecteurs

Pour la première colonne A_l de la matrice, la base entière de lignes est

```
(1, 0, A_l[0])
(0, 1, A_l[1])
(0, 0, q)
```

Elle engendre les vecteurs `(y0,y1,x)` tels que `A_l^T y≡x mod q`.
Son déterminant est q. `research/exact_lll.py` effectue une réduction LLL
avec δ=3/4 et Gram-Schmidt entièrement rationnel. Le demi-entier est arrondi
vers +infini pour rendre le parcours déterministe. Le plafond de 10000
itérations déclenche un arrêt explicite s'il est dépassé.

Pour la base réduite R, une matrice entière U vérifie `R=U B` et `det(U)=±1`.
La trace des opérations se rejoue exactement. Toutes les conditions de
réduction en taille et de Lovasz sont vérifiées sur les rationnels. Ce
certificat établit la validité de la réduction en dimension 3 ; il ne mesure
pas la qualité ou le coût d'une réduction aux dimensions du rang 6.

Les 125 combinaisons de coefficients dans `[-2,2]^3` autour de R sont ensuite
projetées dans le cube centré modulo q. On retire zéro et les doublons à
signe près, puis on trie par norme et ordre lexicographique. Chaque candidat
garde son témoin de combinaison et satisfait la relation duale. La réduction,
l'énumération bornée et la projection sont trois étapes distinctes.

Cette liste ne constitue ni un crible ni un échantillonneur indépendant.
La projection peut raccourcir des combinaisons et la boîte bornée peut
omettre des vecteurs. La référence énumère, elle, tout le quotient non nul,
à signe près. On vérifie que chaque norme ordonnée de la liste bornée est
au moins celle du même rang dans la référence, et on compare les préfixes
complets. Une égalité des normes ne suffit pas à établir l'égalité des listes.

## Scores, données et contrôles

Le score, les lois et les seuils restent ceux de H06. Chaque panneau évalue
toutes les hypothèses de la DFT directe. La vraie hypothèse est la projection
`u=G^T s_f`, pas nécessairement le secret entier. Les rangs et événements
aux seuils 0 et 1/2 sont certifiés avec les tables encadrées de run-013 ;
aucune nouvelle table transcendante n'est nécessaire.

Les identités de données exactes servent à partager les calculs : matrice,
générateur du code et tous les `(y,x,c,r)` doivent coïncider. Les noms des
critères seuls ne servent jamais à décider qu'un calcul est réutilisable.
Les moments incluent toutes les covariances et sont évalués numériquement.
Les probabilités de rang/seuil et les moyennes de ces probabilités sur les
seize matrices sont des fractions exactes.
Une hausse de moyenne du score est relevée au-delà de 10^-12 ; les gains
et pertes de classement sont, eux, comparés en fractions exactes.

Les lois et tables complètes sont reconstructibles depuis les entrées et
liées par SHA-256. Les trois distributions exactes (vrai score, faux score
mélangé, maximum faux) ont aussi leurs empreintes. Cette conservation évite
de dupliquer de grandes tables identiques ; chaque empreinte est rejouée
par les vérificateurs.

Un programme indépendant ne charge aucune arithmétique du projet. Il vérifie
les conditions LLL avec une construction de Gram différente, rejoue la trace,
reconstruit les candidats et les choix de code, puis énumère littéralement
les **524 288 configurations de bits CBD** des 32 matrices. Il retrouve les
lois, scores, événements et empreintes de distributions. Il distingue aussi
les ordres certifiés, les égalités et les intervalles non résolus.

## Résultats de la famille

Les [données de run-014](../results/j2/run-014/summary.json) contiennent les
32 matrices et 768 panneaux, regroupés en **224 banques de scores distinctes**.
Chaque banque conserve les empreintes de sa loi et de ses tables complètes.

Les préfixes de la liste issue de LLL et de l'énumération bornée coïncident
avec la référence exhaustive dans les proportions suivantes :

| Module | N=4 | N=8 | N=12 |
|---|---:|---:|---:|
| q=5 | 16/16 | 16/16 | 16/16 |
| q=17 | 15/16 | 13/16 | 9/16 |

À q=17, la somme des excès de norme au carré sur les seize listes vaut
respectivement 5, 18 et 70 pour N=4,8,12. Ce sont des écarts de listes
complètes, pas une mesure d'un facteur d'approximation en grande dimension.
La boîte bornée après LLL manque donc certains préfixes dès ces petites
tailles ; le certificat LLL ne garantit pas leur récupération exhaustive.

Au code pondéré q=17, les moyennes des probabilités de succès strict sur
les seize matrices sont :

| Source et taille | Euclidien | CBD | CBD meilleur / moins bon / égal |
|---|---:|---:|---:|
| Référence, N=8 | 29,7844 % | 29,5486 % | 0 / 2 / 14 |
| LLL + boîte, N=8 | 29,8553 % | 29,6196 % | 0 / 2 / 14 |
| Référence, N=12 | 32,5386 % | 32,4234 % | 1 / 1 / 14 |
| LLL + boîte, N=12 | 32,5005 % | 32,4509 % | 1 / 1 / 14 |

Dans les deux pertes observées à N=8 pour chacune des sources, la moyenne
du vrai score s'améliore avec CBD. Le constat de H06 se maintient donc sur
la famille élargie, sans faire de CBD un critère systématiquement inférieur.
Pour le code répété q=17, source LLL/N=12, on compte six gains, sept pertes
et trois égalités ; la moyenne de succès passe pourtant de 20,1294 % à
20,8282 %. Le signe moyen et la fréquence des gains répondent à deux
questions distinctes. Les codes répétés restent moins efficaces en moyenne
que les codes pondérés dans ces strates.

Pour le témoin uniforme à q=17 et au seuil 1/2, les probabilités moyennes
sur seize matrices sont :

| N | Référence exhaustive | LLL + boîte | Normale de mêmes moyenne et variance |
|---|---:|---:|---:|
| 4 | 11,4187 % | 11,4187 % | 7,8650 % |
| 8 | 6,2716 % | 6,2284 % | 2,2750 % |
| 12 | 4,2388 % | 3,9792 % | 0,7153 % |

La variance est toujours 1/(2N) pour les listes contrôlées. À N=12, le
rapport de la queue moyenne à la queue normale vaut environ 5,93 pour
la référence et 5,56 pour la source LLL. La queue réelle diminue avec N
en moyenne dans ce tableau, mais son rapport à la normale augmente.
Ces rapports restent propres à ces petits alphabets et listes.

À q=5,N=12, la liste contient toutes les paires de signes non nulles du
quotient Z_5². Au témoin uniforme, le score vaut 1 pour b=0 et −1/24
ailleurs, par orthogonalité des caractères. Sa queue au seuil 1/2 est
donc exactement 1/25, ce qui explique ce cas discret extrême ; ce n'est
pas un modèle de liste de crible indépendante.

## Interprétation et travaux restants

La comparaison est stratifiée par module, source, famille de code et taille
de liste. Chaque strate compte seize matrices, avec les gains, pertes et
égalités CBD/euclidien explicitement séparés. On relève en particulier les
cas où la moyenne du vrai score augmente mais son classement se dégrade.
Le témoin uniforme est comparé à la normale de variance 1/(2N), sans
identifier sa loi à celle des faux candidats LWE.

Cette famille déterministe fournit un contrôle élargi. Elle ne produit pas
d'intervalle de confiance sur toutes les matrices LWE ni de transfert
quantitatif aux grandes dimensions. L'étape de LLL est effective, mais
aucun BKZ, crible, modèle de rotations MLWE ou coût réel d'attaque n'est
déduit de son certificat. La sélection d'un profil, la transformation CCA,
les ressources et les paramètres réels restent à traiter dans J2.

## Complément exécuté : distributions η=2/3 et dimension 5

[run-015](CBD_ET_DIMENSIONS_SUPERIEURES.md) traite maintenant les lois
CBD(2)/CBD(3) et une architecture de réseau de dimension 5. Une récurrence
entière et une méthode indépendante de couches Bernoulli remplacent
l'énumération littérale des bits. Les contre-exemples de classement
persistent ; les données de run-014 restent préservées comme contrôle.
