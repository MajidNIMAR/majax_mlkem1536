# J2 — Décodeurs concrets par blocs à q=7681

Étude du 24 octobre 2026, conservée dans [run-010](../results/j2/run-010/study.json). Deux codes et leurs décodeurs sont implémentés et exécutés aux quatre dimensions de décodage retenues dans run-009, avec leurs contrôles exhaustifs et des mesures locales. Il s'agit de la brique de quantification de l'analyse d'attaque duale. La décapsulation du message du KEM de rang 6 n'est pas implémentée par cette étude.

## Construction explicitement étudiée

Le code contient ℓ coordonnées modulo q et d symboles indépendants. Les coordonnées sont réparties en d blocs contigus équilibrés. Un symbole a produit, dans son bloc, `(a*g0,...,a*g(s−1)) mod q`. Les générateurs commencent par g0=1 ; il y a donc exactement q^d mots distincts. La somme des distances euclidiennes modulaires au carré se sépare entre les blocs. Minimiser chaque bloc indépendamment donne le mot du code le plus proche dans cette métrique ; les égalités sont départagées par le plus petit vecteur de symboles dans l'ordre lexicographique.

Le contrôle « répété » utilise g=(1,...,1). Le code « pondéré » utilise g=(1,b,b²,...) modulo q, avec b égal à l'entier le plus proche de la racine s-ième de q, déterminé par des comparaisons entières. Ce choix est explicite, sans optimisation des générateurs ni revendication de nouveauté. Les deux familles conservent la même longueur, le même nombre de symboles et le même nombre de mots.

Pour le point MLWE du rang 6, ℓ=nfft=140 et d=kfft=21 : quatorze blocs de sept coordonnées et sept blocs de six. Ces 21 symboles appartiennent au code auxiliaire de l'attaque ; le KEM étudié reste un module de rang 6 avec six polynômes de 256 coefficients.

## Deux algorithmes réellement exécutés

Pour un bloc répété de taille s, le décodeur minimise `Σ centered(x_i−a)^2` pour a entier modulo q. Entre deux changements de représentant centré, les valeurs relevées y_i sont fixes et l'objectif est le polynôme `Σy_i²−2aΣy_i+s*a²`. Sur chaque intervalle entier, seuls les deux entiers autour de la moyenne, ramenés dans l'intervalle, doivent être examinés. Le passage d'un seuil ajoute q aux valeurs concernées ; les sommes et sommes de carrés sont actualisées exactement. Il y a au plus s+1 intervalles et 2(s+1) évaluations candidates, après tri des seuils. Les calculs et les égalités sont entièrement entiers.

Pour les blocs pondérés, le décodeur NumPy énumère les q symboles et calcule toutes les distances exactement en entiers de 64 bits. Les limites q<2^16 et ℓ≤256 maintiennent les sommes très en dessous de leur capacité. `argmin` retient le premier symbole en cas d'égalité. La séparation des blocs rend cette énumération exacte pour le code complet : au point 140/21, elle calcule q*d=161301 scores de blocs et q*ℓ=1075340 termes de distance par décodage. Elle n'énumère pas les q^21 vecteurs complets.

La structure en blocs rend ces opérations abordables. Elle ne fournit pas un décodeur pour un code aléatoire ou polaire arbitraire de mêmes dimensions. Aucun objet natif ou pickle fourni par un dépôt tiers n'est chargé. NumPy provient du runtime local déjà verrouillé.

## Validation exacte

Cinq tests vérifient l'algorithme par intervalles contre tous les centres pour les blocs de tailles 1,2,3 aux modules 3,5,7 ; les frontières circulaires et égalités ; la factorisation d'un petit code complet ; la forme 140/21 et un parcours de mots du code ; les formats invalides et le choix entier de la base.

Les six études de petits paramètres, deux familles pour (q,ℓ,d)=(5,3,1),(5,4,2),(7,4,2), parcourent au total 6302 cibles. Le résultat bloc par bloc est comparé à l'énumération de tous les mots du code complet, avec ses égalités. Les histogrammes des distances au carré et leurs masses sont conservés.

Un second programme, sans import de l'arithmétique du projet, reconstruit les six livres de codes et leurs histogrammes. Il vérifie aussi 64 blocs aux modules réels 3329/7681 en énumérant tous leurs symboles, soit 352320 candidats supplémentaires ; distances et symboles sélectionnés concordent. Enfin, le vérificateur courant reconstruit les 2048 cibles synthétiques à partir des graines publiques, contrôle les empreintes, les mots décodés et toutes les distances enregistrées.

## Qualité observée face au modèle idéal

Chaque expérience utilise 256 cibles de test déterministes sur le tore, produites par un flux SHAKE avec rejet des intervalles incomplets de 16 bits. Les deux familles d'un même panneau reçoivent exactement les mêmes cibles. Ce sont des données synthétiques, sans clé réelle et sans affirmation de loi des chiffrés du KEM.

Le rayon de référence est celui du modèle antérieur : `r_GV=q^(1−d/ℓ)*Γ(ℓ/2+1)^(1/ℓ)/sqrt(pi)`. C'est une approximation géométrique continue utilisée comme repère, pas un rayon de couverture prouvé ou atteint par nos codes. Le tableau présente la moyenne observée de la norme divisée par cette référence.

| Module et dimensions ℓ/d | Convention d'attaque du point parent | Blocs répétés : moyenne/r_GV | Blocs pondérés : moyenne/r_GV |
|---|---|---:|---:|
| 3329,114/16 | LWE témoin | 2,742035 | 1,144659 |
| 3329,111/16 | MLWE témoin | 2,814699 | 1,147038 |
| 7681,152/22 | LWE rang 6 | 3,211444 | 1,165069 |
| 7681,140/21 | MLWE rang 6 | 3,332703 | 1,177973 |

Au point 140/21, le rayon de référence vaut environ 5873,215. La norme moyenne observée passe de 19573,680 à 6918,488 ; son écart type empirique pour le code pondéré est 257,888. Les blocs pondérés améliorent donc nettement ce contrôle simple, avec une norme moyenne encore environ 17,8 % au-dessus du repère idéal. Aucune des 256 cibles de ce panneau n'a une distance inférieure ou égale à ce rayon ; ce compte descriptif n'est pas une borne de probabilité générale. Les maxima observés ne sont pas des rayons de couverture.

## Mesures d'exécution

PC local, AMD Ryzen 7 2700, WSL2/Linux x86-64, Python 3.12.15 et NumPy 2.5.4. Sept séries de huit appels unitaires sont conservées par expérience. Les tableaux de mots sont préconstruits ; génération des cibles, vérifications et écritures sont hors chronométrage. Les allocations du décodage, les contrôles d'entrée et les appels Python sont inclus. Les valeurs sont la médiane des durées de séries divisée par huit.

Au point q=7681,140/21 : environ 0,457 ms pour le contrôle répété par intervalles et 6,752 ms pour l'énumération pondérée. Ces mesures décrivent ce prototype et cet environnement ; elles ne constituent pas des budgets de production ou des mesures de temps constant. Les données brutes et l'environnement sont dans `timings.json`.

## Conséquence pour la faisabilité

Un décodeur exact concret fonctionne maintenant à q=7681 aux dimensions examinées ; les calculs de distance et de coût d'exécution sont mesurables et reproductibles. Le résultat est positif face au contrôle répété, mais l'hypothèse idéale de run-009 n'est pas réalisée par cette construction. La sélection de générateurs reste élémentaire et des améliorations peuvent être étudiées.

La moyenne et l'écart type des normes ne suffisent pas à valider les scores duaux : les erreurs de ces codes sont structurées par blocs et leur direction peut compter. Le coût de leur recherche exhaustive n'est pas celui du décodeur polaire supposé par le modèle. Les millisecondes ne se substituent pas aux unités rop de l'estimateur. Aucun coût d'attaque, profil du KEM ou objectif C05 n'est modifié.

La suite [run-011](SCORES_DECODEUR.md) traite la distribution des erreurs et une contribution CBD aux scores, avec ses covariances à secret partagé. Le score complet de l'attaque et un compromis coût/distance amélioré restent à étudier. Une variante de construction propre au projet peut être testée dans ce cadre. J2 reste ouvert pour ces points et pour la sécurité du KEM complet.

## Reproduction

Avec le runtime local disponible : `wsl -d Ubuntu-22.04 -- bash scripts/block-decoder.sh --output artifacts/generated/nom-inexistant`. Le dossier de destination doit être nouveau. Contrôles sans Sage ou NumPy : `python research/verify_block_decoder_results.py` et `python research/verify_block_decoder_independent.py`. Le second rejoue les énumérations indépendantes ; le premier vérifie les données, leurs distances et statistiques sans relancer le chronométrage.
