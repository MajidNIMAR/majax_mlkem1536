# J2 — Adaptation du dual avec codes et rotations

Étape du 24 octobre 2026, conservée dans [run-008](../results/j2/run-008/study.json). L'adaptateur est du code d'analyse cryptographique ; il n'implémente pas KeyGen, Encaps ou Decaps du rang 6. Le profil n'est pas sélectionné et J2 reste ouvert.

## Périmètre réellement exécuté

Le code mathématique et les résultats texte proviennent de [TabOg/CodedDualAttack au commit e2104ca50a293ed09b8fcec703cd2b143d21bee8](https://github.com/TabOg/CodedDualAttack/tree/e2104ca50a293ed09b8fcec703cd2b143d21bee8/OptimizeCodedDualAttack). La copie documentaire, les points de contrôle et l'empreinte de l'archive sont conservés dans [references/coded-dual-evaluation](../references/coded-dual-evaluation/manifest.json). Les deux fichiers de résultats texte ont été comparés aux octets de l'archive vérifiée.

L'intégration ne charge aucun pickle, bytecode ou objet natif fourni. Le lanceur vérifie l'archive et ses sources Python. Pour les calculs de contrôle, une liste explicite de fonctions mathématiques est extraite par AST ; les imports du décodeur polaire, les scripts principaux et leurs effets de bord sont exclus. La dépendance de réduction embarquée par les auteurs est utilisée, distincte de la version communautaire de run-002.

La version e2104 possède déjà une intégrale pondérée utilisant beta1 avec dlat : elle ne reproduit pas l'appel nfft incohérent identifié dans la version 7b7e8000. Notre adaptation ne se présente donc pas comme une correction originale de ce point. Elle retire la spécialisation du pilote à q=3329 et remplace le plafond arbitraire beta0=1000 par la dimension effective du réseau.

## Calibration et stabilité numérique

Six points publiés, modèle de coût CC (`MATZOV list_decoding-classical`) : dimensions LWE 512, 768, 1024, chaque fois avec et sans l'heuristique MLWE des auteurs. Les moyennes et écarts types de décodage publiés sont employés seulement pour ces contrôles à q=3329. Le calcul natif à 2048 bits reproduit les six coûts et les couples beta0/beta1. L'adaptateur retrouve ces valeurs à une tolérance de 10^-8 dans les logarithmes de coûts ; les écarts constatés sont de l'ordre de 10^-13.

L'intégrale utilisée est `I(b,c)=b*∫[0,1]t^(b−1)exp(−ct²)dt`. Avec s=b/2 : `I=s*c^-s*gamma_lower(s,c)`. Une série à termes positifs évite la soustraction de deux gamma presque égales ; les autres cas utilisent la gamma incomplète régularisée. Les queues normales sont évaluées dans le domaine logarithmique, sans calculer `1−erf(x)` en double précision.

Une seconde voie reprend les fonctions des auteurs, adapte explicitement le plafond beta et utilise la gamma inférieure et erfc avec mpmath à 160 décimales, dans un champ Sage à 2048 bits. Elle retrouve les quatre meilleurs points conservés : mêmes beta0/beta1, écarts de coût, de répétitions et de seuil tous inférieurs à 10^-8, le plus grand écart observé étant d'environ 3,54*10^-12. C'est une contre-vérification numérique du même modèle, pas une validation indépendante de ses hypothèses cryptanalytiques.

## Hypothèses de la nouvelle comparaison

- Anneau de degré 256 ; dimensions LWE aplaties 1024 et 1536, donc rangs 4 et 6. Le champ `n` des résultats de cette étude désigne cette dimension aplatie, pas le degré polynomial.
- Scénarios (q=3329,η=2) et (q=7681,η=3), avec secrets et erreurs CBD de même paramètre.
- Une cible, aucun oracle, mémoire exponentielle autorisée sans plafond ; uniquement des sous-ensembles de la clé publique, m≤dimension LWE. Aucun chiffré n'est traité comme un échantillon LWE propre supplémentaire.
- Décodage idéal au rayon GV, ratio 1, avec la formule de coût du décodeur des auteurs. Aucune statistique polaire de q=3329 n'est transférée à q=7681. L'atteignabilité conjointe de ce rayon et de ce coût n'est pas démontrée.
- Probabilité de succès du sous-ensemble nul visée : 0,6 ; budget heuristique global de faux candidats sous modèle normal : 0,05. Ces deux critères ne constituent pas une preuve de succès global de l'attaque.
- Nombre de répétitions borné à 2^100 conformément au cadre repris. Un point refusé à ce titre n'est pas une preuve de résistance.

Pour le sous-ensemble de a coordonnées supposées nulles, les auteurs modélisent Z, le nombre de zéros dans une population de taille P, par une binomiale de paramètre `p0=binom(2η,η)/2^(2η)`. Conditionnellement à Z=z, la probabilité d'un sous-ensemble nul est `binom(z,a)/binom(P,a)`, et le succès après R essais est moyenné sous la forme `1−(1−p)^R`. P vaut a+nfft dans le panneau LWE et toute la dimension aplatie dans le panneau MLWE.

Cette dernière convention est l'heuristique des auteurs. Elle n'est pas une énumération exacte des dépendances entre les 256 rotations d'un module de rang 6. Le degré est explicitement contrôlé, mais aucun facteur 1536 rotations ni soustraction forfaitaire d'un bit n'est introduit. Des tests rationnels sur petites populations contrôlent la formule probabiliste, sans la transformer en preuve du modèle des rotations.

## Résultats conditionnels

La grille comporte 576 points : deux scénarios, deux conventions LWE/MLWE, trois tailles m, quatre valeurs de a, trois nfft et quatre kfft. Elle est complétée par des découpages issus des points publiés et une descente par coordonnées depuis trois points de départ, limitée à douze balayages chacun. Les 1043 évaluations uniques sont conservées : 969 coûts conditionnels et 74 points dont la cible de sous-ensemble nul n'est pas atteinte dans la limite de répétitions. Aucune erreur d'exécution n'est masquée.

| Scénario | Heuristique | Plus petit log2(coût) rencontré | beta0 / beta1 | log2(taille de liste) |
|---|---|---:|---:|---:|
| Témoin 1024, q=3329,η=2 | LWE | 258,482114 | 807 / 788 | 163,524775 |
| Témoin 1024, q=3329,η=2 | MLWE des auteurs | 256,969531 | 801 / 783 | 162,487181 |
| Rang 6, q=7681,η=3 | LWE | 381,755780 | 1244 / 1204 | 249,852575 |
| Rang 6, q=7681,η=3 | MLWE des auteurs | 379,998696 | 1237 / 1197 | 248,399943 |

Les points sont des minima de recherche bornée, pas des optimums globaux. Une trajectoire de chaque panneau du rang 6 atteint la limite de douze balayages en progressant encore ; celle du panneau MLWE fournit le meilleur point rapporté. Ce signal est conservé, et la convergence locale de ce dernier n'est pas revendiquée. L'écart entre les deux panneaux ne mesure donc pas une perte de sécurité démontrée due aux rotations.

Pour chaque point admissible, l'adaptateur vérifie le budget au beta retenu, l'échec de son prédécesseur, et un diagnostic de monotonie sur un maillage de tout l'intervalle de recherche. Ce diagnostic n'est pas une preuve de monotonie à chaque entier. Les quatre points retenus ne touchent pas le plafond final. Au rang 6, remettre le plafond à 1000 rend les deux points inadmissibles au budget de faux candidats : l'ancien pilote ne pouvait pas simplement être exécuté tel quel.

Les coefficients finis de MATZOV sont documentés dans la dépendance comme ajustés jusqu'à beta=1024. Leurs extrapolations au-delà sont marquées dans chaque résultat concerné. Une liste de l'ordre de 2^248 vecteurs, sans comptage de toute la mémoire de l'algorithme, représente une ressource théorique considérable. Ces coûts ne doivent pas être présentés comme une résistance réalisable sous mémoire bornée.

## Ce que l'étape permet de décider

Le volet dual avec codes dispose maintenant d'un adaptateur exécutable et calibré ; il dépasse l'inventaire bibliographique et l'inspection documentaire. Le panneau MLWE au rang 6 donne environ 2^380 opérations sous ses hypothèses. Ce nombre n'est ni une attaque exécutée, ni un niveau de sécurité du KEM, ni une preuve que toutes les attaques actuelles coûtent au moins cela. La longueur des graines, les fonctions de hachage et les autres surfaces du KEM doivent aussi entrer dans l'analyse globale.

Les coûts run-002 restent conservés et ne sont pas remplacés silencieusement. Le nouveau panneau utilise une autre dépendance et des hypothèses de décodage/score explicites ; on ne soustrait pas son écart aux anciens chiffres pour annoncer un gain ou une perte universels. H01 et H02 ont la même clé publique dans ce volet ; leurs distributions de chiffrés ne sont toujours pas validées par ces coûts.

Les prochaines tâches de J2 sont de poursuivre l'optimisation jusqu'à une stabilité documentée, d'évaluer un décodeur concret à q=7681 ou d'établir un autre modèle de code justifié, puis de confronter les seuils aux analyses de covariance et de queues du score dual. Restent aussi les contraintes mémoire, l'analyse du chiffré et la transformation CCA. Les nouvelles données n'imposent aucun changement automatique de paramètres et ne ferment pas J2.

## Reproduction

**Suite de la recherche.** [run-009 et son analyse](STABILISATION_DUAL.md) prolongent les trajectoires avec un modèle inchangé et un contrôle local de 32 voisins autour de chaque point retenu. Le meilleur point MLWE du rang 6 descend à log2(coût)=378,984845. Les données de run-008 ci-dessus restent l'instantané initial ; ce complément ne les remplace pas silencieusement et ne démontre pas un optimum global.

Sous Windows, préparer le runtime avec `scripts/bootstrap-modern.ps1`, puis lancer `wsl -d Ubuntu-22.04 -- bash scripts/coded-dual.sh --output artifacts/generated/nom-inexistant`. Le programme refuse de remplacer un répertoire existant. Les six calibrations doivent réussir avant le panneau exploratoire. La contre-vérification complète utilise `research/verify_coded_dual_numeric.py` avec le même environnement Sage et les arguments `--run` et `--output` dirigés vers une nouvelle sortie du même dossier.

Le contrôle courant `python research/verify_coded_dual_results.py` ne requiert que Python standard : empreintes, calibrations enregistrées, sommes de coûts, contraintes de dimensions, probabilités et rattachement des contre-vérifications. Il ne relance pas les calculs Sage. `scripts/dev.ps1 check` l'exécute avec les autres contrôles.
