# H05 — Décoder par le biais CBD plutôt que par la distance

Étude du 24 octobre 2026, conservée dans [run-012](../results/j2/run-012/study.json).
Le [protocole](PROTOCOLE_H05.md) a été enregistré au commit `17f30d3` avant
l'exécution. Les codes, paramètres et 2048 cibles de run-010 sont inchangés.
Cette expérience concerne le décodeur auxiliaire de l'analyse duale, pas
la décapsulation du KEM.

## Objectif et garantie

Sous le secret idéal iid-CBD(η) de run-011, indépendant des résidus, le biais
de la contribution cosinus vaut `φ(r)=∏ cos(π r_i/q)^(2η)`. Maximiser ce biais
revient à minimiser `C(r)=Σ −2 ln cos(π |r_i|/q)` puisque `φ=exp(−η C)`.
Le critère est indépendant de η lorsqu'il est commun aux coordonnées.
La somme se sépare entre les blocs du code, comme la distance euclidienne.

Une table contient `w[d]=floor(S×(−2 ln cos(π d/q)))`, avec `S=2^40` et
`0≤d≤⌊q/2⌋`. Sa construction utilise des boules réelles Sage/Arb à 192 bits :
les deux bornes de chaque intervalle doivent avoir la même partie entière.
La valeur en zéro est traitée exactement. Tous les calculs de sélection
suivants sont des sommes d'entiers sur 64 bits ; le budget est contrôlé
avant usage. Les égalités sont départagées par le plus petit symbole.

Si `T=Σ w[|r_i|]`, alors `T/S≤C<(T+n)/S`. Le minimiseur entier satisfait
`C_choisi−C_optimal<n/S`. Son défaut éventuel en log2 du biais optimal est
donc inférieur à `η n/(S ln 2)` : au plus environ **5,99×10^-10** sur les
formes expérimentées, et **5,51×10^-10** au point 140/21.

Un certificat plus fort est calculé pour chaque bloc de taille b : tous
les symboles dont le coût entier est inférieur à `T_min+b` doivent avoir
le même multiensemble d'erreurs absolues que le symbole retenu. Ces symboles
ont alors exactement le même coût réel ; les autres ont un coût réel
strictement supérieur par l'encadrement. Cette condition certifie le minimum
réel et son départage. Si elle échoue, seule la garantie d'approximation est
annoncée ; aucune égalité entre histogrammes différents n'est présumée.

Les **38 400 blocs** des expériences aux modules réels satisfont ce certificat.
Les **12 354 blocs** des petits modèles le satisfont également. Aucune
ambiguïté restante n'est observée dans cette expérience, sans garantie que
cela vaille pour d'autres entrées ou codes.

## Comparaison appariée

Pour les deux critères, chaque bloc parcourt les q symboles possibles :
`q×k` candidats et `q×n` contributions coordonnées par appel. Le contrôle
euclidien retrouve les symboles et normes de run-010 pour les 2048 cibles.
La référence répétée rapide par intervalles de run-010 reste distincte :
elle ne constitue pas le budget égal d'énumération utilisé ici.

Les résultats suivants concernent les codes pondérés, avec 256 cibles chacun.
Le gain de biais est le rapport des moyennes empiriques de φ, moins un ;
ce n'est pas l'exponentielle de la moyenne des gains logarithmiques.

| q, longueur/dimension | Mots changés | Gain du biais moyen | Hausse de la norme moyenne | Euclidien, ms/appel | CBD, ms/appel |
|---|---:|---:|---:|---:|---:|
| 3329, 114/16 | 73/256 | +0,666751 % | +0,009416 % | 2,460833 | 3,330288 |
| 3329, 111/16 | 56/256 | +0,185322 % | +0,007213 % | 2,430327 | 3,284294 |
| 7681, 152/22 | 63/256 | +0,344457 % | +0,006506 % | 7,172205 | 9,071882 |
| 7681, 140/21 | 67/256 | +0,427541 % | +0,007432 % | 6,807785 | 8,499721 |

Au point 140/21, 75 symboles de blocs changent sur 5376. La norme moyenne
passe de 6918,487516 à 6919,001702. La moyenne du gain en log2 du biais par
cible est 0,006075765 ; le log2 du rapport des biais moyens est 0,006154971.
Le plus grand gain observé sur une cible est 0,168601050 en log2, et le
minimum est zéro. La norme au carré ne baisse pour aucune cible, conformément
à la minimalité du contrôle euclidien.

Les biais restent inégalement répartis : leur taille effective pondérée
`(Σφ)²/Σφ²` passe de 39,9789 à 40,0509 sur 256 au point 140/21. La plus
grande contribution représente encore 8,46 % de la somme. Une amélioration
mesurée sur ces cibles fixes ne certifie pas sa taille dans la population.

## Contrôles et résultats négatifs

Sur les six petits modèles exhaustifs de run-010, soit **6302 cibles**,
les deux critères sélectionnent les mêmes mots. Le témoin de test séparé
q=17, longueur 4, dimension 1, cible `(0,0,5,15)` montre qu'ils peuvent
sélectionner des mots distincts avec une norme supérieure et un meilleur
biais pour le critère CBD. L'absence de différence dans les six petits
modèles est conservée, sans en déduire une équivalence générale des critères.

Les contrôles répétés changent leurs 256 mots dans chaque panneau, avec
des rapports de biais moyen plus grands, de 2,10 à 6,03 environ. Leurs biais
absolus restent cependant très inférieurs à ceux des codes pondérés, et
leurs tailles effectives pondérées CBD ne vont que d'environ 1 à 2,98.
Ces moyennes très concentrées ne justifient pas une préférence pour ces
codes ni une extrapolation des rapports à la population.

Deux vérifications indépendantes complètent l'expérience :

- mpmath.iv à **160 décimales** retrouve les encadrements des **5513 poids**
  dans leurs cellules entières, sans importer Sage ou l'arithmétique du projet ;
- un programme Python indépendant reconstruit les livres de codes complets
  des petits modèles, puis énumère **352 320 symboles par critère** sur
  **64 blocs aux modules réels**. Symboles, coûts et certificats concordent.

L'oracle indépendant ne réénumère pas les 38 400 blocs réels : le calcul
principal produit leurs certificats et son code est figé par empreintes.
Le vérificateur standard reconstruit toutes les cibles et sorties choisies,
rejoue les petits modèles, vérifie les résumés, provenances et rattachements
aux deux contrôles indépendants. Il n'exige ni Sage ni NumPy.

## Temps de calcul et décision

Les temps sont les médianes de sept séries de huit appels, avec ordre des
deux critères alterné, sur les mêmes cibles et à tables chaudes. Ils incluent
validation, recherche et départage ; le chemin CBD inclut aussi le calcul
de ses certificats. La génération des cibles, la construction des tables et
les écritures sont exclues. Runtime : WSL2, Python 3.12.15, NumPy 2.5.4,
versions figées par les manifestes locaux. Il s'agit de mesures du prototype,
sans garantie statistique sur les temps ou conversion en unités rop.

Au point 140/21, le chemin CBD mesuré prend environ **24,85 % de temps en
plus** pour **0,43 % de biais moyen en plus** sur cet échantillon. Le budget
de candidats est égal, mais le travail par candidat et la certification
diffèrent. Cette mesure ne prouve pas qu'un critère soit préférable dans
l'attaque complète ; elle donne peu de raison de prioriser son optimisation
dans le prototype actuel.

**Décision locale :** conserver ce critère comme témoin presque optimal
avec garantie uniforme, ainsi que le contrôle euclidien. Le résultat confirme
la dépendance directionnelle du biais, mais le gain observé sur les codes
pondérés est limité. La priorité suivante est de relier les résidus à des
vecteurs duaux et au score complet sur un modèle réduit vérifiable, avec
les dépendances et les coûts correspondants. Un biais supérieur peut aider
l'attaque ; ce n'est pas une amélioration de la sécurité du KEM.

Aucun coût d'attaque antérieur, seuil C05, paramètre du KEM ou niveau global
de sécurité n'est modifié. Aucun profil n'est sélectionné et J2 reste ouvert.

## Fichiers et reproduction

`research/cbd_decoder.py` contient le décodeur scalaire, les encadrements et
les résumés ; `cbd_decoder_numpy.py` accélère l'énumération complète.
`run_cbd_decoder.py --output <nouveau-dossier>` exige le runtime Sage local
pour la construction des tables, puis NumPy pour les modules réels. Le
runner refuse d'écraser un dossier. Les six sorties principales et vingt
entrées, dont le protocole préenregistré et les manifestes du runtime, sont
liées par SHA-256. Les vérifications par intervalles et par oracle ont leurs
provenances propres.

`verify_cbd_decoder_results.py` et `verify_cbd_decoder_independent.py` sont
intégrés à `scripts/dev.ps1 check` et `scripts/dev.sh check`. Le contrôle
par intervalles déjà exécuté est conservé dans `interval-verification.json` ;
`verify_cbd_decoder_intervals.py --run <nouvelle-étude>` permet sa reproduction
dans un nouveau dossier, sans écrasement.

## Complément exécuté : score complet réduit

[run-013](SCORE_DUAL_COMPLET_REDUIT.md) relie maintenant les codes et critères
à des relations duales effectives et aux scores de toutes les hypothèses,
dans un modèle LWE fini. Il donne un exemple où CBD augmente le bon score
moyen mais baisse le succès au classement. Ce résultat renforce la décision
de ne pas sélectionner un critère sur la seule moyenne du biais. La
généralisation aux vecteurs et paramètres réels reste ouverte.
