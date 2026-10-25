# Erreurs du décodeur et contribution CBD aux scores

Étude du 24 octobre 2026, conservée dans [run-011](../results/j2/run-011/study.json).
Elle prolonge les [décodeurs concrets](DECODEUR_CONCRET.md) sans modifier les
paramètres du KEM ni les coûts d'attaque de run-009. Les 2048 résidus sont
reconstruits depuis les cibles et symboles figés de run-010 ; le décodeur
n'est pas réexécuté pour choisir de nouvelles observations.

## Question et périmètre

La norme du résidu suffit-elle à décrire sa contribution au score lorsque
le secret suit une CBD discrète ? Peut-on remplacer la loi jointe de ses
coordonnées par le produit des marginales ? Que devient la variance d'une
somme lorsque plusieurs termes partagent le même secret ?

Le modèle étudié est volontairement partiel : pour un résidu fixé r,
`X_r(S) = cos(2π〈S,r〉/q)`, où les coordonnées de S sont des CBD(η) idéales,
indépendantes entre elles et indépendantes des résidus. Un même S est utilisé
dans toute une banque de scores. Aucun vecteur court dual, étape FFT,
score complet de bonne ou mauvaise hypothèse, seuil de décision ou probabilité
de succès d'attaque n'est calculé. Les dimensions 140/21 sont celles du code
auxiliaire de l'attaque ; elles ne désignent pas Decaps du KEM.

## Identités et borne du modèle

Une coordonnée CBD(η) est une somme de η différences de bits uniformes.
Sa fonction caractéristique donne exactement, pour tout résidu fixé :

`φ(r) = E_S[X_r(S)] = ∏_i cos(π r_i/q)^(2η)`.

Chaque coordonnée est réduite dans `[-⌊q/2⌋,⌊q/2⌋]`. Pour les modules impairs
utilisés, les cosinus de cette expression sont strictement positifs.
Le calcul conserve les logarithmes pour éviter les sous-flux numériques.

Sur `|x|<π/2`, `log cos x ≤ −x²/2` : pour x positif, la dérivée de
`log cos x + x²/2` vaut `x−tan x≤0`, et la fonction est paire. Donc :

`φ(r) ≤ exp(−η π² ||r||²/q²)`.

La formule gaussienne est ainsi une majoration ponctuelle de cette contribution
CBD auxiliaire, et pas seulement une approximation numérique. Cette borne
ne constitue pas une majoration de la probabilité de succès de l'attaque.
La norme seule ne fixe pas φ : les puissances supérieures des coordonnées
interviennent dans le logarithme du produit.

Pour deux résidus et le même secret, l'identité produit des cosinus donne :

`Cov_S(X_r,X_t) = [φ(r+t)+φ(r−t)]/2 − φ(r)φ(t)`.

La variance de la moyenne de M termes fixés est la somme de leurs covariances,
divisée par M². Les termes hors diagonale sont conservés avec signe et
logarithme de leur valeur absolue. Les supports disjoints donnent un zéro
algébrique ; un zéro dû à la précision flottante ne prouve pas à lui seul
une annulation exacte. Les résidus opposés donnent des scores identiques,
ce que contrôlent les tests.

## Données, dépendances et mesures

Les huit expériences reprennent chacune les 256 cibles publiques de run-010.
Les vecteurs complets, leurs normes, les biais et huit matrices de moments
coordonnés sont conservés. Les sommes et produits des coordonnées sont des
entiers exacts : le numérateur de covariance empirique est
`N Σ r_i r_j − (Σ r_i)(Σ r_j)`, sur le dénominateur N². Il s'agit de moments
de cet échantillon fini, pas de moments de population certifiés.

Les codes et leurs règles de départage se séparent par blocs. Pour une cible
uniforme dont les blocs sont indépendants, les résidus de blocs sont donc
indépendants. Les coordonnées d'un même bloc ne le sont généralement pas.
Le produit des moyennes empiriques par bloc reste une estimation : il n'est
pas identique à la moyenne du produit sur les 256 vecteurs.

Au point pondéré q=7681, η=3, longueur 140, dimension 21 :

| Quantité sur les mêmes 256 résidus | log2 de la quantité |
|---|---:|
| Moyenne des φ des vecteurs complets | −33,380946504 |
| Moyenne de la majoration gaussienne | −32,687033634 |
| Produit des moyennes empiriques par coordonnée | −31,755681569 |
| Produit des moyennes empiriques par bloc | −33,167966142 |

La moyenne gaussienne vaut environ 1,617665 fois la moyenne CBD. Le produit
des marginales coordonnées vaut environ 3,084988 fois la moyenne jointe.
Ce dernier rapport mesure ici le remplacement de la loi empirique jointe
par une loi artificielle de coordonnées indépendantes ; les fluctuations
d'échantillonnage y contribuent. Ce n'est pas un facteur de population prouvé,
ni un gain ou une perte en bits de sécurité.

La taille effective pondérée `(Σφ)²/Σφ²` vaut environ 39,98 sur 256 et la plus
grande observation représente 8,49 % de la somme. Les contrôles répétés sont
beaucoup plus concentrés : leurs tailles effectives vont d'environ 1 à 2,60.
Leurs grandes différences entre estimations ne doivent donc pas être
interprétées comme une moyenne de population fiable.

Les dix-huit contrôles à norme fixée séparent explicitement direction et
distance. Pour q=7681, η=3 et une norme exactement égale à 3000 :

| Coordonnées non nulles, complétées par des zéros | log2 φ |
|---|---:|
| (3000) | −9,414042490 |
| (1800,2400) | −7,680643419 |
| 25 coordonnées égales à 600 | −6,582797768 |
| Majoration gaussienne, commune aux trois | −6,516321726 |

Chaque norme au carré vaut exactement 9 000 000. La différence de biais
provient de l'identité CBD, évaluée numériquement et contre-vérifiée.

## Covariances et contrôles exhaustifs

Huit banques prennent les 32 premiers résidus de chaque expérience, avec
528 paires diagonale comprise par banque. Pour la banque pondérée 140/21,
la somme doublée des covariances hors diagonale a un log2 d'environ −45,9694,
face à une somme diagonale proche de 16. La variance de la moyenne reste
proche de 1/64, comme dans l'approximation indépendante sur cette banque.
Ce résultat limité ne valide pas l'indépendance d'une liste d'environ 2^248
termes dans run-009 : les résidus réels du crible, leurs dépendances et les
queues pertinentes ne sont pas présents ici.

Six petits modèles complets utilisent les deux familles de codes et les
paramètres `(q,n,k)=(5,3,1),(5,4,2),(7,4,2)`, avec un secret CBD(1).
Les 6302 cibles uniformes sont toutes parcourues. Les histogrammes entiers
de phase `〈S,R〉 mod q` permettent de comparer exactement les lois :

- la factorisation par coordonnées échoue dans les six cas ;
- la factorisation par blocs est exacte dans les six cas ;
- les moments du score avec secret partagé sont retrouvés indépendamment.

Les banques exhaustives contiennent plusieurs fois les mêmes résidus, issus
de cibles différentes. Leurs fortes corrélations illustrent ce multiensemble
fini ; elles ne représentent pas une liste réelle de vecteurs duaux.

## Reproduction et vérification

`research/decoder_score.py` contient les identités et les calculs.
`run_decoder_score.py --output <nouveau-dossier>` refuse d'écraser une étude.
Les six sorties principales et treize entrées sont liées par SHA-256.
Les deux contre-vérifications ont leur propre provenance.

`verify_decoder_score_independent.py` n'importe pas l'arithmétique du projet.
Il reconstruit les livres de codes, cibles et lois entières des six petits
modèles, et énumère littéralement les bits CBD(1). Le contrôle numérique
`verify_decoder_score_numeric.py --run <nouvelle-étude>` utilise mpmath à
160 décimales : 64 biais, 32 covariances et 18 contrôles de norme, soit
114 comparaisons. Elles passent toutes ; l'écart logarithmique maximal
observé est environ 3,41×10^-13.

`verify_decoder_score_results.py` reconstruit les 2048 résidus, huit matrices
de moments, huit banques et contrôles de norme, puis vérifie les provenances
et le rattachement des contrôles indépendants. La tâche `check` rejoue ce
contrôle et l'énumération indépendante sans dépendre de Sage ou NumPy.

## Rapport aux travaux récents et suite

[Ducas et Pulles, Accurate Score Prediction for Dual-Sieve Attacks](https://link.springer.com/article/10.1007/s00145-025-09560-7)
étudient les limites d'heuristiques de score du dual-sieve.
La notice de [Li et Zheng, ePrint 2026/1048](https://eprint.iacr.org/2026/1048),
révisée le 14 octobre 2026, décrit une analyse des scores fondée sur les
covariances. Les métadonnées et l'étendue de consultation sont conservées
dans [sources.json](../references/decoder-score-2026/sources.json).
Notre calcul de contribution CBD n'est pas une reproduction de leurs modèles
complets ; il établit ses propres identités dans le périmètre explicite ci-dessus.

La comparaison d'un critère de choix fondé sur φ avec la distance euclidienne
est maintenant exécutée dans [run-012](DECODEUR_CRITERE_CBD.md), sur les mêmes
codes et cibles, à budget de candidats égal. Son gain observé est limité
sur les codes pondérés. Un meilleur biais auxiliaire pourrait aider l'attaque :
ce ne serait pas automatiquement une amélioration de sécurité du KEM. Il faut
relier le décodeur à une distribution de vecteurs duaux et au score complet,
avec ses queues et son coût. Aucun coût global n'est mis à jour, aucun profil
n'est choisi et J2 demeure ouvert.
