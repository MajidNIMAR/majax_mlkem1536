# H11 — Relations additives et sélection publique des listes

Étude du 25 octobre 2026, [protocole](PROTOCOLE_H11.md) préenregistré au
commit `cfc924c`, [résultats run-018](../results/j2/run-018/summary.json).
Les dix-sept instantanés précédents sont préservés. Le budget comparé est
le même ensemble de candidats ; les temps de sélection sont différents.
Aucun coût d'attaque global, profil ou seuil C05 n'est modifié ; J2 reste ouvert.

## Du quatrième moment aux relations entre fréquences

Pour le témoin b uniforme de run-017 à candidat zéro, écrire
`S(b)=somme_{v dans B} exp(2*pi*i*vᵀb/q)/(2N)`, où `B={±y_i}`.
Les 2N fréquences sont distinctes et non nulles. Si P(z) compte les
paires ordonnées (u,v) de B avec u+v=z modulo q, l'orthogonalité donne :

| Moment | Expression exacte |
|---|---|
| E[S] | 0 |
| E[S²] | 1/(2N) |
| E[S³] | somme_{v dans B} P(v) / (2N)^3 |
| E[S⁴] | somme_z P(z)^2 / (2N)^4 |

Le dernier résultat utilise P(z)=P(−z). Les sorties conservent les
fractions entières, les comptes de triples/quadruples, le support du
spectre de paires et son empreinte. Aucun parcours des q^3 observations
n'est nécessaire pour ces moments exacts. Ce ne sont pas des lois de
probabilité complètes ou des queues exactes.

Pour des cosinus indépendants, le compte de quadruples serait
`12N²−6N`, soit une kurtosis `3−3/(2N)`. Le surplus mesuré quantifie des
relations supplémentaires. La kurtosis désigne ici `E[S⁴]/E[S²]²`.
Les triples donnent la dissymétrie, nulle
dans le modèle de cosinus indépendants ou pour la normale. Les relations
comptées expliquent exactement l'excès de ces moments ; les seuls
moments trois/quatre ne déterminent pas toute la distribution de queue.

## Trois sélections, mêmes candidats

Les quatre matrices q=7681/η=3, le réseau de dimension 5, les 128 candidats
et les deux codes 140/21 sont ceux de run-017. Aucun nouveau décodage
n'est introduit. Les règles publiques sont : ordre de norme `norm`,
ordre SHA256 fixé `hash`, et ordre glouton `energy` minimisant à chaque
ajout la somme des carrés du spectre de paires. Les égalités sont
départagées par l'indice initial, donc par norme puis y,x. Aucun état
CBD ou uniforme n'intervient dans la sélection.

Le glouton calcule 8256 coûts d'ajout par matrice pour l'ordre complet,
soit **33 024 coûts** en tout. Les coûts cumulés des préfixes 32 et 64
sont respectivement 3600 et 6176 évaluations par matrice. Il n'est pas
un optimum global sur tous les sous-ensembles.
Le contrôle `hash` utilise 128 hachages et un tri ; `norm` réutilise
l'ordre initial. La construction des trois ordres prend environ 3,05 à
3,15 s par matrice sur ce poste, dont le glouton est l'étape dominante.
Le même ensemble de candidats n'implique donc pas le même coût de sélection.

Les tailles 32/64/128 donnent 36 panneaux, mais **28 ensembles distincts**.
À N=128 les trois ordres désignent tous les candidats : les sorties
partagent ce même ensemble et ses mesures. Avec les deux codes, on
obtient 56 panneaux LWE distincts. Les comptes ne triplent pas les
expériences identiques à N=128.

## Résultats du témoin uniforme

Chaque matrice reçoit 8192 nouvelles observations synthétiques, soit
32 768 au total, avec des étiquettes SHAKE fixées. Les mêmes observations
sont appariées entre sélections et tailles. Les chiffres ci-dessous sont
les moyennes des moments sur quatre matrices ; les queues restent des
fréquences échantillonnées, pas des probabilités exactes.

| N | Sélection | Kurtosis exacte moyenne | Dissymétrie moyenne | Dépassements de 3 écarts types / 32 768 | Fréquence |
|---|---|---:|---:|---:|---:|
| 32 | norme | 12,164063 | 2,416992 | 806 | 2,459717 % |
| 32 | hachage | 5,173828 | 0,577148 | 260 | 0,793457 % |
| 32 | glouton | 4,311035 | 0,527344 | 209 | 0,637817 % |
| 64 | norme | 23,731201 | 3,523795 | 738 | 2,252197 % |
| 64 | hachage | 12,710815 | 1,630351 | 393 | 1,199341 % |
| 64 | glouton | 9,231079 | 1,118665 | 284 | 0,866699 % |
| 128 | même ensemble, trois ordres | 44,812134 | 4,935059 | 589 | 1,797485 % |

La normale de moyenne nulle et variance 1/(2N) aurait une kurtosis 3,
une dissymétrie 0 et une queue positive à trois écarts types de 0,134990 %.
À N=32, le glouton réduit la kurtosis et les dépassements dans chacune
des quatre matrices face aux deux contrôles. Cela n'établit ni une
normalité du nouveau score, ni la même réduction à d'autres dimensions.
Le contrôle par hachage améliore déjà fortement l'ordre de norme.

Les kurtosis empiriques moyennes à N=32 sont respectivement 12,3034,
5,4119 et 4,5273 ; à N=128, 44,1493. Elles sont des mesures finies avec
variabilité, distinctes des valeurs exactes. Les intervalles Wilson des
queues sont approximatifs et conditionnels au modèle iid du générateur.

Markov donne la borne exacte `P(S>=3*sigma) <= min(1,kurtosis/81)` pour
ce témoin. Même une kurtosis proche de 3 ne fournit par cette seule borne
qu'environ 3,7 %, loin de la queue normale 0,135 %. Les données ne
certifient donc pas une queue normale, encore moins une probabilité
cryptographique rare. La borne n'est pas transférée aux faux candidats LWE.

## Compromis sur le score CBD complet

Quatre nouveaux ensembles de 4096 états CBD(3), 145 variables par état,
donnent 16 384 états synthétiques. Les deux formes des phases sont
vérifiées pour les 128 candidats, une seule fois par matrice et code :
**4 194 304 identités distinctes**. Les mêmes phases sont réutilisées
selon les sélections, sans les recompter comme nouvelles identités.

Chaque panneau calcule quatre décalages de run-017 : vrai, une coordonnée
unité, tout-un et un pseudo-aléatoire fixé. Ce sont **trois faux candidats**,
pas les q^21−1. Les 224 moyennes/variances CBD proviennent des identités
complètes sur (y,x,r,c). Les troisième/quatrième moments LWE de cette
étude sont uniquement empiriques, sans quatrième moment CBD de population.

| N | Sélection | Moyenne des normes réseau au carré | Moyenne des log2 du biais vrai pondéré |
|---|---|---:|---:|
| 32 | norme | 2443,375000 | −32,699800 |
| 32 | hachage | 4489,507813 | −33,211823 |
| 32 | glouton | 4617,710938 | −33,897997 |
| 64 | norme | 3249,488281 | −32,781448 |
| 64 | hachage | 4416,878906 | −32,670207 |
| 64 | glouton | 5040,277344 | −33,274952 |

À N=32, la norme au carré moyenne augmente d'environ 89 % entre norme
et glouton, et la moyenne des log2 de biais baisse d'environ 1,198 bit.
À N=64, ces chiffres sont environ 55 % et 0,494 bit. Ce sont des moyennes
sur quatre cas, pas des pertes uniformes : la matrice 2 donne un meilleur
biais pondéré avec le glouton aux deux tailles ; les trois autres un
moins bon biais. Les normes des résidus et le contrôle répété sont
également conservés, sans désigner de méthode gagnante.

À N=32, les kurtosis empiriques du vrai score pondéré sont 2,9147,
2,9595 et 3,0239 selon les trois règles, avec 17, 17 et 18 dépassements
sur 16 384. Ces petits comptes ne démontrent pas une égalité de queues.
La grande variation uniforme ne se retrouve pas telle quelle sur ces
mesures LWE. Le faible biais positif ne peut pas être résolu par quelques
milliers d'échantillons. Tous les rangs des étiquettes de code calculés
valent 21 ; aucun événement de seuil ambigu à 10^-12 n'est rencontré,
sans certificat par intervalles.

## Vérification et ressources

Quatre nouveaux tests contrôlent un tore exhaustif de 49 observations,
le témoin indépendant, tous les choix gloutons d'un petit cas par
recalcul complet et le rejet des fréquences invalides.

La seconde implémentation n'importe pas l'arithmétique du projet. Elle
encode les sommes de paires et reconstruit leur histogramme vectorisé,
emploie un autre développement algébrique pour chaque coût glouton,
puis reconstruit le spectre complet après chaque ajout. Elle retrouve
les 33 024 coûts, choix, empreintes et 28 tables de moments exacts.
Une extraction bit par bit indépendante contrôle les nouveaux états
CBD, phases, scores et événements ; les 224 moments CBD numériques sont
retrouvés. Écart absolu maximal observé : 5,69×10^-14. Pour les petites
moyennes CBD, l'erreur rapportée à l'échelle du biais vrai positif reste
inférieure à 2,85×10^-14. Les moments CBD ne sont pas des certificats
par arithmétique d'intervalles.

Douze témoins uniformes et 96 moments CBD retrouvent run-017. Les étapes
primaires instrumentées prennent environ 16,16 s au total ; les tableaux
recensés comprennent notamment 8 388 608 octets pour un tableau de
phases uniformes. Ces mesures n'incluent pas tout le processus, les
temporaires, objets Python, contre-vérifications ou écritures. Elles
ne sont ni un RSS système ni un coût extrapolé d'attaque.

Reproduction dans le runtime local NumPy 2.3.5 :

```powershell
.tools/research-venv/Scripts/python.exe research/run_additive_score.py --output artifacts/generated/h11-nouveau
.tools/research-venv/Scripts/python.exe research/verify_additive_score_independent.py --run artifacts/generated/h11-nouveau
```

Le lanceur refuse un dossier existant. Les vérificateurs sans argument
rejouent run-018 et sont intégrés à `scripts/dev.ps1 check`.

## Décision

La sélection publique modifie fortement les moments supérieurs du
témoin uniforme, avec un surcoût et un compromis de biais qui empêchent
d'en déduire une amélioration automatique de l'attaque. Conserver les
trois témoins et les cas défavorables. La suite prioritaire est de
calculer le quatrième moment CBD complet sur des listes réduites,
avec les décalages des vrais/faux candidats, pour confronter directement
l'objectif de sélection au score LWE au-delà de sa covariance.

Restent l'extrapolation au réseau de dimension 2576, les queues rares,
les rotations MLWE et les autres volets de J2. Aucun profil ni nouveau
coût global n'est sélectionné.
