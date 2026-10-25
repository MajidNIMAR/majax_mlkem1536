# H13 — Bornes à 32 vecteurs et première brique du moteur

25 octobre 2026. [Protocole](PROTOCOLE_H13.md) préenregistré au commit
`5fc45d1`, [instantané run-020](../results/j2/run-020/summary.json).
L'étude conclut l'extension des moments sur petites listes ; elle
s'accompagne d'un livrable d'arithmétique Rust pour le futur moteur.

## Résultat utile et portée

Les quatre matrices, deux codes 140/21 et trois ordres publics de H11
sont repris sans ajustement : 24 banques à N=32, q=7681 et η=3.
Pour chacune, la kurtosis du score CBD complet est encadrée autour de
`3−3/(2N)=2,953125` avec une borne rationnelle exacte.

| Sélection publique | Écart absolu majoré, code pondéré : maximum des quatre matrices | Écart absolu majoré, code répété |
|---|---:|---:|
| Norme | ≈1,211×10^-13 | ≈1,313×10^-35 |
| Hachage fixé | ≈2,982×10^-13 | ≈1,313×10^-35 |
| Glouton du moment uniforme | ≈6,758×10^-14 | ≈1,313×10^-35 |

Les décimales du tableau présentent les bornes, pas les écarts réels.
Les fractions décisives sont conservées dans chaque certificat.
La comparaison rationnelle établit **un écart strictement inférieur à
3×10^-13 pour les 24 banques**. Les bornes sont valables pour tout
décalage d dans (Z/qZ)^21, grâce à une majoration indépendante de la
phase. Aucun nouvel échantillon n'est généré.

Ce résultat distingue plus nettement le score CBD du témoin uniforme,
dont les kurtosis moyennes à N=32 étaient 12,1641 / 5,1738 / 4,3110
pour norme / hachage / glouton. Une borne plus petite n'établit pas
qu'une sélection a un écart réel plus petit ou un meilleur succès
d'attaque. Les biais vrais et les ressources restent des critères séparés.

L'encadrement ne donne ni indépendance des termes, ni queue normale,
ni taux de récupération parmi q^21 hypothèses. Il porte sur des moments
finis dans un réseau de dimension 5, sans transfert au réseau estimé
de dimension 2576 ou aux rotations MLWE. J2 reste ouvert.

## Majoration sans arrondi transcendant

Pour tout coefficient centré, |r|<q/2 et
`log(cos(pi*r/q))≤−(pi*r/q)^2/2`. Pour η=3 :

`phi(v)=produit cos(pi*center(v_j)/q)^6`

`phi(v)≤exp(−3*pi²*||center(v)||²/q²)≤2^(−42*||center(v)||²/q²)`.

L'inégalité logarithmique suit de tan(t)≥t pour t≥0, puis intégration.
Les constantes sont justifiées rationnellement : une minoration de
Machin par série alternée prouve pi>157/50 ; la somme des quatre premiers
termes de exp(7/10) dépasse 2, donc ln(2)<7/10. Il en résulte
`3*(157/50)^2>42*(7/10)`. Les fractions de ces témoins sont conservées.

Chaque puissance p=1..4 est développée en fréquences signées. Les
appariements équilibrés donnent exactement les moments bruts de
référence `0,1/(2N),0,3/(4N²)−3/(8N³)`. Chaque autre terme est majoré
en valeur absolue par `2^-K`, où
`K=min(128,floor(42*norme²/q²))`. Les phases vérifient |cos|≤1.
La somme des multiplicités entières fois 2^-K, divisée par (2N)^p,
donne B_p, borne de la correction brute. Les histogrammes entiers
et leurs sommes rationnelles sont enregistrés.

Les coordonnées peuvent s'arrêter dès que la norme partielle atteint
le seuil 128 : toutes les coordonnées restantes ont une contribution
positive à la norme. Le terme est conservé avec la majoration 2^-128.
La masse plafonnée est séparée ; sa contribution normalisée est au
plus 2^-128≈2,939×10^-39 par moment. C'est une marge de majoration,
pas une erreur flottante non maîtrisée. Aucun terme n'est supprimé
sans être couvert par la borne. Aucune annulation complète supplémentaire
n'apparaît hors appariements équilibrés dans les 24 banques.

## Propagation aux moments centrés

Écrire μ=E[S], v0=1/(2N), f0=3/(4N²)−3/(8N³), κ0=f0/v0².
Si |correction_p|≤B_p, alors

`D_v=B_2+B_1²`,

`D_f=B_4+4*B_1*B_3+6*B_1²*(v0+B_2)+3*B_1^4`.

On obtient |Var(S)−v0|≤D_v et |E[(S−μ)^4]−f0|≤D_f.
Lorsque D_v<v0, ce qui est vérifié exactement pour les 24 banques :

`|kurtosis−κ0|≤[D_f+κ0*(2*v0*D_v+D_v²)]/(v0−D_v)²`.

Toutes les opérations de ce certificat utilisent des entiers et des
fractions, sans évaluation de pi, logarithme, cosinus ou exponentielle
flottante. Les conversions décimales du résumé n'interviennent dans
aucune décision de certification.

## Vérifications, provenance et ressources

La voie primaire énumère les multisets des 2N fréquences, en lots de
2048 et coordonnées par groupes de 32. À N=32 : 19 545 216 multisets,
409 044 480 termes ordonnés pondérés, 13 757 076 arrêts anticipés et
1 924 428 844 coordonnées évaluées. Somme des temps instrumentés des
24 certificats : environ 65,09 s sur cet hôte. Le chronométrage ne
couvre pas toute la chaîne ni les calibrations et dépend de l'hôte.
Les indexations temporaires peuvent atteindre 2048×4×32 coefficients ;
ce n'est pas une mesure du RSS ni du pic mémoire global.

La seconde implémentation, sans import de l'arithmétique du projet,
énumère les multisets des N indices de cosinus, puis les 2^p signes.
Elle calcule toutes les 145 coordonnées et plafonne ensuite les normes.
Elle retrouve exactement les histogrammes, masses et fractions, ainsi
que la propagation centrée avec une autre écriture algébrique.
Les 23 132 160 évaluations indice/signes couvrent N=32 et les calibrations
H12 ; elles ne représentent pas des échantillons ou des attaques.

Les 64 banques H12 sont recalculées avec les mêmes majorations ; les
1024 corrections numériques précédentes entrent dans les bornes. Cette
calibration ne rend pas leurs valeurs numériques exactes. Les cinq
nouveaux tests utilisent aussi un développement ordonné littéral, une
relation complète non triviale, une loi CBD(3) pondérée, l'arrêt anticipé
contre calcul complet et des contrôles rationnels du centrage.

Pour reproduire dans un nouveau dossier :

```powershell
.tools/research-venv/Scripts/python.exe research/run_bounded_moments.py --output artifacts/generated/h13-nouveau
.tools/research-venv/Scripts/python.exe research/verify_bounded_moments_independent.py --run artifacts/generated/h13-nouveau
```

NumPy 2.3.5 local, sans dépendance nouvelle. Les vérificateurs sans
argument ciblent run-020 ; les dix-neuf instantanés précédents restent
figés. Les durées ne sont pas comparées à l'identique lors des rejeux.

## Livrable moteur et décision

`crates/kem1536/src/reference_ring.rs` fournit une arithmétique canonique
de référence dans Z_q[X]/(X^256+1) : addition, soustraction et produit
par convolution directe, modulo explicite au niveau du type. Les
accumulateurs signés sont bornés par moins de 2^40 pour tout modulo u16
admis. Les entrées non canoniques et modulos invalides sont rejetés.
Les valeurs des polynômes n'ont pas d'implémentation Debug.

Trois tests Rust contrôlent les modules 3329 et 7681, un grand modulo
65535 pour les bornes, une convolution ordinaire indépendante de longueur
511 suivie de la réduction, les lois de l'anneau et X^255*X=−1.
Cette brique constitue un oracle pour les futures versions optimisées.
Elle n'implémente pas le KEM ; ses propriétés de temps constant et
d'effacement des secrets ne sont pas établies.

**Décision : arrêter ici l'extension automatique des petites listes.**
La prochaine étape principale est le bilan C01–C06 pour le passage J2
vers le prototype J3, avec obstacles classés et recommandation motivée.
Les primitives indépendantes des paramètres finaux peuvent avancer.
La [feuille de route du moteur](FEUILLE_DE_ROUTE_MOTEUR.md) fixe cet ordre.
Aucun profil n'est sélectionné, aucun coût d'attaque révisé ou niveau
global de sécurité revendiqué, aucun seuil C05 modifié.
