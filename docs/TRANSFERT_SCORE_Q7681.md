# H09 — Transfert du score et ressources à q=7681

Étude du 25 octobre 2026, [protocole](PROTOCOLE_H09.md) préenregistré au
commit `a0b9fab`, [données run-016](../results/j2/run-016/study.json).
Les quatre minima run-009 et les 2048 résidus run-011 sont conservés.
Cette étude quantifie des conditions de transfert ; elle ne calcule pas
un nouvel optimum d'attaque et ne clôt pas J2.

## Facteur idéal et codes concrets

Le modèle historique pose un seuil relatif mu égal au produit de deux
intégrales : contribution du réseau et contribution du code idéal GV
avec approximation gaussienne du biais.
On recalcule la seconde avec les dimensions exactes du point, puis on
retrouve la première par soustraction des logarithmes. Ce facteur réseau
reste celui du modèle historique, sans nouvelle validation géométrique.

| q=7681, η=3 | LWE | Heuristique MLWE des auteurs |
|---|---:|---:|
| nfft / kfft | 152 / 22 | 140 / 21 |
| log2 du facteur code idéal | −29,646504 | −24,925654 |
| log2 de la moyenne CBD du code pondéré, 256 résidus | −38,864168 | −33,380947 |
| Rapport idéal / moyenne observée | 595,38 | 350,99 |
| Nombre effectif de poids dans les 256 résidus | 39,60 | 39,98 |

Les résidus viennent des décodeurs euclidiens de run-010 ; cette comparaison
ne réexécute pas le critère CBD de H05. L'écart combine la géométrie du code
concret et la formule CBD exacte : il ne mesure pas le seul effet du choix
de critère. Il s'agit d'un écart de biais, pas d'un facteur de coût ou d'une
perte de sécurité. La moyenne observée ne certifie pas une moyenne de population.
La substitution du seul facteur code, à beta et facteur réseau inchangés,
donne un seuil diagnostique plus petit. Avec les autres hypothèses normales
conservées, le logarithme du budget de faux candidats devient positif :
357,164 et 356,656. La borne plafonnée à 1 n'informe donc plus sur le succès.
Cela montre que ce remplacement naïf ne justifie pas le point historique ;
cela ne démontre pas l'échec d'une attaque réoptimisée avec un autre code.

Le code répété est également conservé, avec une concentration encore plus
forte des poids : effectifs 1,00000000003 et 1,2463. Ne pas interpréter les
grands écarts de ses moyennes comme des estimations fiables de population.
Le coût de décodage et la loi jointe avec les vecteurs du réseau doivent
aussi accompagner toute substitution future.

## Sensibilité de la queue normale

À N, mu et M=R*q^kfft fixés, le budget normal historique vaut
`M*Q(sqrt(2*N)*mu)`. Sous une variance multipliée par ν, on examine
`M*Q(sqrt(2*N/ν)*mu)`. L'hypothèse de normalité est conservée dans cette
sensibilité ; aucune de ces variances n'est mesurée à grande dimension.

| q=7681 | log2 budget, ν=1 | ν=1,01 | ν=1,1 | Hausse maximale au budget 0,05 |
|---|---:|---:|---:|---:|
| LWE | −9,371771 | −5,782781 | 23,584506 | 1,412782 % |
| MLWE des auteurs | −4,940002 | −1,399518 | 27,570903 | 0,173146 % |

La dernière colonne est calculée à paramètres fixes : un changement de
seuil, de code, de liste ou de beta déplacerait cette limite. Une hausse
de 1 % suffit déjà à faire dépasser 0,05 dans le second panneau, sous le
modèle normal lui-même.

Pour une liste fixe de N termes avec variance diagonale moyenne 1/2,
si cbar désigne la covariance moyenne sur les paires ordonnées distinctes,
`Var(score)=1/(2N)+(N−1)*cbar/N`. Une hausse relative au plus ε exige
`cbar <= ε/(2*(N−1))`. Au point MLWE, la limite normale ci-dessus correspond
à cbar d'environ 2^-258,159 ; au point LWE, 2^-257,205. Les variances
diagonales réelles peuvent elles-mêmes différer de 1/2. Ces nombres ne
sont donc pas des certificats sur la covariance réelle : ils fixent la
précision et l'échelle que le futur modèle doit justifier. Les covariances
de 32 résidus auxiliaires de run-011 ne remplissent pas ce contrat.

## Ce que donnent seulement les moments supposés

En gardant, pour chaque faux candidat, moyenne nulle et variance 1/(2N),
Cantelli donne `P(score >= mu) <= 1/(1+2*N*mu²)`. Une union sur M évaluations
ne demande pas leur indépendance. Elle donne ici la borne plafonnée 1
dans les quatre panneaux : ces moments seuls ne certifient pas 0,05.
Ils restent eux-mêmes des hypothèses pour les faux candidats LWE réels.

À mu fixé, la taille suffisante pour cette borne est
`N >= (M/0,05−1)/(2*mu²)`. Son logarithme vaut 603,620 en LWE et 601,087
en MLWE, contre les tailles historiques 250,060 et 247,985. Ce calcul
exprime la faiblesse du certificat de moments dans ce régime de queues
rares. Il ne fournit ni une taille nécessaire, ni un coût d'attaque, ni
une preuve que les listes historiques échouent. Une borne de queue plus
précise peut être beaucoup meilleure si ses hypothèses sont établies.

## Ressources sous des représentations explicites

| q=7681 | Dimension réseau | log2 N | Octets/vecteur, résidus empaquetés | log2 octets de liste |
|---|---:|---:|---:|---:|
| LWE | 2585 | 250,060 | 4201 | 262,097 |
| MLWE des auteurs | 2576 | 247,985 | 4186 | 260,016 |

La représentation empaquetée utilise 13 bits par coordonnée modulo q,
puis arrondit chaque vecteur à l'octet. Une représentation à 64 bits par
coordonnée donne respectivement 2^264,396 et 2^262,316 octets. Cela omet
les structures du crible, les indices, le code et les espaces de travail.
Ce sont des volumes sous ces représentations d'une liste matérialisée,
pas des bornes mémoire universelles : compression, génération à la
demande et compromis temps/mémoire demanderaient une analyse distincte.

Les budgets 2^40, 2^60 et 2^80 octets dans les données sont des sensibilités
illustratives. Aucun n'est adopté comme contrainte du projet. Refuser une
représentation à un budget donné ne permet pas de relever un niveau de
sécurité sans analyser d'autres compromis et attaques.

## Contrat pour une révision ultérieure

L'identité CBD `phi_eta(a)=produit cos(pi*a_i/q)^(2*eta)` reste valable au
module réel pour des coefficients fixes sous les hypothèses iid-CBD.
Les identités de covariance de run-013 s'y appliquent aussi. Leur usage
demande les coefficients complets a=(y,x,r), les mots/étiquettes c et les
décalages de fausses hypothèses, avec une loi de sélection explicitée.
Les seules normes et les seuls résidus r ne suffisent pas.

La suite doit donc fournir une liste duale effective à q=7681 de taille
réalisable, les identités de phase et sa sélection, puis calculer les
moments complets du vrai candidat et des faux candidats choisis. Les
coûts de génération/décodage et les ressources doivent être enregistrés.
Cette étude finie permettra de contrôler un modèle, sans prétendre
matérialiser 2^248 vecteurs. Une extrapolation requerra ensuite une loi
de liste et une justification de queue explicites, ainsi que le traitement
MLWE des rotations. Le témoin uniforme et la seule variance ne valident
pas les faux candidats conditionnés par une vraie instance LWE.

## Reproduction et vérification

`python research/run_score_transfer.py --output artifacts/generated/h09-nouveau`
refuse un dossier existant. Puis
`python research/verify_score_transfer_independent.py --run artifacts/generated/h09-nouveau`.
Le contrôle courant rejoue run-016 avec `python research/verify_score_transfer.py`
et son vérificateur indépendant sans argument ; ils sont intégrés à `check`.

La seconde voie utilise Decimal à 90 chiffres, une série alternée pour
l'intégrale du code au lieu de la série positive primaire, des encadrements
de Mills pour les grandes abscisses normales, une intégration en série
pour les autres, et une série cosinus pour les contributions CBD. Elle
retrouve 192 champs numériques et les 2048 résidus ; écart maximal
9,30×10^-12. Les identités analytiques et inégalités probabilistes sont
distinctes de leurs évaluations numériques : ces dernières ne sont pas
des certificats par arithmétique d'intervalles.

Aucun seuil de correction, profil ou coût d'attaque global n'est modifié.
