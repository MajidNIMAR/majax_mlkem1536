# H10 — Listes effectives et scores complets à q=7681

Étude du 25 octobre 2026, [protocole](PROTOCOLE_H10.md) préenregistré au
commit `6827a5a`, [résultats run-017](../results/j2/run-017/summary.json).
Cette étape réalise le contrat fini H09 au module réel : vecteurs effectifs,
codes, phases, moments vrais/faux et ressources. Elle ne réalise pas
l'attaque en dimension 2576, ne sélectionne aucun profil et laisse J2 ouvert.

## Construction et sélection publiques

Quatre matrices publiques A=[A_l|A_f] de forme 3×142 sont fixées par les
étiquettes SHAKE préenregistrées. Trois observations LWE, deux coordonnées
secrètes dans la partie réseau, 140 dans la partie code. Les 145 variables
erreur/secret sont CBD(3). Il s'agit d'instances LWE de calibration ; le
rang 6, ses rotations MLWE et sa transformation CCA ne sont pas implémentés.

Le réseau entier de base lignes `[I_3|A_l]`, `[0|q I_2]` a dimension 5 et
déterminant q². Le LLL rationnel δ=3/4 fournit quatre certificats : trace,
transformation unimodulaire, déterminant et conditions de réduction.
La boîte [-2,2]^5 donne 1562 représentants centrés non nuls à ± près par
matrice. Après tri (norme²,y,x), les préfixes 32, 64, 128 sont conservés.
La boîte ne certifie pas les plus courts représentants du quotient q^3.
Elle est la règle de sélection de cette expérience.

Pour chaque vecteur, on calcule `t=A_fᵀy`, puis on décode les codes répété
et pondéré existants, chacun de longueur 140 et dimension 21, par distance
euclidienne exacte. Les données conservent y, x, t, c, r, avec
`x=A_lᵀy mod q` et `r=t−Gc mod q`. Les étiquettes c ont rang 21 modulo q
dans chacune des huit banques de 128 vecteurs. Aucun des 26 décalages
choisis n'est un alias du vrai candidat sur ces banques. Ni les secrets,
ni les scores n'interviennent dans cette sélection publique.

## Phases et moments complets

Pour `b=A*s+e mod q` et `u=Gᵀs_f mod q`, l'identité
`yᵀb−cᵀu = yᵀe+xᵀs_l+rᵀs_f mod q` est contrôlée pour tous les vecteurs
et échantillons : **4 194 304 égalités**. Les empreintes des tableaux
entiers permettent de reconstruire et vérifier les données sans stocker
tous les scores flottants. Les préfixes partagent ces contrôles ; on ne
les recompte pas comme expériences indépendantes.

Le score au décalage d vaut la moyenne de
`cos(2*pi*(aᵀZ−cᵀd)/q)`, avec a=(y,x,r) et Z=(e,s_l,s_f). Sous Z iid-CBD(3),
`phi(a)=produit cos(pi*center(a_i)/q)^6`. La moyenne et les covariances
proviennent des caractères aux coefficients a, a+b et a−b, avec les
phases cᵀd. Ces identités concernent la loi CBD complète, pas uniquement
les configurations échantillonnées. Leurs évaluations restent numériques,
sans certificat par arithmétique d'intervalles.

Plus précisément, pour `theta_i=2*pi*c_iᵀd/q`, on utilise
`mu_i=phi(a_i)*cos(theta_i)` et
`K_ij=[phi(a_i−a_j)*cos(theta_i−theta_j)+phi(a_i+a_j)*cos(theta_i+theta_j)]/2−mu_i*mu_j`.
La moyenne du score est `somme(mu_i)/N`, sa variance `somme(K_ij)/N²`.
Aucune annulation des covariances hors diagonale n'est imposée au calcul.

On obtient **648 enregistrements de moments** : 4 matrices × 2 codes ×
3 tailles × 27 décalages. Les 26 faux décalages sont les 21 vecteurs
unité, tout-un, alterné 1/−1 et trois vecteurs publics fixés. Ils ne
couvrent pas les q^21−1 faux candidats. La moyenne de certains faux
scores est non nulle ; le maximum absolu calculé est environ 2,32×10^-10.

Pour les 648 cas, l'écart numérique maximal de la variance à 1/(2N),
rapporté à cette référence, est environ 1,49×10^-14. Cela contrôle ces
listes finies et leurs hypothèses CBD, sans valider une extrapolation à
2^248 vecteurs. Certaines contributions de caractères extrêmement petites
s'arrondissent à zéro en double précision dans les noyaux du code répété
(17 à 25 entrées selon la banque). Les logarithmes employés pour les
biais et les contrôles sélectionnés sont conservés ; ces zéros numériques
ne constituent pas des identités mathématiques.

À N=128, les log2 des biais du vrai score pondéré sont :

| Matrice | log2 du biais complet |
|---|---:|
| 0 | −31,814237 |
| 1 | −32,980790 |
| 2 | −33,361673 |
| 3 | −32,526082 |

Les quelques milliers d'échantillons disponibles ne permettent pas de
résoudre expérimentalement des moyennes aussi petites face à un écart
type proche de 0,0625. La proximité des variances empiriques ne valide
donc pas ces biais ni des queues à probabilité cryptographique.

## Échantillonnage LWE et témoin uniforme séparé

Chaque matrice a 4096 configurations synthétiques CBD(3), reconstruites
par 870 bits bas d'un flux SHAKE par état. Au total : **16 384 états**,
pas une énumération des 2^870 configurations possibles. Les mêmes états
sont appariés entre les deux codes et les trois préfixes. Toutes les
comparaisons numériques gardent une bande d'ambiguïté de 10^-12 ; aucun
événement ambigu n'est rencontré dans cette exécution. Ce constat n'est
pas un certificat de rang par intervalles.

Le témoin uniforme prend séparément 4096 b dans Z_q^3 par matrice, avec
candidat fixé à zéro. Les y distincts à ± près donnent exactement, par
orthogonalité des caractères uniformes, moyenne nulle et variance 1/(2N).
Sa loi diffère de celle d'un faux candidat décalé du vrai u dans une
instance LWE. À u=0, ce témoin ne dépend pas du code : les résultats
identiques des deux familles ne sont pas des répétitions indépendantes.

| Taille N | Queue uniforme observée au seuil 3/√(2N) | Nombre / 16 384 | Normale de même variance |
|---|---:|---:|---:|
| 32 | 2,410889 % | 395 | 0,134990 % |
| 64 | 2,191162 % | 359 | 0,134990 % |
| 128 | 1,806641 % | 296 | 0,134990 % |

À N=128, le rapport observé est environ 13,38. Les quatre comptes par
matrice sont 77, 70, 76, 73 sur 4096. Ce sont des fréquences finies, pas
une probabilité exacte sur les q^3 observations uniformes.

Pour le vrai score LWE pondéré à N=128, on observe au même seuil 22 cas
sur 16 384, soit 0,134277 %. Pour les faux décalages pondérés pris
individuellement, les comptes par banque vont de 1 à 9 cas sur 4096.
Cela ne démontre pas une loi normale : des comptes aussi petits ont une
incertitude importante, et les candidats et préfixes partagent les mêmes
états. Les intervalles de Wilson enregistrés sont approximatifs et
conditionnels au modèle iid du générateur synthétique. On ne transfère
pas le facteur uniforme de 13,38 aux faux candidats LWE.

Le vrai candidat pondéré à N=128 dépasse les 26 faux candidats choisis
dans 630 états sur 16 384. C'est un classement sur 27 candidats ; il ne
mesure pas un succès de récupération parmi q^21 candidats et ne constitue
pas une attaque utile démontrée. Les autres tailles et le contrôle répété
sont conservés, même lorsqu'ils donnent des résultats différents.

## Ressources et vérification

Les étapes instrumentées du calcul primaire totalisent environ 8,81 s
sur ce poste : quatre réductions/énumérations, huit décodages de listes,
noyaux/moments et observations, avec leurs contrôles internes. Ces temps
n'incluent pas la seconde implémentation, les contrôles séparés, la
génération des états CBD, les écritures ni tout l'environnement.
Ils ne sont pas convertis en rop et ne sont pas extrapolés au grand réseau.
Les décodages pondérés des 128 cibles prennent environ 1,06 à 1,14 s
par matrice dans cette exécution, construction éventuelle des tables comprise.

Le plus grand tableau explicitement recensé fait 4 751 360 octets ; la
somme des tableaux recensés par banque est 18 388 992 octets. Il s'agit
des états, observations, symboles, phases, coefficients et étiquettes.
Les temporaires, tables du décodeur, objets Python et noyaux ne sont pas
tous inclus. Ces mesures ne sont ni le RSS système ni un pic total mémoire.
Les fichiers de [ressources](../results/j2/run-017/resources.json)
conservent les durées et le détail des volumes.

La seconde implémentation n'importe pas l'arithmétique du projet. Elle
vérifie les certificats LLL et la boîte avec une autre construction,
énumère tous les symboles des blocs avec des distances modulaires signées,
reconstruit les bits CBD par extraction individuelle, puis les deux
formes des phases, les scores et tous les événements. Elle contrôle
**1 101 148 160 termes de distance**, 648 moments et les empreintes des
4 194 304 phases. Une table de caractères en Decimal à 80 chiffres et
des sommes scalaires indépendantes contrôlent les noyaux ; 64 caractères
prédéfinis sont comparés à haute précision. Écart numérique maximal
observé : environ 8,99×10^-12. Les statistiques empiriques restent des
observations, même lorsque les deux programmes les retrouvent exactement.

Reproduction, runtime NumPy local 2.3.5 déjà préparé :

```powershell
.tools/research-venv/Scripts/python.exe research/run_real_dual.py --output artifacts/generated/h10-nouveau
.tools/research-venv/Scripts/python.exe research/verify_real_dual_independent.py --run artifacts/generated/h10-nouveau
```

Le lanceur refuse un dossier existant. Les deux vérificateurs sans argument
rejouent run-017 et font partie de `scripts/dev.ps1 check`.

## Décision et suite

La chaîne complète sur une liste effective au module réel est maintenant
contrôlée. L'expérience montre aussi pourquoi il faut distinguer moments,
queues du témoin uniforme et faux candidats LWE conditionnés. La prochaine
étude doit quantifier les dépendances d'ordre supérieur et leur lien à la
génération des listes, puis justifier une extrapolation des queues avant
tout transfert de coût. Augmenter seulement N ou appliquer un facteur de
queue empirique ne résout pas ce problème.

Restent le grand réseau, les rotations MLWE, les ressources des compromis
temps/mémoire, les autres attaques et la transformation CCA. Aucun coût
global, profil ou seuil de correction C05 n'est modifié ; J2 reste ouvert.
