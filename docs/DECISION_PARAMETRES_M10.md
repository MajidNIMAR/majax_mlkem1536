# M10 — décision des paramètres R1 et comparaison à ML-KEM-1024

16 novembre 2026. Préenregistrement après le protocole M10 du commit
`1105e7f`. Aucun paramètre, domaine ou format Rust n'est modifié par ce
chantier. La décision finale ci-dessous attend les sorties prévues,
y compris toute erreur ou expiration de délai.

## Plan fixé avant acquisition

Exécuter exactement **40 travaux neufs**, soit deux profils, deux jeux
finis d'échantillons, deux modèles de coût et cinq familles. R1 conserve
n=256, k=6, q=7681, CBD(3) ; ML-KEM-1024 a n=256, k=4, q=3329, CBD(2).
Les jeux sont respectivement m=1536/1792 et m=1024/1280. Le second est un
hybride idéal distinct ; les chiffrés comprimés réels ne sont pas déclarés
fournir une ligne MLWE indépendante. Le passage au problème LWE aplati
est un proxy d'estimation, pas une identité d'instances indépendantes.

L'estimateur est épinglé au commit courant vérifié le 16 novembre :
`malb/lattice-estimator@7d59f866655362ea8eab803dbc833710c2bc362a`
(commit du 9 novembre 2026). Les 108 calculs M05 au commit f31b86fe restent
historiques ; ils ne sont pas comptés comme nouvelles évaluations. Chaque
nouvelle paire ne compare que le même jeu, modèle, famille et convention.

Familles : uSVP/GSA ; BDD/GSA ; hybride primal avec MITM explicite,
Babai désactivé et GSA ; dual simple avec cible de solveur 0,99 ; dual
hybride MATZOV et son μ interne0,5. Ces succès ne sont pas interchangeables.
Modèles : MATZOV classique et sensibilité de réduction BCSS23 quantique,
en gardant les autres travaux de l'estimateur. Le second n'est pas un
comptage de portes d'une attaque quantique complète.

Temps : 300 secondes murales par travail, quatre processus au plus,
affinités choisies parmi CPU 0..5. Tous les 40 travaux sont demandés une
fois, sans remplacement d'une famille ou d'une expiration. Les entrées,
sorties, exceptions, stdout/stderr, durées et versions sont conservés.
Un défaut du contrôleur pourra être corrigé seulement dans une reprise
explicitement reliée, avec les tentatives antérieures préservées.

L'optimisation de chaque famille reste sans plafond RAM, comme son API.
Le champ `mem`, lorsqu'il existe, garde son unité documentée en éléments
modulo q. Sa représentation dense en u16 fournit une sensibilité de
stockage déclarée pour des plafonds de 2^40, 2^60 et 2^80 octets ; elle
ne prouve pas le pic physique total. `N` reste un nombre de vecteurs et
n'est pas rebaptisé RAM. Un optimum hors plafond n'est pas une preuve
d'absence d'autre attaque sous plafond. Aucun coût contraint ne sera
inventé en filtrant simplement l'optimum non contraint.

## Sorties falsifiables et décision

Le bilan annoncera les 20 paires attendues, les sorties manquantes, les
écarts et la plage d'extrapolation de MATZOV au-delà de β=1024. Il ne
réduira pas des contrats différents à un minimum de sécurité globale.
Une inversion défavorable R1/témoin dans un modèle retenu, ou un contrat
manquant, reste visible et bloque toute sélection finale automatique.

Le volet C03 calcule séparément les recherches génériques sur les graines
communes à plusieurs clés, les messages sous une même clé et les messages
liés à des clés différentes. Les bornes exactes ou rationnelles sont
contrôlées sur de petits espaces exhaustifs. Les requêtes quantiques
restent distinctes du coût des prédicats réversibles et de leur stockage.
Le nombre 256 décrit ici les espaces graines/messages et la sortie ; une
augmentation du rang n'augmente pas leur entropie.

Le volet correction rattache sans les recalculer les fractions certifiées
run-004 et leur transfert RO aux bruits semés, leur population et leur
quantification. Le seuil C05 historique 2^-174,8 est conservé. Le résultat
heuristique publié de ML-KEM-1024 ne devient pas un certificat identique,
et le taux honnête ne traite pas une recherche adaptative d'échecs.

La décision C01–C06 sera soit la conservation motivée de R1 pour le
développement, soit une proposition explicite de profil distinct. Les
obstacles de matrice semée, QROM, primitives concrètes, queues du dual,
mémoire bornée et nouvelles adaptations ne sont pas clos par un tableau
de coûts. Aucun nouveau profil ne sera substitué au moteur à la suite
d'un simple gain de rang ou d'un chiffre Core-SVP.

## Veille primaire consultée

La [documentation du mainteneur de l'estimateur](https://github.com/malb/lattice-estimator)
décrit son caractère heuristique et recommande d'identifier le commit.
[Li–Zheng2026/1048](https://eprint.iacr.org/2026/1048) traite la covariance
des scores ; [Bashiri2026/2565](https://eprint.iacr.org/2026/2565) améliore
des analyses duales prouvables. Leurs gains ne sont pas soustraits aux
coûts du panneau sans traduction de leur modèle.

[Kaiburr, version primaire du 3 novembre 2026](https://www.cryptojedi.org/papers/kaiburr-20261103.pdf),
d'Adhikari, Lyubashevsky et Schwabe, étudie des variantes de rang accru
avec une autre loi de bruit, q=3329 et retrait de la compression du
chiffré. Les auteurs publient [du code](https://github.com/cryptojedi/kaiburr),
des preuves de correction EasyCrypt et des réalisations C/Jasmin.
Cela interdit de présenter l'augmentation du rang comme une nouveauté
suffisante. Ces profils, leurs cibles de correction et leurs conventions
Core-SVP sont distincts de R1 ; les fortes valeurs Core-SVP n'éliminent
pas les limites dues aux primitives symétriques inchangées.

## Résultats du panneau neuf

Les contrôles de calcul ont été commis avant lancement au commit
`c37e9f7`. Les **40 travaux ont produit 40 coûts finis**, sans exception,
expiration ou remplacement. Le plus long a pris 95,293 secondes murales,
sous le plafond300 s. Ce temps mesure l'estimation, pas une récupération
de clé. Sage 10.7/Python 3.12.15, NumPy 2.5.4 et SciPy 1.18.1 proviennent des
158 paquets épinglés ; leurs versions sont conservées. Le runtime tmpfs
absent a été réhydraté depuis les archives locales vérifiées avant calcul.

Voici les valeurs `log2(rop)` du jeu key ; chaque ligne conserve son
contrat propre et ne représente pas un niveau global de sécurité.

| Modèle | Famille | ML-KEM-1024 | R1 | Différence conditionnelle |
|---|---|---:|---:|---:|
| MATZOV classique | uSVP | 275,104 | 402,823 | +127,718 |
| MATZOV classique | BDD | 270,724 | 398,256 | +127,532 |
| MATZOV classique | Hybride primal MITM | 270,750 | 398,274 | +127,524 |
| MATZOV classique | Dual simple | 288,526 | 422,276 | +133,750 |
| MATZOV classique | Dual hybride MATZOV | 262,336 | 383,773 | +121,437 |
| Sensibilité BCSS23 | uSVP | 224,006 | 340,110 | +116,104 |
| Sensibilité BCSS23 | BDD | 224,884 | 341,120 | +116,236 |
| Sensibilité BCSS23 | Hybride primal MITM | 224,884 | 341,120 | +116,236 |
| Sensibilité BCSS23 | Dual simple | 231,695 | 350,362 | +118,667 |
| Sensibilité BCSS23 | Dual hybride MATZOV | 214,789 | 325,958 | +111,169 |

Les **20 paires** des deux jeux finis sont favorables au proxy R1.
L'ajout de la ligne idéale ne change aucun des vingt coûts obtenus dans
cette exécution, sans établir une équivalence des hypothèses MLWE(6,6)
et(7,6). Les 24 sorties ayant une contrepartie M05 retrouvent exactement
leurs `log2(rop)` ; elles sont bien recalculées avec la nouvelle version,
mais ce constat n'est pas une nouvelle validation de l'heuristique.

Les huit appels d'hybride primal choisissent ζ=0. Ils n'établissent pas
qu'aucun hybride à secret deviné ne serait meilleur : l'optimisation de
ζ est locale, et sa gestion de d diffère du wrapper BDD. Pour R1 classique,
le coût hybride est supérieur au BDD de 0,0181 unité logarithmique malgré
ζ=0. Cet écart d'optimisation est conservé. Aucun optimum exhaustif en
(ζ,d,β) n'est prétendu. Dix sorties classiques R1 emploient des paramètres
de réduction au-delà de1024, hors la plage de calibration annoncée du
modèle fini MATZOV. Les rotations de la structure du module et les
révisions modernes de scores ne sont pas automatiquement absorbées par
l'API LWE aplatie.

## Ce que les ressources permettent de conclure

Le dual simple donne un champ mem documenté en éléments modulo q.
Dans la convention dense u16 annoncée, son stockage au jeu key vaut :

| Modèle | log2 octets, ML-KEM-1024 | log2 octets, R1 |
|---|---:|---:|
| MATZOV classique | 196,310 | 290,690 |
| Sensibilité BCSS23 | 198,402 | 295,070 |

Ces quatre points dépassent chacun les trois plafonds de 2^40, 2^60 et 2^80
octets. Le champ ne valide pas tout le pic RAM d'une réduction, et les
autres familles ne fournissent pas un champ comparable contrôlé ici.
**Une comparaison réoptimisée sous plafond RAM reste donc ouverte.**
Un contre-exemple exact du rapport donne une famille A avec points
(temps,mémoire)=(1,100) et(3,1), puis B=(4,1). Filtrer seulement l'optimum
non contraint de A à mémoire1 masquerait son point faisable qui bat B.
Le panneau ne transforme pas une telle suppression en coût infini ou
en résistance prouvée sous plafond.

## Limites symétriques et cibles multiples

Les deux profils gardent des espaces graines/messages de 256 bits et des
sorties de 32 octets. Les recherches génériques de taille 2^256 et leur
échelle de requêtes Grover 2^128 bornent ce qu'une augmentation du rang
peut promettre sur ces espaces ; les portes réversibles, la profondeur,
les prédicats et la mémoire ne sont pas chiffrés par ces exposants.
Les références primaires sont [Grover1996](https://arxiv.org/abs/quant-ph/9605043)
et [Zalka1999](https://arxiv.org/abs/quant-ph/9711070). Le rapport vérifie
son modèle fini, sans prétendre redémontrer l'optimalité quantique générale.

Pour U cibles indépendantes et q candidats distincts testés dans un même
domaine de M points, la probabilité exacte est `1-(1-q/M)^U` ; le rapport
conserve un intervalle rationnel par inclusion-exclusion et borne d'union.
Cela décrit une recherche de graine commune à plusieurs clés, ou des
messages sous une même clé. Le stockage et le test cohérent d'appartenance
aux U cibles ne sont pas gratuits.

Pour des messages sous des clés différentes, le prédicat dépend de la
clé. Avec q_i tests sous chaque clé, le modèle indépendant donne
`1-prod_i(1-q_i/M) <= sum_i(q_i)/M`. Évaluer un même candidat contre U clés
coûte U prédicats ; le diviseur U n'est pas attribué gratuitement. Le
modèle quantique uniforme de paires (clé,message) garde une densité1/M.
La récurrence d'amplitudes de Grover est calculée exactement en fractions
sur petits espaces. Au total : 108 panneaux de recherche commune,
286 allocations de requêtes entre clés et 162 panneaux Grover exacts.
Les 15 panneaux à256bits restent des modèles génériques d'objectifs
définis, sans borne globale IND-CCA.

## Correction, coût de format et décision C01–C06

La fraction historique run-004 vérifie à nouveau exactement
`delta^5 <= 2^-874`, soit le seuil 2^-174,8. Son affichage est environ
2^-310,086 dans le modèle CBD. Le transfert RO historique multiplie ce
majorant par `1-2^-256`, en moyenne sur les oracles/clés et pour le pire
message avec coins PKE frais. Cela ne certifie ni chaque clé fixée ni
SHAKE concret. Le taux ML-KEM-1024 publié dans
[FIPS 203, tableau 1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
est une estimation sous heuristique de fonctions aléatoires ; le rapport
ne lui attribue pas le même statut que la fraction rationnelle R1.
Les erreurs adaptativement recherchées restent liées à C01.

| Exigence | Décision M10 |
|---|---|
| C01 | Conserver le raccord exact en cours, sans clôture QROM/primitives concrètes ni héritage automatique de la preuve ML-KEM |
| C02 | Les 20 comparaisons préenregistrées passent le critère relatif dans leurs modèles ; RAM bornée, structure, queues et optimalité globale empêchent encore un gel final |
| C03 | Aucune hausse d'entropie par le seul rang ; distinguer objectifs, cibles et coût des prédicats |
| C04/C05 | Conserver le témoin R1 et sa marge conditionnelle, sans transformer les essais du moteur en démonstration d'événements rares |
| C06 | Conserver R1 pour le développement, aucun nouveau profil sélectionné, aucune modification silencieuse du moteur |

Le coût de format est réel : clé publique 2528 contre 1568 octets, chiffré
2656 contre1568, clé privée développée5088 contre 3168. Un échange
comprenant une clé et un chiffré prend 5184 contre 3136 octets, soit
**2048 octets supplémentaires (+65,306 %)**. Les 32 octets de secret partagé
restent communs. Les tailles de référence sont celles de FIPS 203,
tableaux 2/3 ; les tailles R1 sont reconstruites de ses encodages.
Aucune nouvelle comparaison de performances entre réalisations des deux
KEM n'a été exécutée par ce chantier ; les gains M09 ne sont pas multipliés
aux chiffres d'anciens benchmarks pour en inventer une.

La conservation de R1 est une décision de recherche motivée par les
comparaisons et la correction étudiée. Elle ne constitue pas une sélection
cryptographique finale ou une supériorité générale sur ML-KEM-1024.

## Conservation et rejeu

`results/security/m10-parameters-001` conserve 238 membres : plan,
40 entrées/sorties, flux et reçus, contrôleurs exécutés et d'analyse,
versions, provenance de l'estimateur et sources primaires référencées.
Les paquets Sage et les documents primaires complets restent dans le
cache local, sans redistribution externe dans cette capsule.

Deux incidents de posttraitement sont conservés : utilisation initiale
du manifeste run-004 de l'étude u-dependency à la place du manifeste
séparé du certificat ; puis différence de types tuples/listes au rejeu
JSON du petit contre-exemple mémoire. Les corrections n'ont changé
aucune des 40 sorties d'estimation, quantité ou conclusion numérique.
Le précontrôle initial du runtime absent et sa réhydratation sont eux
aussi identifiés, sans crédit de calcul supplémentaire.

Le lecteur ne lance ni Sage ni téléchargement. Treize tests passent,
dont les refus de m infini, résultat expiré présenté comme fini, flux
altéré, entrée historique réétiquetée et les contrôles mathématiques finis.
Le rejeu sous `python -O` passe également.

```powershell
.tools/research-venv/Scripts/python.exe -B research/m10_parameters_report.py verify
.tools/research-venv/Scripts/python.exe -B -m unittest discover -s research -p 'test_m10_parameters*.py' -v
```
