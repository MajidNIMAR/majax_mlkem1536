# M06 — borne du rejet implicite de R1

10 novembre 2026, Europe/Paris. Étude issue du protocole
[M06](PROTOCOLE_M06_MOTEUR.md), point de départ
`693c6a305b5143b9b00b912353bbae153cad4e4f`. Ce travail ne modifie ni le moteur,
ni R1, ni les instantanés M05. Les dates ci-dessus identifient le jalon ;
elles ne sont pas déduites de l'horloge de la machine.

**Le terme ε_J de M05 reçoit maintenant une borne dans le modèle RO idéal :**

`ε_J,ROM ≤ min(1, q/2^256)` ;

`ε_J,QROM ≤ min(1, 2q/2^128)`.

Ces expressions valent lorsque D>0, avec D accès classiques à la fonction
indexée par la clé secrète. Si D=0, les deux jeux sont identiques et leur
écart vaut exactement zéro. Le nombre q compte les appels publics pouvant
porter sur le domaine J, avec la convention globale précisée ci-dessous.
Les deux bornes sont des **écarts absolus de probabilités de distinction**
dans [0,1], et non un biais CCA dans [0,1/2]. La constante quantique 2 est
vérifiée ; aucune constante quadratique conjecturée n'est substituée.
La borne quantique demeure lâche pour les grands budgets.

Ce résultat traite l'inconnue ciblée du modèle idéal. La sécurité de
SHAKE256 concret, le PKE à graines et l'argument IND-CCA complet restent
ouverts. C01 n'est pas clos.

## 1. Fonction du programme et jeu précis

Le code `crates/kem1536/src/dev_kem.rs` calcule le candidat de rejet

`J_z(c) = SHAKE256(TAG || "J\0" || z || c, 32 octets)`.

TAG est la chaîne de 21 octets `KEM1536-DEV-Q7681-R1\0`. Le préfixe public
TAG||J\0 occupe 23 octets ; z occupe 32 octets et c exactement 2656 octets.
L'entrée totale est donc de **2711 octets**. Cette concaténation est
injective en (z,c), sans ambiguïté de découpage. Le domaine bruit utilise
TAG||N\0||seed||nonce, soit 56 octets, et demeure distinct même lorsque
les valeurs des graines coïncident.

La génération honnête appelle l'aléa système pour 64 octets : d est la
première moitié, z la seconde. Le modèle suppose ces 64 octets uniformes,
indépendants des oracles ; z est ainsi indépendant de d, de la clé
publique, de ses bruits et des informations auxiliaires de l'adversaire.
L'interface d'import d'une clé privée n'établit pas cette hypothèse pour
une clé importée quelconque. Une clé z connue, choisie par l'adversaire ou
corrélée à ses informations ne relève pas du présent énoncé.

La décapsulation calcule J sur chaque chiffré de longueur R1 et sélectionne
le candidat après comparaison du chiffré entier avec la réencapsulation.
Le jeu PRF donne à l'adversaire **toutes** les réponses J demandées, ce qui
domine l'observation du candidat effectivement sélectionné. Les entrées
refusées avant cet appel ne nécessitent pas de requête à l'oracle indexé.
Rendre une réponse répétée exige la même valeur, dans les deux jeux.

Notons H l'oracle public idéal SHAKE, représenté par un flot indépendant
de bits aléatoires par entrée. Le jeu réel donne H et la fonction classique
`c ↦ prefix_256(H(TAG||J\0||z||c))`. Le jeu idéal donne H et une fonction
aléatoire indépendante R de `{0,1}^{21248}` vers `{0,1}^{256}`. L'adversaire
peut faire D appels classiques adaptatifs à la seconde interface et q
appels quantiques à H. Les autres fonctions du KEM restent disponibles
avec leur modèle et leurs ressources M05.

L'accès public quantique est maintenu dans **les deux jeux**. L'énoncé ne
remplace pas cet accès par une simple liste de requêtes classiques.

## 2. Couplage de la ligne entière

Échantillonnons indépendamment H, R et z. Définissons H' comme H, sauf
pour les entrées `TAG||J\0||z||c`, où ses 256 premiers bits deviennent R(c).
Les bits suivants du flot restent ceux de H. La modification couvre tous
les chiffrés, avant les choix adaptatifs de l'adversaire.

Pour chaque z fixé, H' est encore un flot aléatoire uniforme par entrée.
Son préfixe à la ligne z est R ; la distribution jointe `(H',R)` est donc
exactement celle du jeu réel. `(H,R)` est exactement le jeu idéal. Toutes
les requêtes SHAKE avec différentes longueurs de sortie voient des préfixes
cohérents du même flot, y compris les requêtes de plus de 32 octets. Le
suffixe public n'introduit pas de nouvelle corrélation avec z.

Soit S_z l'ensemble des entrées de cette ligne secrète. La vue complète du
jeu idéal, y compris R et les domaines auxiliaires publics, est indépendante
de z. Pour toute entrée x déterminée par cette vue,

`Pr_z[x ∈ S_z] ≤ 2^-256`.

Une entrée hors du domaine J a une probabilité nulle ; une entrée J de la
bonne longueur comporte un seul candidat z. Cette indépendance porte sur
le jeu idéal, pas sur l'état du jeu réel après avoir appris des réponses.

## 3. ROM : dérivation finie et rôle de D

Dans le couplage précédent, les exécutions classiques sont identiques
jusqu'au premier appel public à S_z. Dans le jeu idéal, la liste adaptative
des candidats z reste indépendante du vrai z. Elle contient au plus q
candidats distincts ; sa couverture moyenne est donc au plus

`min(q,2^256)/2^256`.

Le lemme élémentaire des jeux identiques jusqu'au mauvais événement donne
le majorant ROM annoncé. Les appels indexés ne devinent aucun candidat z :
ils consultent R, indépendante de z dans le couplage. Il n'est donc pas
nécessaire de multiplier q par D. Cette absence de facteur D n'affirme pas
que l'adversaire apprend la même chose avec une réponse et avec de très
nombreuses réponses ; elle dit que la borne choisie couvre toutes ces
situations par un même événement plus large.

Les collisions de sorties existent déjà dans R et dans la ligne aléatoire
H'(z,·). Il ne faut pas ajouter automatiquement un terme anniversaire
`D(D−1)/2^257` : les deux jeux ont la même loi de collisions tant qu'ils
ne croisent pas un accès public sur la ligne secrète. Les répétitions d'un
même chiffré sont également cohérentes des deux côtés.

Un contrôle exact distingue collision et secret trouvé. Pour un candidat
fixe z' et t chiffrés distincts, on compare les t réponses publiques à leurs
t réponses indexées. Le coût est t appels publics et t appels indexés.
La probabilité que toutes les comparaisons passent vaut

`1/2^256 + (1−1/2^256)/2^(256t)` dans le jeu réel,

et `1/2^(256t)` dans le jeu idéal. L'écart exact est donc

`(1−2^(-256t))/2^256`.

Un faux candidat peut passer : une égalité de sorties n'est pas une preuve
de récupération de z. Cette stratégie n'est pas un majorant universel.

## 4. QROM : théorème et constantes vérifiés

Le théorème 3 d'Ambainis–Hamburg–Unruh, p.11, autorise deux oracles qui
diffèrent sur un ensemble S, avec distribution jointe arbitraire. Il borne
l'écart de probabilités par `2d√P_guess`, où d est la profondeur des
requêtes et P_guess la probabilité de rencontrer S en mesurant les
registres d'une requête choisie uniformément. On peut exécuter cette mesure
dans l'un ou l'autre monde. Le texte permet aussi des oracles auxiliaires,
absorbés dans une description auxiliaire commune (discussion p.10).
[AHU, source primaire](https://eprint.iacr.org/2018/904).

Appliquons le théorème en exécutant l'extracteur dans le **monde idéal** H,R.
L'auxiliaire contient R et les domaines auxiliaires fixes disjoints du
domaine J complet, notamment N, échantillonnés indépendamment de z. Les
autres entrées J restent dans l'oracle variable H/H'. On ne transmet pas
une description du complément de S_z, dont le domaine dévoilerait z.
Même après D réponses classiques de
R, l'état du registre d'entrée de l'extracteur reste indépendant de z.
Pour une requête séquentielle, la somme des poids des lignes J est au plus
1 ; sa moyenne à la ligne z vaut au plus `2^-256`. D'où

`ε_J,QROM ≤ 2q√(2^-256) = 2q/2^128`.

La preuve ne définit pas « l'événement qu'une superposition a interrogé z »
comme si la requête était classique : elle utilise précisément la mesure
intermédiaire du théorème O2H. La section 5.4 d'AHU, p.25–28, justifie la
constante par la norme de la différence des états, puis les états mixtes
et les probabilités d'événements. La constante n'est pas extrapolée d'un
coût de Grover.

**Requêtes parallèles.** q compte le nombre total de portes d'oracle, pas
le nombre de lots. Un lot de plusieurs registres peut être sérialisé sans
changer la transformation finale : les portes agissent sur des registres
distincts et commutent. Cette sérialisation conserve q et autorise la
borne séquentielle ci-dessus, sans prétendre préserver la latence du lot.
En appliquant directement le théorème à des lots, le poids de S_z peut
être multiplié par leur nombre de registres ; on ne peut alors garder
`P_guess≤2^-256` en comptant le lot comme une seule requête.

**Oracle global et ressources de la réduction.** Une requête cohérente
peut mélanger J, N et des entrées quelconques. On compte chaque tel appel
dans q ; on ne lui attribue pas un label classique. La modification H→H'
agit directement sur l'oracle global : il n'y a pas de facteur 2 de
dispatch entre domaines dans cette preuve. Un appel interne dont l'entrée
est certainement dans N est identique dans les deux mondes. Il peut être
absorbé dans les opérations auxiliaires communes utilisant H hors J ;
dans la preuve par différences de normes, son poids sur S_z est nul.
Son temps et son coût d'évaluation N restent comptés dans les ressources.

Ainsi, dans le remplacement de J au sein de M05, q doit borner **tous**
les appels potentiellement J du distingueur PRF complet, y compris ceux
d'un simulateur s'il en introduit. Les appels indexés D sont l'autre
interface et ne sont pas ajoutés à q ; les N internes connus hors J ne
créent pas d'appel potentiellement J. Si ces conditions ne sont pas
établies pour une autre réduction, on emploie son nombre total d'appels
publics SHAKE comme q. Les tables complètes utilisées pour l'argument
informationnel ne constituent pas une simulation quantique efficace
gratuite par une table classique paresseuse.

L'adversaire ne reçoit aucun accès quantique à l'interface indexée dans
le contrat de ce jalon. Le théorème est appliqué avec ses D réponses
classiques, dont les entrées et sorties peuvent être mémorisées. L'argument
ne ferme ni une sécurité qCCA de décapsulation en superposition, ni une
preuve de temps constant ou d'effacement mémoire.

### Contrôle des versions et correction de SXY

Le lemme 2.2 de Saito–Xagawa–Yamakawa traite exactement la fonction à
préfixe secret H(s,·), en présence de l'oracle H public. Son texte corrigé
d'août 2021 et sa preuve, appendice C.1 p.27, donnent aussi
`2q_H·2^(-ℓ/2)` ; la note 9 corrige explicitement l'ancienne constante
`sqrt(2)q_H·2^(-ℓ/2)`. Le miroir téléchargé fournit l'ancien PDF de mai
2018 : **sa constante plus favorable n'est pas utilisée**. Le texte
corrigé et sa note ont été vérifiés dans l'index du PDF officiel ; son
fichier intégral n'a pas été récupéré et aucune empreinte lui est inventée.
[SXY, notice et version corrigée](https://eprint.iacr.org/2017/1005).

La notice AHU de décembre 2021 signale une erreur de son annexe B sur une
transformation FO. Son avertissement primaire précise que les résultats
principaux sont inchangés. Nous utilisons le théorème O2H principal et sa
preuve, pas l'analyse FO de cette annexe. La copie intégrale lue est datée
du 18 février 2019 ; l'avertissement de 2021 a été vérifié séparément sur
le texte indexé du PDF officiel. Ce contrôle évite de confondre ancienne
copie de miroir et dernière version.

Le travail récent de Jaeger, version arXiv v1 de novembre 2025, reprend
explicitement AHU théorème 3 et en montre des applications adaptatives
plus générales. Ses théorèmes 1–2, p.10–11, confirment le cadre de
distinction retenu. Notre ligne entière est fixée dès le départ, donc
aucune constante supplémentaire issue d'une reprogrammation adaptative
n'est nécessaire. Les résultats y sont cités avec la version PDF lue ;
le rendu HTML actuellement servi comporte une autre date de fabrication.
[Jaeger, version v1](https://arxiv.org/abs/2511.16009v1).

## 5. Valeurs et raccord au résultat M05

Pour D>0 et q=2^b, les logarithmes des majorants sont exacts avant
plafonnement à 1 :

| b | Borne ROM ε_J | Borne QROM ε_J |
|---:|---:|---:|
| 0 | 2^-256 | 2^-127 |
| 16 | 2^-240 | 2^-111 |
| 32 | 2^-224 | 2^-95 |
| 64 | 2^-192 | 2^-63 |
| 96 | 2^-160 | 2^-31 |
| 128 | 2^-128 | 1 |

La borne QROM apporte une expression chiffrée justifiée à la place de
l'inconnue ε_J, mais elle est peu serrée. Elle ne signifie pas qu'une
attaque atteint `2^-63` à `2^64` appels, ni que R1 possède 63 bits de
sécurité. Une borne supérieure de distinction n'est pas une probabilité
de récupération de clé. Un coût de recherche de clé n'est pas non plus
automatiquement une borne de distinction. Aucun coefficient `q²/2^256`
n'est déclaré pour le présent jeu sans théorème et réduction vérifiés.

Le théorème 22 de Ge–Yang–Yu–Yu utilisé en M05 conserve la forme

`Adv_CCA ≤ min(1/2, ε_J + 2(Q_F+Q_K)√ε_OW +16(Q_F+1)^2δ_RO)`.

Sous les hypothèses du présent modèle, on peut désormais y substituer
`ε_J≤min(1,2q/2^128)`. Les oracles N communs et les autres auxiliaires
restent publics dans le jeu PKE ; cette substitution ne les retire pas
de ε_OW. Le budget conservateur M05 `Q_F=Q_K=2g+D+1` ne change pas.
[GYY, théorème 22](https://eprint.iacr.org/2025/1641).

Avec g=q=D=2^64, la composante de correction reste environ `2^-174,916`
et celle du rejet est majorée par `2^-63`. La cible illustrative M05
`ε_J≤2^-130` n'est donc pas certifiée par ce majorant. Pour D>0, la borne
ROM la certifie pour `q≤2^126` ; la borne QROM ne la certifie pour aucun
q entier strictement positif. Ce résultat décrit la force de la réduction,
pas une impossibilité de sécurité du moteur. Une allocation moins stricte,
un autre budget ou une preuve de rejet plus serrée sont des questions
distinctes. Le résultat M05 défavorable lié au plancher de devinette du
message OW demeure lui aussi intact.

Le calculateur rejoue sept panneaux, dont q=D=0, q=D=1 et les cinq
puissances de deux de la table. Il remplace effectivement le terme PRF
dans le raccord QROM et inverse l'exigence sur ε_OW lorsque le résidu
l'autorise. Aucun avantage OW inconnu n'est mis à zéro pour revendiquer
une sécurité complète ; un diagnostic « même avec OW=0 » indique
uniquement une limite du majorant suffisant.

## 6. Reproduction et portée des tests

```powershell
.\.tools\research-venv\Scripts\python.exe -B -m unittest discover -s research -p test_rejection_security_m06.py -v
.\.tools\research-venv\Scripts\python.exe -B research/rejection_security_m06.py
.\.tools\research-venv\Scripts\python.exe -B research/rejection_security_m06.py --verify results/security/m06-rejection-001
```

`results/security/m06-rejection-001` conserve fractions rationnelles de J,
recettes rationnelles exactes pour les termes issus du certificat,
contrat étroit du domaine J, références primaires, provenance et sources
propres du calcul. Le vérificateur contrôle les empreintes et rejoue les
panneaux à partir du certificat archivé. Les fragments source contrôlés
automatiquement accompagnent la lecture humaine de J, de xof et de
KeyGen ; ce contrôle textuel n'est pas une preuve formelle de programme ou
une preuve d'entropie du générateur système. L'instantané peut contenir
des octets du travail M06 simultané sur l'arithmétique : leur présence ne
constitue pas une preuve sur cette optimisation.

Les huit tests couvrent les unités et plafonds de probabilité, les budgets
maximaux suffisants exacts, et des expériences finies indépendantes du
calculateur : toutes les tables H/R/z de petites instances, sans accès
indexé, répétitions, deux chiffrés distincts, choix adaptatifs et faux
positifs par égalité de sorties. Un test d'amplitudes rationnelles contrôle
`||(U'−U)ψ||²≤4*poids(S_z)` dans une superposition J/N. Un dernier test
énumère un véritable calcul à une requête quantique, avec projection qui
conserve les termes croisés entre candidats. Ces fixtures mathématiques
ne simulent pas le moteur R1 et ne constituent pas une vérification
machine du théorème pour tous les adversaires quantiques.

Les PDF externes restent dans le cache ignoré
`artifacts/generated/m06-rejection-primary`, sans redistribution dans le
résultat. La table suivante identifie exactement les fichiers consultés.

| Source | Version et périmètre relu | SHA-256 du fichier effectivement récupéré |
|---|---|---|
| AHU | 18 février 2019, 45 pages ; théorème 3 p.11 et preuve p.25–28. Avertissement primaire 9 décembre 2021 lu séparément, copie intégrale corrigée non récupérée | `a3b09922553b2138dc022db72035e8378c30cf27cfad312b1a45558bad03d69d` |
| SXY | Ancien miroir 16 mai 2018, 31 pages, constante exclue ; correction officielle août 2021 et C.1 p.27 lues par index, sans empreinte inventée pour la version corrigée | `97f6a84ff8ee7cb845b0adda6c66947635bdea1903fe2c5ad216639c5889b1bb` |
| Jaeger | arXiv v1, couverture 21 novembre 2025, 24 pages ; théorèmes 1–2 p.10–11 | `95609e630baf7fd7572591e5cdf2e4693d768dab51c8d2a095b9d120922d8965` |
| GYY | Copie du 30 septembre 2025, 97 pages, déjà figée M05 ; théorème 22 p.96 | `408b2f6f880658b4026e19393ef2d6cd764255f823b0a5ec28538e40f14d34ff` |

La fonction de rejet du programme et le modèle de sa clé doivent conserver
ce contrat. Le transfert de l'oracle idéal vers Keccak, une borne plus
serrée si nécessaire et l'argument complet sur le PKE à graines restent
des travaux explicites ; l'optimisation du moteur se poursuit indépendamment.
