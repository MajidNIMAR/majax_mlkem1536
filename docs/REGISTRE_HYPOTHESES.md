# Registre des hypothèses de recherche propres au projet

Ouvert le 24 octobre 2026 à la demande de l'utilisateur. Ce registre complète
le cahier des charges et les critères de faisabilité J2. Il sert à formuler
des expériences avant d'en connaître les résultats, puis à conserver les
pistes positives, négatives et indécidables. Une proposition locale ne vaut
pas revendication de nouveauté mondiale.

**Orientation précisée le 24 octobre 2026.** Les propositions peuvent employer
des méthodes non standardisées et modifier la construction de référence.
Une approbation institutionnelle préalable n'est pas nécessaire pour les
étudier. Leur intérêt doit être formulé par une hypothèse testable : correction,
coût, taille, hypothèse de sécurité ou résistance à une attaque identifiée.
Les références existantes restent des contrôles ; l'évaluation extérieure du
candidat viendra ensuite. Les preuves, estimations et mesures restent distinctes.

## H01 — Précision mixte fixe de u

**Question.** À n=256,k=6,q=7681,η1=η2=3 fixés, une répartition publique de la
précision de u peut-elle réduire le témoin de 2656 octets de `run-004` tout en
conservant une borne satisfaisant C05, sans indépendance des arrondis ?

**Variables.** Pour u : coefficients sur 11 ou 12 bits, ou transmis exactement
sur 13 bits. Pour v : 2,3,4,5,6,7,8 ou 13 bits. Répartitions par polynômes
entiers puis masques entrelacés publics de coefficients. Aucun choix de masque
ne dépend de la clé, du message ou d'un essai de décapsulation.

**Contrôles.** Le témoin u exact/dv=5 doit reproduire le certificat rationnel
de `run-004`. Comparer aussi le meilleur u exact avec dv réduit, afin de séparer
le gain de v et le gain propre à la précision mixte de u.

**Décision locale.** Une configuration est certifiée pour la correction si la
borne rationnelle passe C05. Une configuration qui ne passe pas cette borne
est marquée « non certifiée par cette méthode » : cela ne prouve pas que son
taux d'échec réel dépasse le seuil. Une amélioration de longueur ne sélectionne
pas un nouveau profil avant la comparaison des attaques.

**Méthode.** Majoration point par point `−s*δu ≤ |s|*r` pour chaque erreur de
support [-r,r], puis MGF rationnelle des variables CBD. Le flottant ne sert
qu'à proposer les points de recherche ; chaque configuration rapportée est
recalculée en rationnels et chaque acceptation est décidée en entiers.

**État.** Expérience exécutée dans `run-005`. Voir
[`PRECISION_MIXTE.md`](PRECISION_MIXTE.md) pour les résultats et la portée.

**Résultat H01.** Un point de 2581 octets obtient une borne 2^-175,734559 dans
le modèle, avec 88 coefficients sur 12 bits et dv=3. Le gain propre à la
précision mixte est de 11 octets au-delà du contrôle u exact/dv=3 ; la réduction
de v apporte séparément 64 octets. H01 produit donc un gain limité mais
certifié dans le modèle. 215 des 240 configurations rapportées ne sont pas
certifiées par cette majoration. Aucun nouveau profil ni niveau global n'est
validé et aucune nouveauté mondiale n'est établie.

## H02 — Quantification par groupes adaptée aux queues du bruit

**Question.** Une règle de quantification sur de petits groupes de coefficients,
optimisée pour une majoration du bruit après produits secrets, peut-elle
améliorer le compromis longueur/correction obtenu avec les supports scalaires ?

**Première expérience envisagée.** Énumérer des quantificateurs bidimensionnels
sur un petit anneau, compter les cellules et leurs erreurs, puis comparer les
bornes de queues en conservant les dépendances requises. Garder les règles
déterministes et les régions de décodage explicitement vérifiables.

**Antécédents et risque.** Les codes multidimensionnels et les décodages groupés
ont des antécédents, notamment les
[codes Minal](https://github.com/thalespaiva/minal_mlkem/). Leur existence doit
être citée. Les erreurs opposées ne s'annulent pas automatiquement dans le
produit avec des secrets inconnus ; toute amélioration doit être calculée.

**État.** Expérience exécutée dans `run-006`. Le quantificateur décalé par paires
admet à q=7681 une erreur de norme L1 au plus 1, vérifiée par un argument de
couverture et des contrôles finis. Le plus court certificat trouvé atteint
2567 octets et une borne 2^-175,665600, soit 14 octets de moins que H01. Il
reste un point de frontière à faible marge, sans profil sélectionné.
Voir [`QUANTIFICATION_PAR_PAIRES.md`](QUANTIFICATION_PAR_PAIRES.md).

**Résultats négatifs conservés.** Le contrôle de couverture échoue à q=17,b=3
malgré une meilleure erreur moyenne. Le critère MGF local n'améliore pas les
histogrammes du critère euclidien dans les cinq petits modèles testés. Neuf
des seize bornes de rang 6 rapportées ne sont pas certifiées par la méthode.

## H03 — Contrôle des configurations extrêmes à l'échantillonnage

**Question.** Une distribution dense avec contrainte globale de norme peut-elle
améliorer la correction tout en conservant la difficulté des problèmes exposés ?

**Première expérience envisagée.** Comparer sur de petits paramètres la loi CBD
initiale et une loi conditionnée explicitement définie : normalisation, support,
entropie, corrélations et queues. Examiner ensuite les attaques qui pourraient
exploiter la contrainte introduite. La quantité d'entropie ne suffit pas à
conclure à la difficulté cryptographique.

**État.** Hypothèse non testée, de portée plus large que H01. Elle modifierait
les distributions de sécurité et demanderait une étude propre.

## H04 — Codes auxiliaires pondérés et décodage concret

**Question.** À mêmes q, longueur de code et nombre de symboles, une pondération
des coordonnées de blocs peut-elle améliorer la quantification du contrôle
répété tout en conservant un décodage exact effectivement exécutable ?

**État.** Première expérience exécutée dans `run-010`. Cette entrée est ajoutée
après l'étude et ne constitue pas une préinscription. Le choix élémentaire de
puissances d'une base rapproche la norme moyenne observée du repère GV dans
les quatre panneaux, au prix d'une énumération complète des symboles de bloc.
Au point q=7681,140/21 : ratio moyen 1,177973, contre 3,332703 pour le contrôle.
Le décodeur exact prend environ 6,752 ms dans le prototype local. Les générateurs
ne sont pas optimisés ; l'hypothèse idéale n'est pas réalisée et aucun coût
d'attaque ou paramètre de décapsulation du KEM n'est validé par ce résultat.
Voir [`DECODEUR_CONCRET.md`](DECODEUR_CONCRET.md).

**Complément exécuté.** `run-011` reconstruit les résidus et traite leur
contribution cosinus sous CBD idéal. La norme seule ne détermine pas le biais.
Six lois exhaustives confirment les dépendances intrabloc et la factorisation
entre blocs indépendants. Les 32 termes de chaque banque ne suffisent pas à
valider une liste exponentielle de l'attaque. Le score complet et le compromis
coût/distance restent ouverts ; aucun coût de sécurité n'est actualisé.
Voir [`SCORES_DECODEUR.md`](SCORES_DECODEUR.md).

## Originalité et publication

Le [README Minal figé au commit 6b12ae4](https://github.com/thalespaiva/minal_mlkem/blob/6b12ae4fa24c04fe756386cb8d7e7d88d283d1a9/README.md)
contient des paramètres DU0/DU1 et un nombre de blocs pour DU0. La compression
mixte par blocs a donc un antécédent explicite. H01 reste une expérience locale
avec sa borne et ses contrôles, sans nouveauté revendiquée sur ce principe.

Le rang 6 apparaît déjà dans le paramétrage simplifié « Kyber1536 » de
[Boudgoust et Scholl, ePrint 2023/016](https://eprint.iacr.org/2023/016).
Ce précédent n'établit pas l'existence d'un moteur correspondant à notre futur
format ; il doit néanmoins être conservé dans l'état de l'art.

Une recherche web ciblée du 24 octobre 2026 sur les termes « Kyber1536 »,
« ML-KEM-1536 », « mixed precision » et « heterogeneous compression » ne
constitue pas une recherche exhaustive des dépôts ni une preuve d'absence de
code sous d'autres noms. La revendication éventuelle doit porter sur une
construction précise, sa preuve, son code et sa date de publication, avec
recherche d'antériorité dédiée. Aucune primauté mondiale n'est établie ici.

## H05 — Choisir le mot selon la contribution CBD

**Question préenregistrée.** À code, cibles et budget de candidats identiques,
le critère CBD apporte-t-il une amélioration utile par rapport au plus proche
mot euclidien ? [Protocole](PROTOCOLE_H05.md) enregistré avant l'exécution au
commit `17f30d3`. Secret idéal iid-CBD indépendant du résidu, contribution
auxiliaire seulement. Une aide à l'attaque n'est pas un gain de sécurité.

**État.** Expérience exécutée dans run-012. Poids entiers encadrés par
intervalles et borne uniforme d'approximation ; minima réels certifiés pour
les 38 400 blocs réels observés. À q=7681,140/21 pondéré : 67 mots changés
sur 256, biais moyen +0,427541 %, norme moyenne +0,007432 %, temps local
environ +24,85 %, avec certification comprise. Même budget q×k candidats,
travail par candidat différent. Six petits modèles complets : aucun mot
changé. Gain limité sur les codes pondérés ; conserver comme témoin et
prioriser le lien au score complet. Voir [l'étude](DECODEUR_CRITERE_CBD.md).
Aucun nouveau coût global, profil ou clôture J2.

## H06 — Relier décodeur et score dual complet dans un modèle fini

**Question et protocole.** Les résidus concrets, les contributions des vecteurs
duaux et les faux candidats changent-ils l'interprétation du biais de H05 ?
[Protocole](PROTOCOLE_H06.md) figé avant calcul au commit 3cbbd7c. Quatre
matrices fixes q=5/17, sept coordonnées CBD(1) comprenant secret et erreurs,
listes de 4/8 représentants duaux, deux familles et deux critères.

**État.** Exécuté dans run-013. La chaîne jusqu'à toutes les hypothèses de la
DFT est contrôlée par histogrammes exacts, décisions certifiées et covariance
complète. Le critère CBD peut augmenter le bon score moyen tout en dégradant
le classement : 35,7544 % vers 32,0068 % dans un cas pondéré q=17/N=8.
Le témoin uniforme a la variance 1/(2N) mais une queue non conforme à la
normale dans ce petit modèle. L'effet du critère n'est pas uniforme entre
matrices et les panneaux répétés à q=5 ne sont pas des réplications
indépendantes. Voir [l'étude](SCORE_DUAL_COMPLET_REDUIT.md).

**Décision.** Ne pas utiliser la seule moyenne ni la seule variance pour
valider une utilité de score ou un coût d'attaque. Étendre la famille réduite
et le mode de génération des vecteurs avant passage aux dimensions réelles.
Aucun nouveau niveau global, profil ou clôture J2.

## H07 — Élargissement de la famille et génération après LLL

**Question et protocole.** Les constats H06 persistent-ils sur davantage
de matrices et de tailles de liste, ainsi qu'avec des vecteurs issus d'une
réduction effective ? [Protocole](PROTOCOLE_H07.md) préenregistré au commit
9dfeefa : 32 matrices q=5/17, N=4/8/12, LLL rationnel en dimension 3 puis
125 combinaisons bornées, comparaison au quotient exhaustif et aux deux
critères. Aucun ajustement de matrice ou seuil après observation.

**État.** Exécuté dans run-014. Les 768 panneaux correspondent à 224 banques
distinctes. Certificats LLL et témoins projetés contrôlés indépendamment.
À q=17, accord des listes dans 15/16, 13/16 et 9/16 cas selon N : la boîte
bornée peut manquer des vecteurs. Le critère CBD améliore parfois la moyenne
du vrai score tout en dégradant son classement ; le phénomène persiste
dans la famille élargie. Les queues du témoin uniforme ne sont pas validées
par la seule variance 1/(2N). Voir [l'étude](LLL_ET_FAMILLE_ELARGIE.md).

**Décision.** Garder l'oracle exhaustif comme contrôle des énumérations
réduites. Distinguer certificat de réduction, qualité/couverture de la liste
et utilité du score. Aucun facteur global tiré de ces petits cas ; restent
les dimensions plus grandes, CBD(2)/CBD(3), les ressources et le rang 6.

## H08 — Lois CBD(2)/CBD(3) et dimension de réseau supérieure

**Question préenregistrée.** Les contrôles du score et les constats H07
se maintiennent-ils avec des distributions CBD(2)/CBD(3) et une dimension
de réseau 5 ? [Protocole](PROTOCOLE_H08.md), commit 128c463 : huit matrices
par architecture 3/5, q=17, η=1/2/3, mêmes sources et critères, N=4/8/12.

**État.** Exécuté dans run-015 : 1152 panneaux, 155 banques distinctes,
96 lois jointes exactes, retrouvées par une autre récurrence de bits jusqu'à
2^54 issues couvertes. Aucun échantillonnage de probabilité rare. Les 192
calibrations CBD(1)/dimension 3 sont exactes. Au code pondéré, dimension
5/N=12, η=2 et η=3 donnent chacun trois pertes et cinq égalités pour le
critère CBD, avec amélioration de la moyenne du vrai score dans les pertes.
La boîte LLL retrouve ici les préfixes demandés dans les huit cas de
dimension 5, sans garantie générale d'exhaustivité. Voir
[l'étude](CBD_ET_DIMENSIONS_SUPERIEURES.md).

**Décision.** Conserver les deux critères et les lois exactes comme témoins.
Ne pas transformer les taux de récupération de u ou les queues uniformes
de q=17 en un niveau de sécurité réel. La suite doit relier ces contrôles
aux hypothèses et ressources du score à q=7681, avant une révision des coûts
de J2. Aucun profil sélectionné.

## H09 — Transfert du score et ressources au module réel

**Question préenregistrée.** Quelles hypothèses quantitatives séparent les
identités CBD du score dual estimé à q=7681 ? [Protocole](PROTOCOLE_H09.md),
commit a0b9fab : quatre points figés, sensibilité de variance, borne de
Cantelli, représentations mémoire et huit panneaux de résidus concrets.

**État.** Exécuté dans run-016. Au panneau MLWE/q=7681, la marge normale
à liste/seuil fixes tolère seulement 0,173146 % de hausse de variance.
Le code pondéré donne une moyenne empirique 350,99 fois plus faible que
le facteur code idéal. Les moments seuls supposés donnent une borne de
faux candidats plafonnée à 1. Une seconde voie Decimal à 90 chiffres
retrouve 192 champs et tous les 2048 résidus. Voir
[l'étude](TRANSFERT_SCORE_Q7681.md).

**Décision.** Ces diagnostics n'autorisent pas une substitution de coût.
Construire ensuite des listes effectives à q=7681, conserver (y,x,r,c),
leur sélection et les phases complètes ; confronter les moments vrais/faux
et une justification de queue. Les volumes de stockage dépendent de la
représentation. Aucun budget physique adopté, profil ou clôture J2.

## H10 — Chaîne complète sur des listes effectives à q=7681

**Question préenregistrée.** Réaliser les entrées manquantes du transfert
fini H09 : listes publiques sélectionnées, coefficients complets, moments
et phases au module réel. [Protocole](PROTOCOLE_H10.md), commit 6827a5a :
quatre matrices, réseau de dimension 5, codes 140/21 et préfixes 32/64/128.

**État.** Exécuté dans run-017 : huit banques, 648 moments, 4 194 304
identités et 16 384 états CBD synthétiques. Les moments analytiques
utilisent la loi CBD complète, les observations sont échantillonnées.
Variances proches de 1/(2N) sans validation de queue ; témoin uniforme
à N=128 : 1,8066 % au seuil de trois écarts types contre 0,1350 % normal.
Les faux candidats LWE ne reçoivent pas ce facteur. La seconde voie
reconstruit tous les décodages, phases, moments et événements, avec 64
contrôles de caractères Decimal à 80 chiffres. Voir
[l'étude](LISTES_DUALES_Q7681.md).

**Décision.** Le contrat fini est rempli dans cette dimension, sans liste
en dimension 2576, loi de crible, rotations MLWE ou queue rare démontrée.
La boîte bornée n'est pas un oracle des plus courts vecteurs ; la
récupération parmi 27 candidats n'est pas celle parmi q^21. Étudier les
dépendances d'ordre supérieur et la sélection des listes avant tout
transfert de coût. Aucun profil ni clôture J2.

## H11 — Dépendances additives et sélection des listes

**Question préenregistrée.** Quantifier les moments supérieurs du témoin
uniforme et comparer trois sélections publiques dans les mêmes 128
candidats : norme, hachage fixé, glouton du quatrième moment. Protocole
[H11](PROTOCOLE_H11.md), commit cfc924c, sans sélection fondée sur les états.

**État.** Exécuté dans run-018 : 28 tables de moments uniformes exacts,
36 panneaux, 56 panneaux LWE partagés à N=128. La kurtosis moyenne vaut
44,8121 à N=128. À N=32, glouton 4,3110 contre norme 12,1641 ; fréquences
uniformes à trois écarts types 209 contre 806 sur 32 768. Surcoût glouton
8256 évaluations par matrice, norme réseau au carré moyenne +89 % et
moyenne des log2 du biais vrai pondéré −1,198 bit. Une matrice améliore
le biais, trois le dégradent. Comptages et 33 024 coûts sont retrouvés
par une autre construction ; 12/96 calibrations H10.

**Décision.** Pas de règle gagnante ni transfert automatique de queue
uniforme au score CBD. Les moments LWE supérieurs restent empiriques ;
calculer ensuite le quatrième moment CBD complet sur des listes réduites.
Ces résultats n'énumèrent pas une loi complète à q=7681 et ne valident
pas la dimension 2576, les rotations ou un coût global. Aucun profil.
Voir [résultats et limites](SELECTION_ET_MOMENTS_SUPERIEURS.md).

## H12 — Quatrième moment CBD complet sur petites listes

**Question préenregistrée.** Calculer les moments de population 1..4 du
score complet, et distinguer les relations des coefficients (y,x,r) de
celles sur y seules. [Protocole](PROTOCOLE_H12.md), commit 8354d10 : trois
sélections figées, N=4/8/16, mêmes quatre matrices, deux codes et quatre
décalages vrais/faux fixés.

**État.** Exécuté dans run-019 : 64 banques et 1024 moments par développement
complet de caractères CBD numériques. Les termes équilibrés donnent les
fractions indépendantes exactes ; aucune annulation supplémentaire des
coefficients complets jusqu'à quatre dans ces banques. La kurtosis reste
voisine de 3−3/(2N), écart calculé maximal ≈5,775×10^-16. Les relations sur
y seules ne reproduisent donc pas l'excès de kurtosis du témoin uniforme.
Les corrections signées/logarithmiques conservent les très petits écarts.
Un développement indépendant par cosinus puis signes retrouve les moments,
256 calibrations et les phases des états H11 réutilisés.

**Décision.** Le moment uniforme ne suffit pas à classer les sélections
pour le score CBD complet. Étendre à N=32 avec encadrement explicite des
contributions et du coût, avant extrapolation. Caractères numériques sans
certificat par intervalles ; quatre moments ne déterminent pas la queue
rare. Aucun gain d'attaque, profil, modification C05 ou clôture J2.
Voir [résultats et limites](QUATRIEME_MOMENT_CBD.md).

## H13 — Bornes rationnelles à 32 vecteurs et livrable moteur

**Question préenregistrée.** Encadrer les moments complets jusqu'à quatre
à N=32 et conclure ce volet fini, en livrant une première brique du
moteur. [Protocole](PROTOCOLE_H13.md), commit 5fc45d1 : mêmes banques,
ordres et q=7681/η=3, majorant gaussien dyadique de constante 42,
plafond 128 et propagation rationnelle, sans nouveau tirage.

**État.** Exécuté dans run-020 : 24 banques, borne uniforme en décalage
sur l'écart de kurtosis à 2,953125, strictement inférieur à 3×10^-13.
La masse plafonnée reste couverte par une majoration explicite ≤2^-128
par moment brut. Une autre expansion, sans arrêt anticipé et sans import
arithmétique du projet, retrouve exactement histogrammes et fractions.
Les 64 calibrations H12 contiennent les 1024 corrections numériques
antérieures. Arithmétique polynomiale de référence Rust ajoutée, distincte
du KEM complet, avec trois tests algébriques et convolution indépendante.

**Décision.** Pas de passage automatique à N=64/128 ou aux moments
supérieurs. Les bornes n'établissent ni queue rare, ni classement de
sélection, ni coût d'attaque du grand réseau. Prochaine étape principale :
bilan de passage J2 → J3 et primitives utiles au moteur selon la
[feuille de route](FEUILLE_DE_ROUTE_MOTEUR.md). Aucun profil, seuil C05
ou clôture J2. Voir [calcul et limites](BORNES_N32_ET_MOTEUR.md).
