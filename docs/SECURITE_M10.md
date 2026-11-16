# M10 — composition exacte du PKE à graines et limites de la clôture C01

16 novembre 2026. Travail effectué sous le [protocole M10](PROTOCOLE_M10.md),
commis avant acquisition. Profil inchangé `KEM1536-DEV-Q7681-R1`,
`R=Z_7681[X]/(X^256+1)`, rang six, CBD(3), u exact et v sur cinq bits.
Le chantier de revue extérieure reste différé par l'utilisateur.

**Résultat : le raccord de la matrice publique et celui des bruits reçoivent
des simulations précises dans les modèles idéaux, y compris un hybride
quantique explicite. Deux voies FO quantiques ont été examinées. C01 reste
ouvert pour la sécurité finale du KEM concret.** Le manque résiduel est
localisé en fin de document ; il ne peut être remplacé par des tests du moteur.

Les programmes `m10_security*.py` calculent des fractions exactes et rejouent
des lois finies. Ils ne lancent ni moteur, estimateur, compilation, attaque,
mesure temporelle ou fuzzing. Les instantanés M09 et antérieurs sont intacts.

| Assertion | État obtenu dans M10 | Ce qui interdit une extension plus forte |
|---|---|---|
| PKE à graines en ROM relié aux deux MLWE | Raccord conditionnel, simulation de matrice et requêtes de bruit comptées | Les avantages MLWE aux ressources données restent des hypothèses, pas des inverses de coûts d'estimateur |
| KEM en ROM, composition avec rejets | Registre conservateur et carte classique de simulation fournis | La cible concrète et sa calibration temps/mémoire restent à justifier |
| Raccord CPA en QROM | Hybride de normes et matrice programmée avant interaction explicités | Il faut conserver les compteurs des réductions, pas ceux du seul adversaire initial |
| KEM en QROM | Théorème GYY applicable et voie MRE étudiée | La carte réversible complète et une marge numérique utilisable restent ouvertes |
| Programme avec SHA3/SHAKE fixes | Algorithmes/domaines reliés aux hypothèses et modèles | Aucun remplacement statistique des fonctions fixes n'est démontré ; hypothèses calculatoires à examiner |
| Niveau global au moins égal à ML-KEM-1024 | Non établi | Les modèles d'attaque, ressources, cibles et probabilités doivent être reliés au registre complet |

## 1. Jeu, modèles et convention d'avantage

Le jeu mono-utilisateur produit une clé honnête, remet sa clé publique à
l'adversaire et émet un défi KEM. Les demandes de décapsulation sont
classiques, adaptatives et différentes de la chaîne défi exacte. Le biais
CCA/CPA est `|Pr[gagner]-1/2|`; un avantage décisionnel MLWE et un avantage
PRF sont des écarts absolus de probabilités, dans [0,1]. OW désigne une
probabilité de retrouver le message entier, dans [0,1].

Le ROM donne des accès classiques aux oracles idéaux. Le QROM permet
des accès cohérents à ces oracles ; il conserve une interface classique de
décapsulation. Le modèle n'accorde ni clé privée, ni fuite corrélée aux
graines, ni oracle Decaps quantique. Le temps, la mémoire et la synthèse
réversible d'une réduction sont distincts du nombre de ses appels d'oracle.

Les domaines TAG||KG, TAG||G, TAG||A, TAG||N, TAG||H et TAG||J restent ceux
de la spécification R1. Dans l'idéalisation, leurs restrictions sont
indépendantes, avec des préfixes cohérents pour les lectures XOF. Dans le
programme elles sont réalisées par les fonctions SHA3/SHAKE fixes : la
séparation de domaines décrit leurs entrées, sans démontrer leur sécurité
calculatoire ni leur indépendance statistique concrète.

La liaison au code M10 comporte 17 ancrages dans les fonctions de production
nommées. Une ancienne chaîne conservée dans un test ne peut satisfaire
l'ancrage de `pke_keygen_into` ou de `noise_into`. Ce lecteur est lexical et
borné ; les capsules de qualification du moteur assurent séparément la
conservation des opérations et des octets. Aucune preuve formelle de Rust ou
du code machine n'est attribuée à ce contrôle.

## 2. Le problème de la matrice à graine publique

Dans `uniform`, chaque cellule utilise son flot
`SHAKE128(TAG||A\0||rho[32]||i[1]||j[1])`. Une paire de deux octets donne
un entier uniforme de 16 bits dans le modèle idéal. Le programme garde
ses 13 bits bas, rejette les valeurs de 7681 à 8191 et retient les 256
premières valeurs acceptées. Les trois bits hauts sont ignorés par Parse,
mais restent visibles pour un adversaire qui demande le flot brut.

Il ne suffit donc pas de qualifier le générateur de PRG. rho est public.
Le simulateur doit expliquer **les mêmes flots bruts**, y compris leurs
rejets, bits inutilisés, préfixes partiels et suffixes, à partir d'une
matrice uniforme donnée par le problème MLWE.

L'appendice C d'[Arriaga–Barbosa–Jarecki–Škrobot, CHIC](https://orbilu.uni.lu/bitstream/10993/63175/1/2024-308.pdf),
p.38–39, présente une inversion du rejet pour les paramètres Kyber.
Le présent raccord reprend cette idée et en explicite la loi de mots de
16 bits et les ressources propres au programme R1. Aucun théorème PAKE de
CHIC ni garantie de ses paramètres n'est attribué à notre KEM.

### Simulateur conditionnel d'une cellule

Soit un polynôme cible `a=(a0,...,a255)` uniforme modulo q. Le simulateur
tire d'abord un flot brut uniforme de mots de 16 bits. Il repère les mots
qui auraient été acceptés par le masque et le rejet de R1. Sur les 256
premiers, il remplace seulement les 13 bits bas par les coefficients
successifs de a. Les trois bits hauts, tous les rejets et tout le suffixe
après la 256e acceptation restent inchangés.

Posons `S=8192`, `H=8`, `W=S*H=65536`. Un mot brut a masse `1/W`.
Avant la fin de Parse, pour un coefficient fixé ai, un mot accepté de
bits hauts fixés a masse conditionnelle `q/W` ; un rejet garde masse `1/W`.
Après la fin, chaque mot a de nouveau masse `1/W`. Un préfixe comportant
une valeur acceptée différente du coefficient prescrit a masse zéro.

Ces masses sont exactement celles du flot brut conditionné par
`Parse(flot)=a` : chaque acceptation prescrite multiplie sa masse par q,
et le polynôme uniforme a masse `q^-256`. La moyenne sur tous les a
retrouve donc le flot brut uniforme complet. Le simulateur explique aussi
un préfixe qui s'arrête avant la fin de Parse. Une lecture d'un nombre
impair d'octets utilise le même mot déjà choisi, sans nouveau tirage.

**Les bits hauts ne doivent pas être mis à zéro.** Cette variante erronée
serait immédiatement distinguable par les lectures de l'oracle brut.
Un test négatif protège cette obligation.

### Les deux réductions MLWE

Les distributions décisionnelles nécessaires sont :

| Instance | Matrice en polynômes | Secret CBD(3) | Témoin scalaire aplati |
|---|---|---|---|
| MLWE(6,6) | 6×6 | six polynômes | n=1536, m=1536 |
| MLWE(7,6) | 7×6 | six polynômes | n=1536, m=1792 |

La première remplace `t=A*s+e` par un t uniforme. Dans le second hybride,
la matrice `[A^T;t^T]` est uniforme ; on remplace alors le vecteur de sept
polynômes `(A^T*r+e1,t^T*r+e2)` par un vecteur uniforme. Le simulateur
reconstruit les 36 cellules A à partir des six premières lignes transposées
du défi de la seconde instance. Le septième polynôme ne crée pas une
septième composante secrète.

L'ajout du message au dernier polynôme uniforme ne change pas sa loi.
L'encodage de u et la compression de v sont ensuite des applications
déterministes : ils conservent l'indépendance du message. La loi de v est
celle de `Compress5(U)`, pas une chaîne uniforme de cinq bits par coefficient.

Les rotations de ces matrices ne sont pas des lignes LWE indépendantes.
Les paramètres scalaires du tableau sont des témoins de comparaison
pour un estimateur ; ils n'effacent pas l'hypothèse structurée Module-LWE.
Une estimation avec un nombre infini d'échantillons ne remplace pas
automatiquement l'une ou l'autre de ces deux distributions finies.

## 3. Programmation, terminaison et ressources de matrice

Le simulateur choisit rho et prépare les tables **avant la première
requête de l'adversaire CPA**, une fois sa matrice défi connue. Après la
remise de la clé, rho est public : les requêtes à cette adresse sont
attendues et sont servies par la loi conditionnelle précédente.

Dans un ROM permettant des requêtes préalables avant le choix de rho,
au plus a graines préinterrogées coûtent `min(1,a/2^256)`. Cette borne ne
qualifie pas des requêtes quantiques préalables. L'interface QROM étudiée
ici prépare la clé et la programmation avant tout appel de l'adversaire ;
le calculateur refuse de transformer un budget de prétraitement quantique
en simple probabilité classique a/M.

Un flot idéal peut rejeter arbitrairement longtemps. Pour une réduction
à coût borné, on fixe un plafond L de candidats par cellule, en conservant
le rejet non borné du moteur. L'événement d'abandon du simulateur a la
probabilité exacte, par cellule,

`tau_L = sum_(j=0..255) binom(L,j) * (7681/8192)^j * (511/8192)^(L-j)`.

Les 36 cellules donnent une majoration `t_L=min(1,36*tau_L)`. À L=512,
le calcul entier certifie `2^-540 < t_L <= 2^-539`. Le simulateur traite
au plus **18432 mots, soit 36864 octets de préfixes de matrice**, et sa
moyenne non tronquée vaut exactement `36*256*8192/7681` mots.
Ce compte n'est ni le temps total de réduction ni une mesure de mémoire
du moteur. Conserver à la fois les mots originaux et les corrections XOR
peut demander deux tables de cette taille, auxquelles s'ajoutent la matrice,
les tables d'oracle et les espaces de travail.

Le calculateur charge conservativement quatre fois l'écart d'une simulation
de matrice : branche réelle/uniforme de chacune des deux réductions MLWE.
Cette marge évite de supposer une annulation entre deux abandons. Les
autres lectures d'oracle doivent aussi déclarer leurs longueurs : une
requête XOF produisant beaucoup d'octets n'est pas un coût constant gratuit.

[Barbosa–Schwabe, « Kyber terminates »](https://eprint.iacr.org/2023/708)
sépare justement la terminaison dans le flot idéal et celle du SHAKE
concret. Nous utilisons ici la queue binomiale du modèle idéal ; nous
n'importons pas dans R1 leur borne concrète de Kyber à candidats de 12 bits.

### Oracle quantique de matrice

Les tables conditionnelles sont choisies classiquement avant l'adversaire,
avec le préfixe limite ci-dessus. Pour chaque adresse cible connue, le
simulateur conserve la correction XOR entre le flot auxiliaire et le flot
conditionnel. Une requête cohérente est servie en évaluant l'oracle
auxiliaire puis la correction réversible sur les seuls préfixes connus.
Le reste du flot est inchangé. L'égalité sur chaque entrée de base donne
par linéarité l'égalité sur leurs superpositions.

Il s'agit d'une programmation de tables finies avant interaction, avec
un coût de prétraitement et un circuit de comparaison/correction publics.
Ce n'est pas une transposition d'une table paresseuse classique qui
mesurerait les requêtes quantiques. Ni la disponibilité ni le coût de
ces circuits ne sont attribués gratuitement à une implémentation concrète.

## 4. Extension quantique du couplage des bruits M09

Dans le jeu PKE à bruits frais, introduisons les noms latents d, sigma et
rseed, uniformes et inutilisés, sur un espace de taille M=2^256. Les
coefficients CBD viennent de bits frais. Ces noms restent indépendants
de **toute la vue du jeu frais**, y compris la clé publique, le défi,
les messages choisis et les réponses adaptatives aux oracles auxiliaires.

Hors collision sigma=rseed, on programme KG au point d avec rho||sigma
et N aux adresses sigma/0..11 et rseed/0..12 avec les bits frais du jeu.
La collision a probabilité 1/M et est payée avant cette programmation.
Conditionner les deux noms N à être distincts préserve leurs marges
uniformes et leur indépendance de la vue fraîche.

Pour chaque réalisation des oracles et des tirages, les deux calculs
utilisent les mêmes données publiques et ne diffèrent que par leurs
opérateurs de requête. Si P_S projette sur les entrées modifiées,
`||(O'-O)|psi>|| <= 2||P_S|psi>||`.
Le télescopage de la succession d'opérateurs, en utilisant les états du
jeu frais et les continuations modifiées, donne la somme de ces normes.
Cette méthode permet des choix adaptatifs après une réponse : elle ne
suppose pas un posterior uniforme des noms dans le jeu réel.

Dans les états du jeu frais, la masse moyenne des entrées KG modifiées est
au plus 1/M ; celle de N est au plus 2/M, quel que soit le nombre de nonces
considérés dans la requête. Cauchy–Schwarz/Jensen et la contraction par la
mesure finale donnent alors, pour les nombres g et n de requêtes du
**distingueur CPA et de sa simulation**,

`Delta_noise,Q <= min(1, 1/M + 2*g/sqrt(M) + 2*n*sqrt(2/M))`.

Pour 256 bits, le majorant rationnel plus simple
`min(1,1/M+(2*g+4*n)/2^128)` convient aussi. Le calculateur utilise un
intervalle dyadique majorant chaque racine par des comparaisons entières.
Aucune mesure des registres de requête de l'adversaire n'est insérée.

Le télescopage est de la famille des hybrides de normes de
[Bennett–Bernstein–Brassard–Vazirani](https://arxiv.org/abs/quant-ph/9701001),
section 3.1. Le couplage et les deux lignes de bruit sont explicités ici
pour R1. La borne est conservatrice ; un terme en q²/M plus favorable
n'est pas substitué sans une preuve adaptée au jeu exact.

Cette extension concerne un défi CPA, des oracles idéaux et des graines
cachées sans fuite. Elle n'est pas une conclusion automatique pour la
dérivation adaptative des coins du KEM ni pour SHAKE fixé.

## 5. Composition CPA désormais exprimée par deux hypothèses explicites

Notons epsilon6 et epsilon7 les avantages des deux distingueurs MLWE
classiques ou quantiques **aux ressources de nos réductions**. Avec a=0
pour l'initialisation QROM ci-dessus, les raccords donnent

`CPA_bias_seeded <= min(1/2, epsilon6+epsilon7+Delta_noise+4*Delta_matrix)`.

En ROM, Delta_noise est le comptage exact M09
`1-(M-g)(M-n)(M-n-1)/M^3`. En QROM, c'est le majorant de normes précédent.
Delta_matrix contient l'abandon borné et, uniquement dans le cas classique
prévu, la probabilité de requête avant exposition de rho.

Cette formule remplace l'inconnue générale « PKE à graines » par deux
hypothèses décisionnelles et des coûts d'expansion explicités. Elle ne
fournit pas epsilon6/epsilon7 à partir d'une sortie BKZ. La relation entre
temps, mémoire, probabilités et hypothèse de difficulté doit être énoncée
et examinée avant toute cote globale de sécurité.

Pour un inverseur de message, classique ou quantique, la conversion
normalisée est `OW <= min(1,2*CPA_bias+1/M)`. Le facteur deux est conservé.
La simple devinette d'un message impose déjà une probabilité 1/M à la
meilleure borne OW uniforme sur tous les adversaires.

## 6. Voie FO classique : simulation et carte de ressources comptée

Le registre conservateur M05 est conservé :

`CCA_ROM <= min(1/2,6*CPA_bias+(2*QRO+D)*delta_RO+3*QRO/M)`
avec `QRO=2*g512+j256+3*D+2`.

Le coefficient six reste la marge de normalisation documentée par M05.
Il n'est pas attribué comme constante littérale au tableau HHK. Le lecteur
M10 charge en plus une borne J classique `qJ/M` lorsque D>0, zéro lorsque
D=0, pour conserver séparément le remplacement du rejet par une fonction
indexée idéale. Cette charge supplémentaire est prudente et n'est pas
présentée comme un resserrement des résultats historiques.

La source originale HHK 2017, son erratum primaire indexé de 2021 et la
thèse Hövelmanns citée dans M05 ont été confrontés. Le miroir demandé pour
le texte corrigé retourne les mêmes octets que la version **2017** déjà
conservée ; il n'est pas rebaptisé « texte corrigé intégral relu ».
L'erratum 2021 ajoute la rigidité et corrige les comptes des théorèmes
intermédiaires, tout en déclarant inchangé le tableau global ROM.
[HHK](https://eprint.iacr.org/2017/604),
[thèse](https://doi.org/10.13154/294-7758).

### Simulateur effectivement compté

Après remplacement du rejet indexé par une fonction aléatoire indépendante,
le simulateur classique garde trois listes : F pour les coins déjà donnés,
K pour les messages déjà interrogés et L pour les clés déjà attribuées aux
chiffrés. À une nouvelle requête de clé pour m, il calcule une seule fois
`Enc_F(m)`. Si ce chiffré est déjà dans L, il réutilise sa clé ; sinon il
en choisit une nouvelle. Une décapsulation hors défi lit ou crée simplement
L[c]. Une nouvelle requête de message qui produit le chiffré défi arrête
le simulateur avec le candidat à extraire.

Sur une exécution sans erreur de correction pertinente, la rigidité relie
les réponses de ce simulateur à celles du KEM. Les réponses avant/après une
requête de clé sont cohérentes, même lorsque la décapsulation est demandée
la première. Une collision de deux messages au même chiffré exige en
revanche un échec de correction pour au moins l'un d'eux. Le témoin fini
non injectif le montre : deux clés réelles indépendantes sont égales avec
probabilité 1/2, alors que le simulateur par chiffré les égale toujours.
Le terme de correction est donc nécessaire ; les contrôles finis ne
permettent pas de le supprimer.

Dans la seconde étape HHK, les deux branches CPA réemploient cette même
simulation : C exploite la sortie d'un inverseur et D détecte lequel de
deux messages uniformes a été interrogé à F. Le reste du message uniforme
non défi reste indépendant de la vue. Les deux conversions donnent
respectivement `OW<=2*CPA_bias+1/M` et
`Pr[QUERY]<=2*CPA_bias+2*qF/M`. Cela rétablit un coefficient quatre pour
la somme des deux avantages CPA en biais. M10 conserve la marge six ;
elle est une majoration locale explicite et non une nouvelle constante
attribuée littéralement à HHK.

Posons g=g512, j=j256, a=qSHAKE128, h=qSHA3_256 et D le nombre de
décapsulations. Un appel G512 au contexte de la clé rend **les deux**
coordonnées F et K. Les coins de ce message sont donc déjà en cache quand
sa clé est traitée. Chaque branche CPA respecte l'enveloppe suivante :

| Ressource du distingueur CPA | Majoration |
|---|---:|
| Chiffrements publics Enc_F | g |
| Chiffrements publics et formation du défi MLWE | g+1 |
| Demandes à F, répétitions conservées | 2g+1 |
| Requêtes distinctes à F, défi inclus | g+1 |
| Appels au domaine KG auxiliaire | g |
| Appels au domaine N auxiliaire | j+13g |
| Lectures de cellules de A | a+36g |
| Hash de contexte de clé publique | h+1 |
| Comparaisons de tuples des listes FO | (4g+2D+4)^2 |

Les facteurs 13 et36 sont ceux des opérations publiques R1. La réduction
à temps borné réemploie la matrice A déjà reçue de son défi et prépare
les flots conditionnels sous le cap512 et l'écart d'abandon du §3. Elle
chiffre ensuite avec **A précalculée** ; elle ne prétend pas que la boucle
`uniform()` du moteur a un pire cas idéal fini. Le plafond a+36g est une
enveloppe de lectures, non une obligation de refaire ce travail à chaque
appel. Le hash du contexte de la même clé peut être calculé une fois.
Le plafond g+1 de F compte ses
adresses distinctes ; le lecteur conserve aussi le plafond 2g+1 de toutes
ses demandes afin de ne pas faire disparaître les répétitions de travail.

Le passage CPA à bruits frais remplace **les bruits de la clé honnête et
du seul défi**. Il ne réécrit pas les calculs publics du simulateur en un
FO à grande graine : ses Enc_F connus continuent d'interroger le même N
auxiliaire, et leurs 13g appels sont payés dans le couplage M09/M10.

Le payload des listes est majoré par `64g` pour la liste de messages,
`2688(g+D)` pour la liste de chiffrés et `64(g+1)` pour celle des coins,
plus les 64 octets de messages CPA et 2688 octets du défi. S'ajoutent
l'état de l'adversaire, la représentation des listes, les tables des
oracles auxiliaires et leurs entrées/sorties. Ces nombres ne sont pas une
mesure de RSS ou une borne totale de mémoire du moteur.

Avec C=(4g+2D+4)^2, une enveloppe de temps explicite s'écrit
`T_B <= T_A+(g+1)*T_Enc_given_A_bound+C*Cmp_2656+T_setup_A+T_tables_aux(Q,I,B)` :
T_Enc_given_A_bound couvre le chiffrement public et la formation du défi
avec A déjà connue. T_setup_A paie les préfixes sous cap512 ; son abandon
est déjà compté dans les quatre écarts de matrice du §5. Cmp_2656 couvre
une comparaison d'au plus 2656 octets, I les longueurs d'entrée et B les
octets de préfixes demandés. Une simulation classique par listes
linéaires des oracles auxiliaires paie ses comparaisons et ses nouveaux
octets ; ils ne sont pas des appels physiques à Keccak gratuits. La
calibration de ces unités vers les modèles d'attaque reste une obligation.

### Registre classique M10 avec substitution de la carte

Pour éviter toute finesse de comptage implicite au bord du défi,
le nouveau registre arrondit les coefficients de correction et de
devinette à `8*(g+j+D+1)`. Cela couvre notamment les évaluations F du
défi et des contrôles de correction intermédiaires, en plus du budget
de requêtes distinctes de la simulation. Si
`epsilonCPA = epsilon6+epsilon7+Delta_noise(g,j+13g)+4*Delta_matrix`,
le registre classique conservateur est

`CCA_ROM <= min(1/2, 6*epsilonCPA +8*(g+j+D+1)*delta_RO`
`                         +8*(g+j+D+1)/M +epsilonJ)`.

Il s'agit d'un **nouveau comptage** de la route par listes U_m, pas d'une
majoration terme à terme du vieux 3*QRO : celui-ci avait notamment 9D/M
dans la devinette, contre 8D/M ici. La validité du nouveau coefficient
repose sur son propre décompte ci-dessous, et non sur une comparaison
numérique avec l'ancien registre.

Le code `rom_cca_counted` substitue effectivement g et j+13g dans le
couplage ; il ne laisse plus le budget CPA identique au budget CCA par
simple convention. Les coûts de chaque branche sont majorés par la même
enveloppe maximale, sans additionner toutes les exécutions des hybrides.
Le simulateur et ses compteurs sont dans `m10_security_resources.py`.

Le facteur N*delta ne suppose pas une indépendance des messages choisis
après observation des réponses. Pour une clé kappa et les oracles de base
Psi fixés, M05 fournit l'enveloppe **pointwise** beta(kappa,Psi) valable
pour chaque message, avec moyenne au plus delta_RO. Son témoin est
`b_(kappa,Psi)(r)=1[il existe i : |B_i(r)|>=1800]`, indépendant du message,
et beta est sa moyenne sur la graine r. Ce témoin reste fixé quand N a
déjà été interrogé : conditionner tout Psi conserve justement ces réponses.
À la première
introduction de chaque point F(m), ses coins sont uniformes indépendants
des choix antérieurs conditionnellement à kappa/Psi ; l'échec correspondant
a donc probabilité au plus beta. Un point F déjà introduit n'ajoute pas
une chance indépendante : son événement d'échec a été chargé lors de la
première introduction. La première introduction honnête du point défi est
elle aussi comptée, avant que le défi puisse en révéler de l'information.

Il faut compter **tous** les points examinés, y compris ceux abandonnés
pendant une recherche et ceux introduits par les contrôles des jeux.
Dans la composition des listes HHK, le moniteur de correction du premier
étage a au plus `g+2*(g+D)+1` introductions : g directes et deux par
contrôle de clé/décapsulation, plus le défi. L'étage OW-vers-CPA ajoute
au plus g+1 points pour sa propre borne. Leur somme `4g+2D+2` est couverte
par le coefficient arrondi `8*(g+j+D+1)`. Le nombre g+1 du tableau de
ressources concerne la branche CPA effectivement exécutée ; il ne remplace
pas le nombre plus large des points du moniteur dans les jeux de preuve.

On applique l'union conditionnellement à kappa/Psi, puis la moyenne de
beta. Cela conserve l'ordre des quantificateurs. Un contrôle fini ajoute
32 politiques adaptatives et 288 tables. Deux points F examinés donnent
une probabilité 5/9 de trouver un échec dans son témoin, supérieure au
majorant 1/3 qu'on obtiendrait en ne comptant que le message finalement
retenu. Un second témoin explique pourquoi la moyenne d'un message fixe
sur les clés ne remplace pas le maximum pointwise avant la moyenne.

Cette carte classique ferme le manque de comptage des appels et payloads
dans le modèle retenu. Elle ne transforme pas epsilon6/epsilon7 en chiffres
certifiés, ni les opérations abstraites du simulateur en portes physiques.
Les exemples qui leur attribuent 2^-200 sont explicitement hypothétiques.

## 7. Voie QROM applicable : Ge–Yang–Yu–Yu, théorème 22

La figure 7 et le théorème 22 du texte primaire
[Ge–Yang–Yu–Yu, 2025/1641](https://eprint.iacr.org/2025/1641), p.15–16 et96–97,
portent bien sur le KEM avec clé issue du message et rejet implicite utilisé
par R1. Les transformations ACWC du même article ne sont pas ajoutées.
Avec les budgets cohérents conservateurs de M05,

`QF=QK=2*g512+D+1`,

on conserve la composition conditionnelle

`CCA_QROM <= min(1/2, epsilonJ + 2*(QF+QK)*sqrt(epsilonOW)`
`                         +16*(QF+1)^2*delta_RO)`.

Le nouveau raccord CPA peut majorer epsilonOW par la conversion précédente,
avec les avantages Q-MLWE et les vrais budgets des réductions. Le rejet a
la borne idéale M06 `epsilonJ<=min(1,2*qJ/2^128)` pour D>0. Les hypothèses
sur z, les accès indexés classiques et les accès publics quantiques restent
nécessaires. La correction delta_RO garde sa population : moyenne sur les
oracles et clés honnêtes du pire message ; elle n'est pas uniforme sur
chaque clé privée importée ni sur chaque SHAKE fixé.

Le majorant OW de cette voie est lâche. Pour le diagnostic historique
`g512=j256=D=2^64` et cible de biais `2^-128`, le seul plancher
`2*(QF+QK)*sqrt(1/M)` dépasse déjà la cible, indépendamment des estimations
de réseaux. Le calcul entier vérifie cette obstruction. Cela réfute la
certification de **cette cible par ce registre**, pas la sécurité réelle
du moteur et pas l'existence d'une réduction meilleure.

## 8. Recherche réelle d'une voie QROM plus serrée

Le texte complet [Ge–Liao–Xue, MRE, 2024/777](https://eprint.iacr.org/2024/777)
a été récupéré et ses p.23–28,43–54 relues. Son corollaire 1 traite le KEM
implicite avec clé `G(m,c)` et donne un terme **linéaire** en avantage CPA.
L'hypothèse d'injectivité globale de certaines voies antérieures n'y est
pas requise. Il ne faut toutefois pas employer sa voie OW qui suppose un
algorithme de récupération unique des coins : celui-ci n'est pas établi
pour le PKE R1 à graines.

Le théorème 5 de [Bindel–Hamburg–Hövelmanns–Hülsing–Persichetti, 2019/590](https://eprint.iacr.org/2019/590),
p.15–16, relie les clés issues de m et de (m,c) pour un chiffrement
déterministe. Pour R1 ce chiffrement est `Enc_F(m)=Enc(pk,m;F(m))`,
avec vérification du chiffré entier. On peut simuler l'oracle de clé
message par l'oracle de paire évalué à `(m,Enc_F(m))`.

Cette équivalence n'est pas gratuite en requêtes quantiques. Il faut
calculer F et Enc_F, appeler l'oracle de clé, puis désévaluer les
temporaires. Notre pont explicite de namespace utilise au plus deux
appels à chaque coordonnée et à l'oracle auxiliaire par requête publique.
Pour le pont de graphe, il ajoute un chiffrement cohérent et son inverse,
avec leurs appels à N/A. Les 1536 cas de base vérifient le mécanisme
compute/copy/uncompute et le retour du registre de travail à zéro.

Après ce pont, le corollaire MRE pour profondeurs dH,dG, largeur w,
qH=dH*w et qG=dG*w, a le registre suivant :

`epsilonJ +2*sqrt(dG)*(7*dG+dH+3)*epsilonCPA`
` +16*(2*qH+2*qG+1)^2*delta_RO +4*sqrt(dG)*delta_RO`
` +16*sqrt(dG)*(8*qG+2*qH+1)/M`.

Les racines sont encadrées rationnellement. Le calculateur expose cette
voie séparément avec `directly_resource_qualified_for_R1=false` : la
carte complète des appels N/KG/A, des lectures XOF, des circuits inverses,
des fonctions suffisamment indépendantes et de l'espace réversible reste
à instancier. La remarque 5 MRE signale notamment un espace quantique
linéaire en temps lors de l'unitarisation ; cette ressource compte dans
notre comparaison même si les auteurs ne la prennent pas comme métrique
dominante. La complexité asymptotique `O(q²)` du simulateur n'est pas
convertie en un nombre concret de portes ou en RAM sans construction.

Cette voie est une piste **applicable à examiner**, avec un avantage CPA
plus favorable que la racine OW, et non un gain numérique déjà acquis pour
le KEM. Son terme de devinette connu peut aussi épuiser certaines cibles
de biais à grands budgets. Une cible de biais après q requêtes est
distincte d'un facteur de travail `Time/Adv` ; les diagnostics ne mélangent
pas ces deux objectifs.

Le PDF complet [Chen et al., 2026/468](https://eprint.iacr.org/2026/468),
révision 15 septembre, a également été récupéré et ses figures 3–4,
définitions et théorèmes ROM examinés. FOAC'0 ajoute un second composant
de chiffré ; FOAC' organise un message en deux parties et le reconstruit
autrement. R1 ne suit aucune de ces deux constructions. Leurs nouvelles
pertes ne sont donc pas importées. Une adoption exigerait une nouvelle
construction identifiée, ses formats et toutes ses analyses.

## 9. Pourquoi l'oracle idéal ne se transforme pas en preuve de SHAKE fixe

Pour une fonction déterministe fixée, une graine de 256 bits atteint au
plus 2^256 matrices. La loi uniforme entière en comporte `7681^9216`.
La distance statistique est donc au moins
`1-2^256/7681^9216`, strictement supérieure à `1-2^-110336`.
Le calcul entier contrôle cette inégalité. Le support réduit est une
obstruction à une affirmation **statistique** de matrice uniforme pour
SHAKE fixé ; il ne fournit pas un distingueur efficace.

Le passage concret repose sur une hypothèse calculatoire définie et
examinée, avec ses budgets, ou sur un modèle de primitive explicitement
adopté. Il ne demande pas une preuve absolue de sécurité de Keccak, mais
il ne peut pas être remplacé par « SHAKE a l'air aléatoire ». Les marges
du ROM/QROM et les résultats d'implémentation restent attachés à leur modèle.

## 10. Contrôles nouveaux, reproduction et décision C01

Les contrôles indépendants finis donnent :

- 40 panneaux et **203360 préfixes transformés**, confrontés à la loi
  conditionnelle calculée autrement ; leur mélange uniforme est exact ;
- 63 panneaux et **49149 flots de candidats**, énumérés pour retrouver
  les queues binomiales de terminaison ;
- 5056 panneaux et **40320 paires oracle/circuit quantique**, amplitudes
  entières avec facteur de normalisation exact, pour les hybrides à une
  ou deux adresses cachées ; aucune mesure de requête ajoutée ;
- 1536 cas de base du pont contrôlé à deux appels ;
- 781 panneaux et **6248 bandes aléatoires** des transcriptions vraies et
  simulées du KEM réduit injectif, avec répétitions et ordres inversés,
  accompagnés d'un contre-exemple non injectif et des plafonds de compteurs ;
- 32 politiques adaptatives et 288 tables de coins pour le comptage de
  tous les points F, y compris les recherches abandonnées et les choix
  dépendant de la clé ;
- sept plafonds de rejet R1, exemples ROM/QROM, intervalles entiers des
  racines et diagnostics de bornes non certifiantes.

Ces modèles finis ne couvrent pas tous les adversaires. La preuve générale
est l'argument mathématique décrit plus haut ; elle n'a pas été formalisée
dans un assistant de preuve. Les tests refusent notamment une conclusion
C01 falsifiée même avec un hash du rapport recalculé, un prétraitement
quantique traité comme classique et un ancien helper de test présenté
comme le code de production.

```powershell
.tools/research-venv/Scripts/python.exe -B -m unittest discover -s research -p test_m10_security.py -v
.tools/research-venv/Scripts/python.exe -B research/m10_security.py verify --output results/security/m10-001
```

Le résultat scientifique de cette tranche comporte donc de nouveaux
raccords CPA, un traitement explicite de leur extension quantique et une
analyse de deux compositions FO applicables ou conditionnelles. Les
obligations scientifiques restant à résoudre pour fermer C01 sont les
suivantes :

1. calibration concrète des deux avantages MLWE aux ressources de réduction,
   avec la cible, mémoire, parallélisme et nombre de cibles déclarés ;
2. instanciation du circuit et des appels auxiliaires des réductions QROM,
   notamment du pont de graphe MRE, et vérification d'une marge utilisable ;
3. hypothèses calculatoires clairement assumées et examinées pour les
   fonctions SHA3/SHAKE concrètes.

La revue cryptographique indépendante constitue une étape d'évaluation
distincte, différée par l'utilisateur. Elle apporte un examen externe de
l'argument et de ses hypothèses ; sa réalisation n'est pas une condition
mathématique de la preuve.

**Aucun gel cryptographique final, niveau global en bits, audit externe ou
fermeture C01 n'est déclaré.** Le maintien de R1 comme moteur de recherche
peut être décidé séparément. Les fonctions arithmétiques, les paramètres,
formats et domaines ne sont pas modifiés par cette étude.

## Sources et versions effectivement examinées

Les SHA-256, voies de récupération et échecs sont enregistrés dans
`source-anchors.json` de la capsule. Les PDF ne sont pas redistribués.
Une copie de miroir est distinguée de la notice primaire et sa date ne
vaut pas validation de notre travail.

| Source | Version et parties lues | Usage limité ici |
|---|---|---|
| CHIC | Copie du dépôt institutionnel, 39 pages, appendice C p.38–39 | Idée d'inversion du rejet ; loi R1 recalculée |
| BBBV | arXiv quant-ph/9701001v1, §3.1 p.7–8 | Hybride de normes, dérivé explicitement pour les noms R1 |
| HHK | Copie 2017 SHA identique à M05 ; erratum primaire 2021 indexé | Registre conservateur et rigidité ; aucune nouvelle lecture du PDF corrigé prétendue |
| Hövelmanns | Thèse 2021, copie identifiée dans M05 | Conventions et comptes classiques, avec réserve de normalisation conservée |
| GYY | Copie 30 septembre 2025 SHA identique à M05, fig.7 et théorème22 | Transformation implicite effectivement utilisée |
| MRE | Notice primaire révisée 25 mai 2024 ; copie de miroir p.23–28,43–54 | Voie IND-CPA sans racine, ressources de raccord encore ouvertes |
| BHHP | Copie de miroir, théorème5 p.15–16 | Équivalence de clés et son circuit de graphe |
| Chen et al. | Copie 15 septembre 2026, fig.3–4 et p.10–16 | Inapplicabilité directe des nouvelles constructions FOAC' à R1 |
| AHU | Notice/erratum primaire 9 décembre 2021 et copie de miroir 18 février2019 distinctes | Les théorèmes O2H centraux sont distingués de l'appendice FO corrigé ; aucune preuve FO de l'ancienne annexe n'est importée |
