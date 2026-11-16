# M09 — Un hybride classique pour les bruits à graines de R1

16 novembre 2026. Ce chantier fait progresser un sous-terme de C01 : le
remplacement des bruits expansés par des bruits CBD frais **dans un jeu CPA
classique avec oracles idéaux**. Le résultat conserve la matrice publique
issue de rho. Il ne ferme ni la sécurité du PKE ainsi obtenu, ni le QROM,
ni la substitution par Keccak concret, ni C01 dans son ensemble.

Le programme `research/m09_security_noise.py` calcule la perte exactement.
La capsule `results/security/m09-001` conserve calculateur, tests, document,
rapport et source M08 examinée. Le contrat de référence est
`dev_kem.rs` SHA-256
`b39c2fdfcdd7c22634162a2c451213a6c4309b27524a82069f37903653e12334`,
avec douze ancrages littéraux. Les réalisations ultérieures doivent conserver
ces domaines, tailles, distributions et nonces pour bénéficier de l'argument;
ce document ne certifie pas leurs octets machine.

## 1. Deux expériences précisément séparées

Le jeu réel idéalisé considère une clé honnête et **un défi IND-CPA du PKE**.
Il ne s'agit pas directement du jeu KEM avec message caché et coins FO :
le passage à ce jeu dépend encore du théorème de transformation et de ses
ressources. Les trois graines d, sigma et rseed ont 256 bits. On pose M=2^256.

- KG est une fonction idéale indépendante, sur le domaine R1 `KG`, dont
  `KG(d,6)` fournit rho et sigma, deux chaînes indépendantes de 32 octets.
- N est un oracle idéal indépendant sur le domaine R1 `N`. À chaque couple
  `(seed[32],nonce[1])`, son préfixe de 192 octets est uniforme. Les douze
  appels de génération utilisent sigma et les nonces 0..11; les treize
  appels de chiffrement utilisent rseed frais uniforme et les nonces 0..12.
- La matrice reste calculée à partir de rho par le domaine A. Les autres
  oracles publics sont indépendants de KG/N dans cette idéalisation.
- L'adversaire dispose d'accès **classiques** aux oracles. Aucun accès à la
  clé privée, aux graines cachées ou à une fuite les concernant n'est permis.
  Les ressources de toute exécution locale du chiffrement public sont comptées.

Dans le jeu frais, rho est uniforme; les bits donnant les douze et treize
polynômes CBD sont tirés indépendamment. Les oracles publics KG et N sont
indépendants de ces tirages. La clé publique et le chiffré sont calculés
avec les mêmes opérations R1 et la même matrice à graine publique.
Ce jeu n'est donc pas automatiquement le PKE à matrice uniforme entière
du raisonnement MLWE à deux hybrides de M04.

## 2. Couplage et perte

Dans le jeu frais, on ajoute trois **noms latents inutilisés** d, sigma et
rseed, indépendants et uniformes. La génération de t et du chiffré dépend
des bits CBD frais, pas de ces noms. Ces noms restent donc indépendants du
transcript observable complet de ce jeu, même quand les requêtes dépendent
de t, du chiffré, des messages choisis et des réponses d'oracle antérieures.

On définit les ensembles des d distincts interrogés au domaine KG avec le
rang six, et des graines distinctes interrogées au domaine N, tous nonces
confondus. Compter tous les nonces est conservateur : une requête à un nonce
inutilisé est aussi comptée. Toute requête à un préfixe pertinent de sortie
de N est incluse. Les budgets q_KG et q_N portent sur **le distingueur du
PKE et sa simulation**, pas automatiquement sur l'adversaire CCA initial.

Le mauvais événement est la réunion de :

1. d appartient à l'ensemble des entrées KG interrogées;
2. sigma ou rseed appartient à l'ensemble des graines N interrogées;
3. sigma=rseed.

Conditionnons sur un transcript du jeu frais, avec g entrées KG distinctes
et n graines N distinctes. Les noms étant encore uniformes indépendants,
le nombre de triplets bons est `(M-g)(M-n)(M-n-1)` sur M^3. Pour des
majorants q_KG/q_N, plafonnés à M, la probabilité mauvaise est donc au plus

`b = 1 - (1-g/M) * (M-n)*(M-n-1)/M^2`.

Elle est au plus `min(1,(q_KG+2*q_N+1)/M)`. Même sans requête publique, la
collision entre les deux graines de bruit est chargée par b=1/M : elle
ne produit pas des bruits indépendants dans le jeu réel.

Pour le couplage, on programme KG au point d avec les rho/sigma choisis et
N aux deux graines distinctes avec les chaînes uniformes utilisées pour
les bits CBD frais. Ces valeurs ont les bonnes lois d'oracles. Hors mauvais
événement, aucun adversaire classique n'observe ces points et les deux
transcripts sont identiques. Jusqu'au premier point interrogé, les parcours
adaptatifs coïncident; après celui-ci, le mauvais événement est déjà chargé.
La branche sigma=rseed est chargée avant d'exiger la programmation de deux
valeurs potentiellement différentes à une même adresse.

**On ne suppose pas un posterior uniforme des graines dans le jeu réel.**
L'indépendance est celle des noms inutilisés dans le jeu frais; le couplage
compare ensuite les deux expériences. Si les graines sont révélées ou si
une information corrélée est fournie, cet argument ne s'applique plus.

Avec la convention de biais `|Pr[gagner]-1/2|`, cela donne le sous-lemme

`epsilon_CPA_seeded <= epsilon_CPA_frais,même_matrice_seed + b`.

Le simulateur du jeu frais transmet la clé et le défi de son PKE frais et
simule les oracles publics par tables paresseuses. Il n'a pas besoin de
connaître les bruits du défi pour cette simulation. La programmation sert
au couplage mathématique, pas à extraire ces bruits depuis le défi. Les
tables, appels et octets produits restent des ressources de la réduction.
Le couplage concerne 25 sorties N de 192 octets (4800 octets) et une sortie
KG de 64 octets; ce compte n'inclut pas les requêtes publiques de l'adversaire.

## 3. Utilisation limitée dans le registre ROM de M05

Sous les conditions et normalisations déjà explicitées par M05, son
registre conservateur peut être réécrit formellement comme

`Adv_CCA <= min(1/2, 6*epsilon_CPA_frais + 6*b + terme_correction + terme_devinette)`.

Les budgets de b doivent alors être ceux du **distingueur CPA obtenu par
la réduction FO**. Leur correspondance complète avec les requêtes CCA
initiales demeure à établir. Aucun budget n'est transféré implicitement
et aucune sortie BKZ n'est substituée à epsilon_CPA_frais.

Le calculateur prend un terme additif déjà justifié et renvoie l'obligation
exacte sur epsilon_CPA_frais. Il conserve les cas non certifiés. À titre de
diagnostic du sous-terme seul, pour q_KG=q_N=q et coefficient six, les plus
grands q satisfaisant `6*b <= cible` sont :

| Cible de biais | Maximum q du distingueur CPA pour ce seul sous-terme |
|---|---:|
| 2^-128 | 18904575940052136859076367079542678413 |
| 2^-192 | 1024819115206086200 |
| 2^-224 | 238609293 |
| 2^-256 | Aucun, même q=0, avec ce coefficient et cette borne |

Ces limites sont vérifiées par fractions exactes et recherche entière;
le point q+1 échoue à chaque limite finie. Elles allouent toute la cible au
sous-terme : elles ne sont pas les limites de requêtes du KEM complet.
L'échec de certification à 2^-256 ne démontre aucune attaque correspondante.

## 4. Pourquoi cela ne fournit pas une substitution statistique concrète

Une fonction fixe déterministe de 256 bits ne peut produire qu'au plus
2^256 vecteurs. Le vecteur des douze polynômes de génération contient
3072 coefficients CBD(3). Par énumération des 64 configurations de six
bits, la masse maximale d'un coefficient vaut 20/64=5/16. La masse de toute
image de taille au plus 2^256 dans la loi CBD indépendante est donc au plus
`2^256*(5/16)^3072`. La distance statistique à cette loi est au moins
`1 - 2^256*(5/16)^3072`, et cette borne dépasse `1-2^-4898`.

Ce constat de support ne construit aucun distingueur efficace contre
SHAKE. Il explique pourquoi une substitution doit s'appuyer sur un modèle
d'oracle ou une hypothèse calculatoire, et pourquoi un résultat moyenné sur
les oracles ne s'affirme pas pour chaque fonction Keccak fixée.

## 5. Contre-vérifications et reproduction

Les 380 panneaux finis sur alphabets de taille 2..9 comptent littéralement
153512 triplets de noms et retrouvent la formule. Les tests supplémentaires
énumèrent 512 transcripts adaptatifs d'oracles binaires, puis leurs noms
cachés; ils contrôlent aussi saturation, collisions, monotonie, limite
exacte de ressources et rejet des paramètres mal formés. Ces énumérations
contrôlent le comptage et des cas finis, pas tous les adversaires ni une
preuve formalisée dans un assistant de preuve.

Un test du dépôt actif appelle aussi le pont de réalisation M09 : les
tailles fixes des vues de graines, domaines, bits CBD et calendriers de
nonces restent reliés aux contrats R1. Ce contrôle lexical de fragments
revus ne prouve pas la sémantique générale de Rust ni le temps constant.
La capsule mathématique conserve séparément son contrat de référence M08.

```powershell
.tools/research-venv/Scripts/python.exe -B research/m09_security_noise.py verify --output results/security/m09-001
.tools/research-venv/Scripts/python.exe -B -m unittest discover -s research -p test_m09_security_noise.py -v
```

La vérification de capsule contrôle inventaire et empreintes, puis
recalcule le rapport sans réseau, compilateur, estimateur ou moteur Rust.
Les tests altèrent une copie temporaire pour vérifier le refus d'une
conclusion C01 falsifiée, y compris avec une empreinte du rapport mise à jour.

## 6. Veille primaire ciblée au 16 novembre 2026

Cette recherche ne constitue pas une revue exhaustive de toutes les
publications. Les références déjà recensées ne deviennent pas de nouvelles
attaques exécutées. Les gains d'autres paramètres ne sont pas soustraits
des estimations R1.

| Source et état lu | Conséquence pour R1 |
|---|---|
| [Ogilvie, 2026/279](https://eprint.iacr.org/2026/279), notice primaire révisée le 4 octobre; fusion CRYPTO 2026 avec [Hou–Jiang, 2026/366](https://eprint.iacr.org/2026/366), révision du 30 août et correction signalée du théorème 3.1 | Déjà recensés. Maintenir la distinction MLWE/plongement LWE; les rotations concernent le degré 256. Aucun facteur forfaitaire appliqué au rang six. |
| [Ling–Yan–Zhao, 2026/979](https://eprint.iacr.org/2026/979), notice primaire, dernière révision indiquée le 26 mai; [arXiv v1](https://arxiv.org/abs/2605.24798v1), 24 mai | Déjà recensé. Le sampler QRS suppose un accès cohérent spécifique; le présent lemme classique ne le simule pas et ne fournit aucune nouvelle estimation R1 quantique. |
| [Bashiri, 2026/2565](https://eprint.iacr.org/2026/2565), reçu le 20 octobre, approuvé le 21; notice primaire consultée | Le dual prouvable conserve une hypothèse pour la matrice structurée ML-KEM. Distinguer son coût prouvable du meilleur coût heuristique; pas d'exécution ou de coût R1 nouveau ici. |
| [Chen et al., 2026/468](https://eprint.iacr.org/2026/468), révision du 15 septembre, notice annonçant l'acceptation ASIACRYPT 2026 | Les transformations FOAC' annoncées diffèrent de leur cadre antérieur. Leurs meilleures pertes ne sont pas importées dans R1 sur la base du titre ou du résumé; examen de la construction et des théorèmes requis avant substitution. |

Un signalement de `2026/2873`, relatif à LWE avec indices de fuite et daté
du 12 novembre dans un miroir, a aussi été repéré. L'accès primaire
`https://eprint.iacr.org/2026/2873` et son PDF a échoué pendant cette revue
(HTTP 403 confirmé par une seconde voie). Il demeure **à vérifier sur une
source primaire**; aucun chiffre, gain ni conclusion cryptanalytique n'en
est intégré ici. Une attaque avec indices de fuite ne doit de toute façon
pas être assimilée au jeu sans fuite du lemme.

La suite de C01 demeure précise : relier la matrice à graine et les
ressources au PKE frais, établir la carte de ressources FO classique,
traiter séparément l'OW/QROM avec programmation quantique appropriée,
puis justifier les remplacements de primitives concrètes et faire relire
l'ensemble indépendamment. Les paramètres R1 ne changent pas dans ce chantier.
