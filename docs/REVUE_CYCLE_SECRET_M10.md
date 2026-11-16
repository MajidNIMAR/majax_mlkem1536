# M10 — durcissement du cycle des secrets sur PC

16 novembre 2026. Cette revue interne suit le [protocole M10](PROTOCOLE_M10.md).
Le profil `KEM1536-DEV-Q7681-R1`, les formats, les domaines et les résultats
déterministes sont conservés. Les cibles sont Windows GNU x86-64 et Linux
GNU x86-64, CLI et consommateur à fonctionnalités par défaut. Android et
Messenger restent différés. Une revue interne de code ou de quatre images
ne constitue pas un audit externe ni une garantie universelle de temps
constant ou d'effacement.

## Référence et constat motivant le changement

La référence prépatch est capturée dans `artifacts/generated/m10-baseline-001` :
56 fichiers, manifeste source SHA-256
`fea4458893be1e7f84e42d58da22c3740363a015103917fb0828603f902925ce`.
Les sources et images M09 demeurent intactes. Le constat ci-dessous complète
les limites explicites de la [revue M09](REVUE_CYCLE_SECRET_M09.md), sans
modifier ses recueils ou leurs conclusions contemporaines.

Dans la CLI Windows M09, image SHA-256
`9eb95fb2cb9a8531a216012b4cff71d6b10d1a7951285d9d3c666f8186002255`,
le `ct_select` de tableaux retournés par valeur est scalarisé. Une trace
concrète relie un octet favorable à une copie locale hors propriétaire :

| Adresse physique | Instruction | Interprétation bornée |
|---|---|---|
| `0x14004de09` | `movzbl 0x160(%rsp),%eax` | Lecture du premier octet de la dérivation G64 |
| `0x14004de4c` | `mov %rax,0x108(%rsp)` | Copie de cet octet étendu à huit octets dans une case de pile temporaire |
| `0x14004e0cc` | `or 0x108(%rsp),%rbp` | Relecture lors de la reconstruction du premier mot de la clé favorable |
| `0x14004e224` et suivantes | Écriture des mots sélectionnés | Production de la sortie ; les propriétaires source sont ensuite effacés |
| `0x14004e719` | Retour normal observé | Aucun écrasement de la case `rsp+0x108` sur ce suffixe observé |

Le corps est `decapsulate`, entrée `0x14004d670`. La source favorable G64
est sous propriétaire à `rsp+0x160`. D'autres octets sont étendus dans
d'autres cases ; des copies analogues apparaissent dans les trois autres
images M09 examinées. Ce constat porte sur la mémoire locale d'images
précises. Il ne démontre ni extraction à distance, ni exploitation de
protocole, ni comportement d'une image Android.

## Correction source et propriétaires

M10 remplace la sélection de tableaux renvoyés par valeur par une
affectation conditionnelle de la destination existante. La décapsulation
crée un seul propriétaire `Zeroizing<[u8;32]>`, y écrit la clé de rejet J,
puis appelle `assign_shared_secret_into` avec une vue `&[u8;32]` sur les
32 premiers octets de G. `CtAssign` écrit la clé favorable quand la
comparaison du chiffré complet réussit. Les propriétaires séparés `good`
et `fallback`, ainsi que le retour rempli de `ct_select`, disparaissent
de ce chemin source. Le sens du masque est testé dans les deux directions.

`derive_into` écrit les 64 octets SHA3-512 dans un propriétaire créé par
KG, Encaps ou Decaps. `Digest::finalize_into_reset` emprunte l'état et la
destination ; le digest rempli intermédiaire n'est plus créé explicitement.
`xof_into` écrit de même les 192 octets N, les 32 octets J et les attentes
du diagnostic dans des propriétaires existants. À partir de l'itération002,
sa finalisation emprunte l'état avec `finalize_xof_reset` : cet état reste
possédé et exécute son destructeur. Les anciens wrappers à
retour rempli restent limités à `test` ou `research-vectors`.

| Étape | Données et propriétaire source | Examen compilé à faire sur les images M10 |
|---|---|---|
| Entrée KeyGen/Encaps | Entropie OS dans `Zeroizing64/32` ; 98 préfixes d'erreur existants | Chemins succès/erreur et appels du fournisseur |
| Expansion KG | d emprunté ; dérivation G/KG64 détenue par l'appelant interne | Écritures directes, état SHA3 et copies ABI |
| Bruits KG/PKE | 192 octets SHAKE sous owner, sortie dans le polynôme existant | Lecture des six bits, effacement owner et état/lecteur SHAKE |
| Produits PKE | Polynômes et six transformées sous owners fixes | NTT, accumulateurs, coefficients et sauvegardes de l'appelant |
| Déchiffrement | s décodé et somme sous owners ; m écrit dans l'owner de Decaps | Remplissage et effacement message, chemins d'erreur applicables |
| Réchiffrement | Vue coins de G64, owner de rechiffré détenu par Decaps | Appels et accumulation ; comparaison du chiffré entier |
| Sélection | J32 détenu par Decaps, vue favorable G32 empruntée | Stores directs, sens du masque, branches et copies résiduelles |
| Sortie API | `SharedSecret(Zeroizing32)` retourné intentionnellement | Convention de retour et copies de l'appelant restent distinctes |
| Import/export privés | Contrôles avant nouvelle allocation ; export sous owner | Refus et ordre inchangés, octets appartenant à l'appelant exclus de l'effacement |

L'itération003 copie explicitement la sortie Decaps à partir du propriétaire
local de sélection, qui conserve ainsi son destructeur. Cette copie est
intentionnelle pour livrer la clé à l'appelant ; la source locale doit être
essuyée dans les images compilées. L'encapsulation002 examinée écrit déjà
directement les 32 octets de G dans le tuple de sortie puis essuie G64 ;
aucun propriétaire key32 local supplémentaire n'y est observé dans ce chemin.

Les destructeurs `Zeroizing` et les fonctions d'effacement des dépendances
traitent leur propre stockage. Les registres, sauvegardes ABI, états copiés
par LLVM, arrêt brutal et mémoire appartenant à l'appelant restent des
obligations distinctes. `Shake256::finalize_xof_reset` construit encore un lecteur
contenant son état de 200 octets ; à partir de002, la finalisation empruntée
conserve source et lecteur avec leur destructeur et leur effacement.
La sortie `SharedSecret` reste une valeur retournée.
Aucun passage à une allocation supplémentaire ni réécriture des primitives
n'est introduit dans cette itération.

## Raccord au certificat et premières vérifications

Le nouveau [contrat M10](../research/m10_source_contract.py) impose huit
fragments de primitive/propriétaire et cinq correspondances de consommateurs.
Il applique ensuite les contrats M09 puis historiques inchangés : 75 ancrages
pour la variante1, 77 pour la variante2 à XOF emprunté, 78 pour la variante3
à sortie copiée, contre 62/36/35/31/24/21 pour M09/M08/M07/M06/M04/M02. Ce raccord
textuel vérifie des fragments examinés ; il n'est pas un parseur Rust complet
ni une preuve formelle de programme ou de compilation.

Les fixtures des tests historiques qui supposaient le source actif M09
lisent désormais le source M09 scellé dans `qualification.tar.gz`, contrôlé
par son SHA-256 de provenance. Les assertions historiques sont conservées.
Les [tests M10](../research/test_m10_source_contract.py) lisent directement
le source actif et injectent des fautes dans le framing, les destinations,
le sens du masque, les vues, les rôles de bruit et les opérations héritées.

Première itération : 34 tests Rust par défaut et 35 avec `research-vectors`
passent, dont l'empreinte du cas0 vérifié indépendamment. Trois tests nouveaux
couvrent les deux sens de sélection et l'écriture dans une destination
préremplie ; les valeurs connues SHA3/SHAKE proviennent de Python `hashlib`.
Fmt et Clippy avec avertissements refusés passent. Dix tests Python M10,
quinze du pont historique et quatorze de l'étude M09 passent. Ces contrôles
ne remplacent ni les corpus intégraux ni la qualification du protocole M10.

## Acquisition et portée des conclusions

[m10_secret_inventory.py](../research/m10_secret_inventory.py) capture des
inventaires neufs, sources complètes et reçus de build liés aux images.
Le parseur physique M09 est réutilisé sans modification. L'index conserve
les adresses distinctes portant le même nom, les appels directs et les slots
ELF RELATIVE résolus ; les cibles indirectes non résolues restent explicites.
Le rejeu lit uniquement les données conservées et n'exécute aucun binaire,
compilateur ou objdump. Une fermeture d'appels partielle n'est pas confondue
avec tous les chemins du système ni avec une analyse de contamination secrète.
Le lecteur actif contrôle aussi les commandes et SHA-256 stdout des textes
conservés, la distinction CLI/consommateur et baseline/candidat, ainsi que
l'égalité des captures source entre les deux sortes d'image. Neuf tests
des lecteurs (quatre de liaison des commandes, cinq de revue des instructions
et du périmètre) passent. Ces contrôles ont été durcis sans réécrire les
collectes précédentes ni leurs contrôleurs scellés.

## Résultats négatifs des deux premières itérations

Les quatre images001 suppriment la reconstruction scalarisée de `good`, mais
révèlent deux autres copies. La source déplacée de l'état SHAKE n'est pas
essuyée sur le retour normal de N ; la graine32 y apparaît en clair, car
`TAG21 || N2 || seed32 || nonce1` occupe 56 octets, sous le taux136, sans
permutation lors de ces absorptions. Ce résidu préexiste aussi dans les
quatre images baseline M09 recompilées. Le lecteur et la copie consommée
ont bien leurs effacements ; l'état original déplacé n'est traité que sur
le chemin d'unwind observé. Le [lecteur des témoins](../research/m10_secret_review.py)
scelle ce constat dans `m10-secret-rejected-001`, relié aux quatre inventaires
baseline/001, sans exécution d'une image lors du rejeu.

| Image | État N original001 | Graine32 en clair001 | Retour normal001 |
|---|---|---|---|
| CLI Windows | `rsp+0x1c0` | `rsp+0x1d7..0x1f6` | `0x14004d387` |
| CLI Linux | `rsp+0x1a0` | `rsp+0x1b7..0x1d6` | `0x299afb` |
| Consommateur Windows | `rsp+0x1c0` | `rsp+0x1d7..0x1f6` | `0x140025f87` |
| Consommateur Linux | `rsp+0x1a0` | `rsp+0x1b7..0x1d6` | `0x367cb` |

Le second constat concerne la sortie Decaps001 : après affectation, deux
charges de 128 bits lisent le key32 local (`rsp+0x280` Windows, `rsp+0x260`
Linux), puis écrivent la sortie ABI. Ces 32 octets locaux ne sont pas
réécrits avant le retour normal. Ils persistent aussi dans les quatre images002.
Il s'agit d'une copie supplémentaire observée de la sortie sélectionnée ;
elle est distincte de l'ancien résidu de reconstruction de la clé favorable.

Les images002 corrigent le résidu d'état SHAKE ciblé : l'état original et
le lecteur ont chacun leurs 25 stores zéro de huit octets et leur curseur
essuyé avant retour normal ; les octets N restent sous owner effacé. Ce
retrait n'autorise pas leur promotion tant que la source locale de sortie32
reste présente.001 et002 sont donc **REJECTED_FOR_PROMOTION**, indépendamment
de leurs accords fonctionnels. Les résultats négatifs et les images sont
conservés ; aucune mesure de performances ou campagne longue de001 n'est
créditée à un candidat ultérieur.

Le helper d'affectation lui-même comporte quatre `cmovne`, quatre écritures
directes de huit octets et aucune branche conditionnelle ou appel. Il conserve
une copie en pile du masque de validité dérivé du calcul sensible. Windows
emploie aussi `push %rax`, dont la trace à cet appel est celle du comparateur
normalisé, et non un mot de clé. Ces copies du masque ne sont pas présentées
comme publiques ni comme effacées ; les registres restent une limite distincte.

## Revue compilée003 : retraits ciblés constatés

Les douze builds003 sont reliés au manifeste complet
`67084be5ab1cde058661104b16e738138db7993dec001ac39625feb830b2810d`.
Cette revue porte sur les quatre images par défaut ci-dessous ; elle ne
transfère pas ses conclusions aux images de recherche ou à une autre ABI.

| Image003 | SHA-256 |
|---|---|
| CLI Windows | `2d6aa2e5859ea1df7774e5dd1cbb35827c8e9e1feddbe9f1f72a80c1661d5468` |
| CLI Linux | `1d8c015a849f4e53f5f83b0c734a1fadb98a9ff7084e8fdce1cf3747795935f2` |
| Consommateur Windows | `5d4313826aa2b4ee6bb02719657fd8e85db70310786a708646d6b02741fd1987` |
| Consommateur Linux | `7edd21cd13fb86101f4e294920610f11c00ff5b5d515a90ed2cbb6e640c488a0` |

Les deux collectes sont `m10-candidate-cli-003` et
`m10-candidate-consumer-003`, reçus SHA-256 respectifs
`c3b2db76a390ec106b2df7cc60e28588f1ddf063e370c6576d57e667940b47ef`
et `d847feba8c270d1514349a4df7f7cdbc1b23d62f856afbeeb3744750e737db48`.
La petite revue `m10-secret-review-003` est scellée et rejouée avec statut
**BOUNDED_REVIEW_PASS**, provenance
`26f2577cf0c390f2001cd44c6fc0e7706a066b2c3a36b9fa6dd5d13a75a1397f`.
Ses contrôleurs et témoins ne recopient pas les images : ils reçoivent les
deux recueils d'inventaire, dont ils vérifient l'identité complète.

Dans N, l'état original reste à `rsp+0x30` sous Windows et `rsp+0x10` sous
Linux. La copie200 vers le lecteur est suivie d'une remise à zéro de cet
état et de son curseur. Le chemin normal contient aussi les 25 stores zéro
de huit octets et le store du curseur pour chacun des deux propriétaires,
avant retour. Dans J32, les mêmes effacements couvrent état et lecteur.
Le déplacement208 consommant observé001 n'est plus présent à ces frontières.
Les 192 octets N sont écrits dans leur propriétaire, puis essuyés.

Après copie vers la sortie Decaps, 32 stores zéro couvrent maintenant la
source locale de la clé sélectionnée. Une seconde relecture interne
indépendante du premier lecteur confirme les quatre images ; il ne s'agit
toujours pas d'une revue extérieure.

| Image003 | Début et fin des stores zéro locaux de key32 | Retour normal |
|---|---|---|
| CLI Windows | `0x14004de90` à `0x14004df88` | `0x14004e2b9` |
| Consommateur Windows | `0x140026a90` à `0x140026b88` | `0x140026eb9` |
| CLI Linux | `0x29a5ac` à `0x29a6a4` | `0x29a95e` |
| Consommateur Linux | `0x3729c` à `0x37394` | `0x3764e` |

Les 201 octets d'état SHA3 de `derive_into` sont aussi explicitement essuyés
après la finalisation empruntant la destination. Les corps complets de KG,
PKE, Decaps et imports sont conservés dans le registre de fonctions de la
revue. KG écrit sa dérivation64 dans `rsp+0x60` Windows et `rsp+0x40` Linux ;
64 stores zéro couvrent cette plage après son usage. Dans Decaps, le message
est écrit dans `rsp+0x30` Windows / `rsp+0x10` Linux, puis 32 stores zéro
le couvrent ; G64 à `rsp+0x80` / `rsp+0x60` est couvert par 64 stores zéro.
Ces observations valent pour les quatre images et leur suffixe normal,
sans généralisation à tout déroulement exceptionnel.

Encaps écrit les 32 premiers octets de G64 directement dans le tuple de
sortie et efface ensuite G64. Les invariants scalaires de transform M09
passent sur les quatre images003 : six stores de frame liés aux pointeurs,
compteurs et twiddle publics ; aucune instruction SIMD ou division dans
cette fonction. Le cœur polynomial source est inchangé. Les 31 fonctions
retenues par image Windows, 16 par CLI Linux et 22 par consommateur Linux
de ce registre ne contiennent aucune division ; ces comptes ne représentent
pas l'ensemble des fonctions des images. Les cinq divisions de la fermeture
conservatrice Windows sont dans les conversions d'horloge `std::time`, et
restent visibles dans l'inventaire global.

Les prologues Windows de `forward_into`, `inverse_into` et
`multiply_add_assign` conservent leurs sauvegardes SIMD héritées de M09.
Le registre contient leurs instructions ; cette revue ne prouve pas que les
valeurs entrantes sont toujours publiques ni qu'elles sont toutes effacées.
Elle ne transforme donc pas les effacements ciblés en fermeture ABI. Le masque
sensible d'égalité, les registres volatils, les appels indirects non résolus,
les dépendances et les copies détenues par l'appelant restent explicitement
hors garantie globale. Les chemins de refus d'import sont reliés au pont
source et aux contrôles fonctionnels ; leur ordre observable fait partie
de l'API, distinct de la sélection implicite d'une clé de rejet.

**État : retraits ciblés003 confirmés sur les quatre images PC et revue
bornée rejouable.** Les coûts, corpus, diagnostics et campagne longue du
candidat final sont consignés par les contrôleurs M10 et leur bilan général ;
la présente revue ne les déclare pas réussis par anticipation.
C01, QROM, primitives concrètes, assurance externe et garanties universelles
de compilation restent ouverts.
