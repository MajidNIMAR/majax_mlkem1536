# M06 — contre-revue du moteur et du rejet implicite

10 novembre 2026. Cette revue est menée séparément de l'implémentation M06.
Elle ne modifie pas le cœur. Les constats ci-dessous distinguent les
invariants du programme, les contrôles exécutés et les limites de leur
transfert au binaire.

## Sources examinées

Le périmètre du cœur est figé par les empreintes SHA-256 suivantes :

| Fichier | SHA-256 |
| --- | --- |
| `crates/kem1536/src/engine_poly.rs` | `ffe7b50dfebfe8d9998296672bd1973a8376a02cb06f2338418e27f23a392ac2` |
| `crates/kem1536/src/dev_kem.rs` | `eb7635eedc73c3db93d7baa81a86817157969a82890f797acfb3694a767e0262` |

La comparaison porte sur les changements depuis
`693c6a305b5143b9b00b912353bbae153cad4e4f`. Les archives M01–M05 et J2
ne sont ni remplacées ni modifiées par cette revue.

## Arithmétique et représentation

`NttPolynomial` possède son tableau privé de 256 résidus dans
`Zeroizing<[u16;256]>`. Il est distinct du type en coefficients et
n'implémente ni `Copy` ni `Clone`. Son constructeur ne retourne que des
zéros ; `forward_into`, `multiply_add_assign` et `inverse_into` remplissent
des propriétaires déjà établis. Les chemins secrets nouveaux ne retournent
pas de polynôme rempli par valeur. `uniform` conserve son retour par
valeur, limité à la matrice publique.

Les bornes requises par les réductions sont préservées. Pour deux résidus
canoniques, le produit entier est au plus 7680² = 58 982 400. Le quotient
par réciproque sous-estime le quotient exact d'au plus une unité ; le
reste avant la correction est donc inférieur à 2q. Dans une accumulation,
le produit est déjà canonique, puis la somme avec l'accumulateur est au
plus 2(q−1) = 15 360 < 2q = 15 362. La réduction après **chaque** terme
rend cette borne indépendante du nombre de termes. L'accumulation ne
dépend donc pas d'une hypothèse de somme non réduite de seulement six
produits.

La NTT emploie le même twist par une racine d'ordre 512, les mêmes racines
cycliques et le même facteur inverse qu'avant M06. Sa linéarité donne
`inverse(sum_i forward(a_i)*forward(b_i)) = sum_i a_i*b_i` dans
`Z_7681[X]/(X^256+1)`. La suppression des inverses intermédiaires ne change
ni le signe de la convolution négacyclique ni la normalisation. Le test
monomial `X^255*X = −1` vérifie en particulier le signe à la frontière.
`inverse_into` préserve sa source et copie ses 512 octets directement dans
le propriétaire du résultat avant de transformer ce dernier.

## Intégration au KEM

Les lignes de KeyGen utilisent toujours `A[i,j]`, celles du chiffrement
`A[j,i]`. Les nonces du secret ou de l'aléa restent 0 à 5, ceux des erreurs
vectorielles 6 à 11 et celui de l'erreur scalaire 12. Le bruit et le message
sont ajoutés dans le domaine des coefficients. `sum.clear()` précède
chaque nouveau produit scalaire et l'accumulation scalaire de `v`. Le
déchiffrement soustrait une fois la somme des six produits, ce qui est
identique à six soustractions modulo q.

| Opération | Transformations M04 | Transformations M06 | Décomposition M06 |
| --- | ---: | ---: | --- |
| KeyGen | 108 | 48 | 6 secrets + 36 entrées de matrice + 6 inverses |
| Encaps | 126 | 55 | 6 aléas + 36 entrées de matrice + 6 coefficients publics + 7 inverses |
| Decaps | 144 | 68 | 12 transformations + 1 inverse de déchiffrement + 55 de réencapsulation |

Ces comptes décrivent le programme ; ils ne prédisent pas à eux seuls sa
latence ou sa mémoire. Les nouveaux tableaux transformés coexistent avec
d'autres buffers et peuvent accroître la pile ou le travail d'effacement.
Les mesures propres à M06 doivent établir ce compromis.

Les domaines de hachage, encodages, tailles, importations et sources
d'aléa n'ont pas changé. Un chiffré de bonne longueur avec coefficients
non canoniques est toujours réduit pour le calcul, puis réencapsulé sous
forme canonique. La comparaison de l'ensemble des 2656 octets impose le
rejet lorsqu'un encodage non canonique diffère. Le calcul de `J(z,c)` et
la sélection conditionnelle restent communs aux deux issues de Decaps.

## Propriétaires secrets et effacements

Les coefficients secrets transformés et les accumulateurs sont portés
par `Zeroizing`, comme leurs résultats en coefficients. Les nouvelles
fonctions reçoivent leurs destinations par référence mutable. Les
temporaires de bruit écrivent dans leurs propriétaires et les vecteurs
transformés restent locaux à l'opération ; aucun cache secret persistant
n'est introduit.

`clear()` remet à zéro l'accumulateur pour la correction du calcul. Son
`fill(0)` ordinaire n'est pas présenté comme un effacement volatile de
toutes les copies. Le `Drop` de chaque propriétaire `Zeroizing` fournit
l'effacement demandé à la fin de vie de son stockage. Ce raisonnement de
source ne prouve pas que tous les registres, copies, déplacements,
débordements de pile ou chemins d'arrêt sont effacés. Le nouveau nombre
de propriétaires impose sa propre revue du binaire ; les deux boucles de
512 octets du jalon M04 ne constituent pas cette revue.

## Lecture contradictoire des nouveaux tests

Le test des produits scalaires confronte vingt cas de six produits à la
convolution générique indépendante : zéro, tous les résidus maximaux,
monômes à la frontière négacyclique, alternances et cas pseudorandomisés.
Il réemploie l'accumulateur avec `clear`, contrôle les résidus canoniques,
préremplit la destination et vérifie la conservation de la source de
l'inverse. Le test d'accumulation force le franchissement exact de q avec
`(q−1)*(q−1)`, sur plus de q additions. Il traite le risque d'une réduction
retardée au-delà de la seule taille du rang 6.

Le compteur de transformations est uniquement compilé sous `cfg(test)`
et local au thread. Le test KEM contrôle 48/55/68, puis 68 pour un rejet
non canonique avec résultat exactement égal au fallback attendu. Ce cas
ne prouve pas l'égalité de temps de tous les chemins. La copie du tableau
NTT dans le test de conservation est synthétique et hors production.

La présente lecture des tests ne remplace pas leur exécution ni le
rejeu intégral des corpus. Les résultats effectifs et leurs empreintes
sont conservés séparément par la campagne M06.

## Binaires examinés et effacements ciblés

Après le marqueur `ROOT_TIMING_DONE`, les quatre exécutables issus de
`artifacts/generated/m06-validation-001` ont été désassemblés intégralement
par `inspect_m03_binary.py`. Chaque dossier
`artifacts/generated/m06-audit-{windows,linux}-{research,delivered}`
conserve le binaire, le désassemblage, l'inventaire et `ntt-review.json`.

| Cible | Type | SHA-256 du binaire |
| --- | --- | --- |
| Windows | recherche | `f84cb5418bef5bc630d631a209bd98f4f51e1f1496616963468139becda2d027` |
| Windows | livré | `8afa24959f7ec8e59472938f9569da4f30ef8088d9aa48f4c82baa2e19f11b67` |
| Linux | recherche | `e01cdb5c9a067f4a091e6c0ebd323e1b32ca176cc9f6fe74ff2b94bfc414b70a` |
| Linux | livré | `eef23ebf6c9b96b14d377d585971a4cbc531d0c58e26654a544abac8133b39ff` |

Les quatre versions conservent `forward_into`, `multiply_add_assign`,
`inverse_into` et `transform`, sans division entière dans ces fonctions.
L'ancien `multiply_into`, réservé aux tests, est absent. Les trois
helpers nouveaux ont chacun une seule branche conditionnelle : le retour
de leur boucle de parcours fixe. La transformée a sept branches
conditionnelles, rattachées au compteur de permutation, à la comparaison
des indices de bit-reversal, aux boucles de papillons et d'étages, et au
contrôle de borne d'un indice public. Les multiplications et corrections
des résidus utilisent des opérations SIMD et des masques ; ces branches
examinées ne consultent pas un coefficient secret pour choisir leur issue.
Cette qualification locale ne vaut pas preuve de temps constant du KEM.

Dans les quatre `inverse_into`, la trace des registres de l'ABI établit
que le premier appel copie exactement 512 octets de la source NTT vers la
destination `Polynomial` empruntée. Le second appel transforme cette même
destination. L'appel `memcpy` est donc attendu : il n'est pas un retour de
polynôme secret dans un temporaire. Son corps système n'est pas prouvé
par ce contrôle. Les helpers Windows sauvegardent aussi des registres
SIMD prescrits par l'ABI ; ces sauvegardes, les registres de calcul et
les autres copies ne sont pas couverts par la preuve de stockage ciblée.

Les nouveaux owners secrets sont identifiés par une lecture des arguments
des appels dans les appelants. Le reconnaisseur vérifie ensuite les
**intervalles** de leurs écritures nulles, et non seulement un nombre de
boucles. Dans chaque binaire, huit emplacements sont ciblés :
`transformed_s` et `transformed_r` de 3072 octets chacun ; leurs deux
accumulateurs de 512 octets ; le bruit temporaire de chiffrement de 512
octets ; les trois NTT `left`, `right` et `sum` du déchiffrement de 512
octets chacun. Il s'agit de stockages situés dans des fonctions différentes,
pas d'une annonce de pic mémoire ou d'octets uniques simultanément vivants.

Pour les binaires livrés, les décalages suivants sont relatifs au `%rsp`
du cadre de l'appelant examiné. Chaque valeur est le début du stockage ;
les tailles figurent dans le paragraphe précédent et dans les JSON.

| Owner | Windows | Linux |
| --- | ---: | ---: |
| `transformed_s`, dans `keygen` | `0x14a0` | `0x1498` |
| somme KeyGen | `0x2a0` | `0x290` |
| `transformed_r`, dans `pke_encrypt_into` | `0x1a30` | `0x1a18` |
| somme de chiffrement | `0x230` | `0x218` |
| bruit temporaire | `0xc30` | `0xc18` |
| NTT `left`, dans `decapsulate` | `0x970` | `0x1558` |
| NTT `right` | `0x770` | `0x1358` |
| somme de déchiffrement | `0x370` | `0x358` |

Les emplacements des binaires de recherche sont distincts et conservés
dans leurs propres JSON. Leur chiffrement a un nom LLVM encore manglé
dans le désassemblage : le préfixe lexical `R1_core` ne l'inclut pas,
mais la fermeture directe le rejoint et la présente revue le sélectionne
explicitement. Les deux divisions recensées dans les cœurs de recherche
se trouvent dans le diagnostic `hardening::timing`. Les cœurs livrés
n'en recensent aucune. Les cinq divisions dans la fermeture directe
Windows livrée se trouvent dans les conversions de compteurs de temps
de la bibliothèque standard ; la fermeture directe Linux livrée n'en
recense aucune. Les limites sur les appels indirects restent celles de
l'inventaire, même lorsque les relocalisations GOT sont résolues.

`research/review_m06_binary.py` n'accepte que les quatre empreintes
ci-dessus : un autre binaire demande une nouvelle attribution humaine
des emplacements. Il reconnaît une forme restreinte de huit écritures
nulles de 16 bits, un pas de 16 octets et 32 tours, avant le premier
`ret` textuel. Il calcule leur couverture et échoue si une écriture,
une borne, un pas ou un retour de boucle change, ou si une instruction
non modélisée s'intercale. Les intervalles de chaque owner ciblé doivent
être couverts. Le contrôle ne démontre pas que toute branche de contrôle
atteint ces boucles, ni une provenance générale de toutes les écritures.
Il ne certifie pas les chemins d'unwind, les arrêts anormaux ou tous les
propriétaires secrets du programme.

Les cinq tests du reconnaisseur réussissent sous Windows et Linux. Leurs
contrôles négatifs changent la direction ou la taille de copie, l'appel,
le registre conservé, une écriture nulle, une borne, un pas, un retour de
boucle et une instruction intercalée. Une boucle située après le premier
`ret` ne produit pas de revendication. Les quatre rapports ont été
générés avec succès ; leur rejeu s'effectue par exemple ainsi :

```powershell
.\.tools\research-venv\Scripts\python.exe -B research/review_m06_binary.py artifacts/generated/m06-audit-windows-delivered --verify artifacts/generated/m06-audit-windows-delivered/ntt-review.json
```

## Contre-revue de la borne du rejet J

La note [REJET_IMPLICITE_R1_M06.md](REJET_IMPLICITE_R1_M06.md), son
calculateur et ses huit tests ont été lus séparément de leur rédaction.
Le théorème 3 d'AHU, p.11, et la discussion des oracles auxiliaires p.10
ont été vérifiés dans la copie primaire conservée au cache, SHA-256
`a3b09922553b2138dc022db72035e8378c30cf27cfad312b1a45558bad03d69d`.
Le théorème donne bien `|Pleft−Pright|≤2d√Pguess` et permet de mesurer
l'extracteur dans l'un ou l'autre monde.

Le couplage proposé remplace simultanément les 256 premiers bits de
toute la ligne `TAG||J||z||c` par une fonction indépendante R(c), en
conservant les suffixes XOF. Pour chaque z, l'oracle ainsi modifié demeure
uniforme et son préfixe sur cette ligne est exactement l'interface indexée
réelle. Dans le monde idéal, l'oracle public quantique H et R sont
indépendants du z uniforme. D réponses classiques de R ne changent pas
cette indépendance. Une entrée publique classique ou la mesure d'un
registre quantique séquentiel rencontre la ligne cachée avec probabilité
au plus `2^-256`. Il en résulte le majorant classique `q/2^256`, puis le
majorant quantique `2q/2^128`, chacun plafonné à 1. D=0 donne exactement
zéro, car le seul oracle observé est alors uniforme dans les deux jeux.

La note conserve l'oracle public quantique dans le monde idéal ; elle
n'assimile pas une superposition à une liste classique. q est un nombre
total de portes d'oracle : la sérialisation des lots de portes commute
sur les registres distincts et justifie le compte séquentiel conservateur.
Un appel cohérent qui mélange les domaines compte aussi comme une porte.
Les domaines auxiliaires fixes, comme N, peuvent être absorbés dans les
opérations communes à la comparaison statistique, avec leurs coûts
conservés. Cette opération informationnelle n'est pas une simulation
quantique efficace gratuite pour une autre réduction.

Une ambiguïté a été corrigée avant gel : l'auxiliaire peut contenir les
domaines **fixes disjoints de J** ; une description de la restriction au
complément de la ligne secrète S_z pourrait elle-même révéler z. Les
autres entrées J demeurent dans l'oracle variable. La version relue
après correction énonce cette distinction.

Les tests finis traitent indépendamment répétitions, collisions de
sorties, choix adaptatifs et deux calculs quantiques restreints. La
formule d'écart d'un candidat fixe inclut correctement les faux positifs
par collision ; elle n'est pas utilisée comme borne universelle. Les
opérations du calculateur emploient des fractions rationnelles exactes.
La contre-revue ne démontre pas le théorème pour tous les adversaires
par une énumération, et ne vérifie pas une substitution de SHAKE concret.

Cette analyse ne trouve pas de défaut dans le raccord idéal ciblé de
J. La borne quantique est trop lâche pour certifier l'allocation
illustrative `2^-130` à un nombre positif entier de requêtes. Ce constat
reste défavorable et ne mesure ni une attaque atteignable ni un nombre
global de bits de sécurité. L'uniformité indépendante de z, les accès
indexés classiques, les autres hypothèses M05 et l'absence de fuite de
z sont indispensables. L'IND-CCA concret du KEM, la correction de tous
les transferts FO et C01 restent ouverts.

## État de la contre-revue

Aucun défaut de correction ni changement de format n'a été identifié
dans les changements de source examinés. La borne idéale ciblée de
`J(z,c)` est cohérente avec le couplage et le théorème relus. Ces conclusions
sont limitées aux périmètres explicités ci-dessus. Les quatre binaires
ont leurs constats propres sur les copies et les stockages ciblés ;
aucune preuve générale de temps constant, d'effacement ou de sécurité
IND-CCA n'est déduite de ces contrôles.
