# Rattachement du certificat de correction à R1

**Complément du 26 octobre 2026 :** [M05](SECURITE_CONCRETE_R1_M05.md)
traite maintenant le passage du bruit frais au bruit expansé par graines
dans le modèle RO, y compris la collision des graines. Sa borne est une
moyenne sur oracles/clés ; elle ne vaut pas pour chaque oracle fixé ni
directement pour SHAKE concret. Le certificat rationnel historique et le
rattachement de programme ci-dessous restent inchangés.

Le certificat de [run-004](../results/j2/run-004/correctness-certificate.json)
se rattache aux paramètres, échantillonnages et opérations de
`KEM1536-DEV-Q7681-R1`. Le nouveau vérificateur retrouve sa fraction
exacte, les seuils du décodeur et la décomposition du bruit sur des
vecteurs produits par Rust. **Ce rattachement ne transforme pas SHAKE
concret en variables mathématiquement indépendantes et ne prouve pas
une borne uniforme pour toutes les clés.**

La conclusion acquise est une borne de correction du PKE dans le modèle
de bruit idéal, en moyenne sur les clés honnêtes, y compris lorsque le
pire message est choisi pour chaque clé. Le transfert cryptographique
de ce modèle à la génération par SHA3/SHAKE et à des requêtes KEM
adaptatives reste une obligation distincte. La note
[d'argument de sécurité](ARGUMENT_SECURITE_R1.md) traite ces obligations.

## Contrat exact réalisé

La [spécification R1](SPECIFICATION_DEV_Q7681_R1.md) et
[`dev_kem.rs`](../crates/kem1536/src/dev_kem.rs) emploient :

| Élément | Réalisation | Conséquence pour run-004 |
|---|---|---|
| Anneau | `Z_7681[X]/(X^256+1)`, rang 6 | `q=7681,n=256,k=6` |
| Secrets et erreurs | CBD(3) pour `s,e,r,e1,e2` | `eta1=eta2=3` |
| `u` | Six polynômes exacts de 416 octets, coefficients canoniques sur 13 bits | Aucune erreur de compression de `u` |
| `v` | 256 coefficients compressés sur 5 bits | Erreur centrée dans `[-120,120]` |
| Message | 256 bits, poids faible d'abord ; 0 devient 0 et 1 devient 3841 | Régions de décision calculées ci-dessous |
| Tailles | `ek=2528`, `dk=5088`, `c=2656`, `K=32` octets | Formats propres à R1 |

L'échantillonneur de bruit lit 192 octets de SHAKE256, soit exactement
1536 bits pour 256 coefficients. Le coefficient `j` consomme les bits
`6j..6j+5` sans réemploi : les trois premiers sont additionnés, les trois
suivants soustraits. L'énumération des 64 mots de six bits donne :

| Valeur signée | −3 | −2 | −1 | 0 | 1 | 2 | 3 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Multiplicité / 64 | 1 | 6 | 15 | 20 | 15 | 6 | 1 |

Le programme représente ensuite ces valeurs modulo 7681. Le calcul de
bruit emploie leurs représentants signés pour former les lois entières.
Ce choix de représentants ne change pas les identités modulo `q`.

Les adresses de bruit sont `TAG || N || 0 || graine || nonce`. La clé
utilise `sigma,0..5` pour `s`, `sigma,6..11` pour `e` ; le chiffrement
utilise `rseed,0..5` pour `r`, `rseed,6..11` pour `e1`, puis
`rseed,12` pour `e2`. Les domaines KG, G, A, N, H et J sont distincts.
`sigma` est la seconde moitié de SHA3-512 sur KG et `d`; `rseed` est la
seconde moitié de SHA3-512 sur G, `m` et `H(ek)`.

La matrice rejette les candidats 13 bits ≥7681. Sur les 8192 candidats
possibles d'un mot uniforme, chacun des 7681 coefficients acceptés a
une seule préimage. L'uniformité après rejet est exacte **si les mots
d'entrée sont uniformes indépendants**. La correction ne nécessite
cependant aucune hypothèse d'uniformité sur `A`.

## Identité algébrique et erreur d'arrondi

Pour une clé honnête et un chiffrement honnête, dans l'anneau :

```text
t = A s + e
u = Aᵀ r + e1
v = tᵀ r + e2 + μ(m)
v_restauré = v + δv                  (mod q)
v_restauré − sᵀ u = μ(m) + B + δv    (mod q)
B = eᵀ r − sᵀ e1 + e2
```

L'égalité `(A s)ᵀr = sᵀ(Aᵀr)` repose sur la commutativité du produit
dans l'anneau, pas sur un argument probabiliste. Elle reste vraie pour
une matrice quelconque. L'absence de compression de `u` supprime le
terme `−sᵀδu` ; sa taille exacte dans le chiffré est donc une condition
essentielle du certificat.

Les 7681 entrées possibles du quantificateur de `v` sont énumérées
avec des entiers exacts. L'erreur est le représentant centré de
`Decompress_5(Compress_5(v))−v`, et son support est `[-120,120]`.
Elle peut dépendre de tout le reste du calcul ; nous n'en utilisons
ni la distribution ni l'indépendance.

Le décodeur `Compress_1` possède les régions de réussite suivantes
pour l'erreur totale autour du message encodé :

| Bit | Encodage μ | Intervalle centré de réussite |
|---|---:|---|
| 0 | 0 | `[-1920,1920]` |
| 1 | 3841 | `[-1920,1919]` |

Ainsi `|B_j|≤1799` assure le décodage des deux bits, pour tout
`δv_j∈[-120,120]`. La borne positive est serrée pour cet argument par
supports : `B_j=1800, δv_j=120` fait sortir le bit 1 de sa région.
Cela ne démontre pas que cette paire est réalisable conjointement
dans une exécution. Le seuil de l'événement majorant est **1800**,
avec les deux signes. Aucun passage silencieux à 1801 n'est permis.

## Quantificateurs et reconstruction rationnelle

Dans le PKE idéal, soit `κ=(A,s,e)` une clé honnête et
`ω=(r,e1,e2)` le bruit de chiffrement frais indépendant. Posons :

```text
β(κ) = Pr_ω[il existe j tel que |B_j(κ,ω)| ≥ 1800].
```

L'enveloppe ne dépend pas de `m`. Pour chaque clé, l'implication
déterministe de décodage entraîne donc :

```text
max_m Pr_ω[Decryptκ(Encryptκ(m;ω)) ≠ m] ≤ β(κ)
E_κ max_m Pr_ω[échec | κ,m] ≤ E_κ β(κ) ≤ δ004.
```

Il s'agit d'une moyenne sur clés du pire message **pour chaque clé**,
et non uniquement d'une moyenne sur messages uniformes. Cela ne
majore pas `max_κ β(κ)`. Pour une clé fixée, les coefficients de `s,e`
ne sont plus des variables CBD fraîches : réutiliser directement la
MGF moyenne de run-004 comme MGF conditionnelle serait incorrect.

Pour un coefficient de `B`, chacune des `2nk=3072` contributions est
un produit de deux CBD(3) indépendantes dans le modèle idéal. Pour une
convolution et un coefficient fixés, l'association des indices est une
permutation ; chaque coefficient de chaque facteur intervient une
fois. Les familles `(e,r)` et `(s,e1)` sont disjointes, et `e2` est
indépendant. Les signes négacycliques n'affectent pas la loi symétrique.
Les **différents coefficients de B peuvent être dépendants** : la
borne d'union sur 256 coefficients n'exige pas leur indépendance.

L'énumération des mots de six bits reconstruit la MGF d'une CBD, puis
les 4096 paires de mots la MGF du produit. Avec `z=13/10`, toutes les
opérations suivantes sont rationnelles :

```text
δ004 = 2 × 256 × M_produit(13/10)^3072 × M_CBD3(13/10) / (13/10)^1800
log2(δ004) ≈ −310,08596919852425
δ004 ≤ 2^-310                              comparaison entière exacte
δ004^5 × 2^874 ≤ 1                         comparaison C05 exacte
```

Le logarithme sert à la lecture ; il n'entre dans aucune décision.
La variance d'un coefficient idéal de `B` vaut exactement
`13827/2 = 6913,5`. La fraction reconstruite est exactement celle de
run-004, pas une approximation ou une nouvelle optimisation.

Si le message PKE est correctement retrouvé, le KEM honnête retrouve
les mêmes entrées de G, les mêmes pièces de chiffrement et le même
chiffré canonique : la réencapsulation accepte et retourne le même K.
Le passage de la distribution PKE à celle des pièces dérivées par G
relève toutefois du modèle de primitives explicité ci-après.

## De la loi idéale à SHAKE concret

Un flot dérivé d'une graine de 256 bits ne constitue pas une preuve
d'indépendance statistique de milliers de coefficients. La clé
consomme 12 blocs, soit 18432 bits avant CBD, à partir de `sigma` ;
le chiffrement en consomme 13, soit 19968 bits, à partir de `rseed`.
Ces expansions sont déterministes. Leur remplacement par les lois
idéales exige une hypothèse ou un hybride cryptographique explicite,
avec le budget de requêtes et les dépendances aux messages et clés.
Une absence d'écart dans des tests ne certifie pas ce remplacement.

Il existe un cas de réemploi à traiter plutôt que d'affirmer que tous
les nonces sont globalement distincts : si `sigma=rseed`, les nonces
alignés donnent **r=s et e1=e**. Alors `eᵀr−sᵀe1=0` exactement, et
`B=e2`. Avec `|e2|≤3` et `|δv|≤120`, le décodage reste sûr. Une
pénalité automatique de `2^-256` pour cette seule collision de graines
serait donc inutile pour la correction. Cette observation concerne
le calendrier exact R1 ; elle ne prouve aucune propriété de sécurité
de réemploi des graines et ne traite pas des requêtes adverses.

Dans une expérience honnête à un seul chiffrement où les domaines de
fonctions sont idéalisés, les adresses N différentes donnent les
blocs idéaux ; le cas d'adresses alignées est couvert par l'annulation
ci-dessus. Pour SHA3/SHAKE fixés, pour des messages sélectionnés après
recherche de pièces G particulières ou pour des décapsulations
adverses, le présent document n'affirme pas que le terme de transfert
est nul. Il ne fournit pas de preuve IND-CCA ni de borne d'échec
adaptatif.

La borne ne couvre pas les clés importées arbitraires. L'import
vérifie canonicité et `H(ek)`, pas l'appartenance de `s,e` à leur
distribution honnête. Un contre-exemple public synthétique prend
`s=0`, `t[0]=3840` constant et les autres `t[i]=0` ; la sérialisation
est canonique et son hash cohérent, mais `t−As` n'est pas petit. Pour
le message nul et les pièces G effectivement dérivées, le vérificateur
retrouve **111 bits PKE incorrects**. Il reconstruit les prédicats
d'import sans exécuter l'import Rust ; ce constat illustre le
périmètre honnête du certificat, pas une attaque contre les clés
issues de KeyGen.

## Contrôles exécutables et limites de la preuve machine

[`verify_r1_certificate_bridge.py`](../research/verify_r1_certificate_bridge.py)
n'importe ni le calcul Chernoff existant, ni l'oracle Python R1,
ni NumPy. Il utilise hashlib et une convolution entière indépendante
de précision non bornée. Sa commande est :

```powershell
.tools/research-venv/Scripts/python.exe research/verify_r1_certificate_bridge.py
.tools/research-venv/Scripts/python.exe -m unittest discover -s research -p test_r1_certificate_bridge.py -v
```

Avec `--output`, le répertoire de destination doit être nouveau ; le
vérificateur refuse d'écraser un résultat antérieur. Le résultat initial
est conservé localement sous
`artifacts/generated/r1-certificate-bridge/summary.json`.

Les huit cas synthétiques fixés avant l'exécution sont
`0,1,2,3,250,500,750,999`. Ils couvrent 2048 coefficients. La totalité
du flot des matrices, des échantillons, des clés et du chiffré est
reconstruite ; les douze champs du vecteur gelé sont contrôlés, y
compris le secret de remplacement du chiffré altéré. La décomposition
de B est vérifiée coefficient par coefficient à partir de ces objets
effectifs. Le maximum observé de `|B|` est 329 et celui de `|δv|` 120.
**Ces maxima sont des observations finies ; aucun taux rare n'est
mesuré.** Les campagnes antérieures de 1000 vecteurs restent leurs
preuves propres et ne sont pas comptées comme rejouées par ce test.

Les empreintes de run-004 et du corpus moteur sont contrôlées. Le
résultat lie également les empreintes du code Rust courant, de la
spécification et du nouveau vérificateur. Des repères de source
contrôlent les constantes et appels examinés ; ils provoquent un échec
si un de ces sites change. **Ces repères ne sont ni un analyseur Rust
ni une preuve sémantique du programme.** La conservation des vecteurs,
les tests Rust/oracle et la revue de l'arithmétique complètent cette
liaison ; chaque nouvelle réalisation de multiplication doit conserver
les mêmes opérations d'anneau et être confrontée aux oracles.

Le premier résultat et ses huit sources sont conservés dans
`artifacts/generated/r1-certificate-bridge/` : sa réalisation est
`M02-schoolbook-return-owned-1`, avec `dev_kem.rs` d'empreinte
`a21bb340bd5af3c4983f1f76b59ef542aea67edf4c62ad7ff23e8205612cb564`
et `engine_poly.rs` d'empreinte
`e16599a7d711f045ece773216a508c573907e37217906082e3a8e61192dba8d9`.
L'archive `sources.tar.gz` préserve également le vérificateur et la
présente note avant les modifications de multiplication.

Le refactor M04 emploie la réalisation
`M04-destination-owned-NTT-scalar-1` : bruit, message et vecteurs sont
écrits dans des propriétaires appelants, les produits utilisent
`multiply_into`, et l'accumulation est effectuée en place. Le nouveau
jeu de repères couvre ces appels ; ses sorties et empreintes sont
distinctes sous `artifacts/generated/m04-ntt-agent/certificate-bridge/`.
Le certificat mathématique et les formats R1 restent identiques. La
concordance du nouveau calcul NTT avec l'oracle de convolution est
vérifiée par les tests Rust, séparément des repères textuels. L'examen
du binaire doit encore établir le traitement effectif des temporaires
dans cette réalisation ; les noms des fonctions ne le démontrent pas.

Les tests du vérificateur incluent des corruptions de certificat,
des changements de nonces et d'arrondis, un bit de clé modifié, les
signes négacycliques exhaustifs d'un petit anneau, et un exemple où
un secret réemployé rend fausse une factorisation naïve des MGF.
Ils contrôlent ainsi les erreurs de raisonnement visées, au-delà
d'une simple répétition des valeurs attendues.

M06 ajoute la réalisation `M06-destination-owned-NTT-accumulated-1`.
Les produits scalaires sont désormais accumulés avant une seule inverse.
Les repères de source contrôlent séparément les boucles de KeyGen et de
chiffrement, leur orientation de matrice, la remise à zéro, leur inverse
et leur addition finale ; ils couvrent aussi le produit secret de
déchiffrement et les sorties encodées. Les mutants ciblent chaque site
d'inverse/addition séparément, la transposition, un accumulateur périmé,
une transformation omise et l'encodage du mauvais vecteur. La contre-revue
a identifié puis fait corriger une première ancre globale qui pouvait
être satisfaite par l'autre site intact. La sortie M06 est conservée dans
`results/engine/m06-001/bridge/summary.json`, avec les sources du contrôle.
Le certificat mathématique reste celui de run-004 ; aucun changement
de loi de bruit, de seuil ou de paramètre n'est introduit.

L'étape rattache donc une borne exacte et ses quantificateurs aux
opérations R1 décrites et observées. Restent distincts : la vérification
formelle de tout le code et du compilateur, le transfert aux primitives
concrètes, les requêtes adaptatives, les clés adverses, les canaux
auxiliaires et la sécurité globale du KEM.
