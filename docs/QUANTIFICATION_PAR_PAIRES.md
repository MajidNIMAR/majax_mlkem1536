# J2 — H02 : quantification décalée par paires

Étude du 24 octobre 2026, conservée dans
[`run-006`](../results/j2/run-006/). Les paramètres restent n=256,k=6,q=7681,
η1=η2=3. Le projet dispose de quantificateurs mathématiques et de leurs
certificats ; aucun nouveau profil ni KEM de rang 6 n'est sélectionné.

## Résultat principal

Dans les familles explorées, le plus court certificat de H02 correspond à
**2567 octets**, avec **228 paires** quantifiées sur 24 bits chacune,
1080 coefficients u transmis exactement sur 13 bits et v sur 4 bits.
La borne supérieure est **2^-175,665600** dans le modèle CBD indépendant,
sans indépendance des arrondis. C05 reste 2^-174,8.

Le gain est de **14 octets sur H01** (2581) et de **89 octets sur le témoin de
2656**, soit environ 3,35 % de ce dernier. La marge logarithmique du point
le plus compact est seulement d'environ **0,866 bit** ; il sert de point de
frontière et n'est pas une recommandation de profil.

## 1. Construction du quantificateur

Notons R(t) l'arrondi au plus proche, demi-entiers vers le haut. Pour b bits
par indice et L=2^b, les deux indices i,j de 0 à L−1 reconstruisent

`y_j = R(q*j/L)`,
`x_ij = R(q*(2*i + (j mod 2))/(2*L))`.

Une ligne sur deux est décalée horizontalement d'une demi-maille avant
l'arrondi entier. Le livre de reconstruction contient L² points distincts
lorsque les lignes et colonnes correspondantes sont distinctes. Une paire
est représentée par les deux indices, soit 2b bits. À q=7681,b=12, cela fait
16777216 points et 24 bits par paire, comme deux compressions scalaires de
12 bits.

L'encodeur mathématique recherche parmi les deux lignes encadrant y et les
deux colonnes encadrant x dans chaque ligne. Il choisit la plus petite distance
euclidienne au carré, avec une règle de départage déterministe. Le décodage
emploie directement la formule des deux points reconstruits. Les opérations
sont modulo q, les erreurs étant représentées dans l'intervalle centré.

Le prototype Python emploie des recherches et branchements ordinaires pour
l'étude ; aucune propriété de temps constant n'est revendiquée.

## 2. Couverture prouvée par contrôles finis

Pour q=7681 et L=4096, les listes unidimensionnelles établissent exactement :

- 4096 lignes distinctes ; 511 écarts circulaires de 1 et 3585 de 2 ;
- dans chaque phase horizontale, des colonnes distinctes et des écarts au plus 2 ;
- l'union des deux phases horizontales contient tous les 7681 résidus ;
- les phases alternent entre lignes adjacentes, y compris au retour modulo q.

Tout point d'entrée est alors dans l'un des deux cas suivants. Si y est une
ligne, une colonne de cette ligne est à distance au plus 1 de x. Si y est
entre deux lignes, leur écart est 2 et y est à distance 1 des deux ; l'union
des phases contient exactement x dans au moins une des lignes.

Il existe donc toujours une reconstruction dont l'erreur appartient à

`E = {(0,0),(1,0),(−1,0),(0,1),(0,−1)}`.

Le choix de plus petite distance ne peut pas produire une erreur euclidienne
supérieure à 1. Sur des coordonnées entières, cela implique
**`|δ1|+|δ2|≤1`**. La garantie porte sur les 7681² entrées, par l'argument de
couverture et les contrôles finis des listes ; il ne s'agit pas d'une
estimation par échantillonnage.

Cette propriété n'est pas universelle : à q=17,b=3, l'écart maximal atteint 3
et le contrôle de couverture échoue. Ce cas négatif est conservé.

## 3. Expériences exhaustives sur de petits modules

Les cinq tores sont entièrement parcourus avec trois règles : compression
scalaire, quantification décalée de plus petite distance et quantification
décalée minimisant un MGF local. Chaque comparaison utilise le même nombre
de points et le même nombre de bits fixes par paire.

| q / b | Erreur quadratique moyenne scalaire | Erreur quadratique moyenne décalée | Couverture par le support E établie ? |
|---|---:|---:|---|
| 5 / 2 | 2/5 | 9/25 | Oui |
| 7 / 2 | 6/7 | 33/49 | Oui |
| 13 / 3 | 10/13 | 105/169 | Oui |
| 17 / 3 | 18/17 | 250/289 | Non |
| 31 / 4 | 30/31 | 705/961 | Oui |

Ces moyennes concernent des entrées uniformes dans les petits tores, pas la
loi réelle des chiffrés de rang 6. À q=17, une meilleure moyenne ne suffit
précisément pas à établir la propriété de support recherchée.

Le critère local MGF donne les mêmes histogrammes que le critère euclidien
dans les cinq cas : **aucun gain supplémentaire de ce critère n'est observé**
ici. Tous les histogrammes, supports et scores rationnels sont conservés.

## 4. Borne de décapsulation conservant le support joint

Pour les deux secrets d'une paire, la couverture donne point par point

`−S1*δ1−S2*δ2 ≤ max(|S1|,|S2|)`.

À l'inverse, les supports scalaires séparés [-1,1]² donnent
`|S1|+|S2|`. Conserver le support joint améliore donc la majoration à budget
égal de 24 bits. Aucune indépendance de δ1,δ2 ou du reste du calcul n'est
nécessaire.

Définir, pour z>1 rationnel,

`P(z)=E[z^(E*Y)]`, `C(z)=E[z^E2]`,
`D(z)=E[z^(−S1*F1−S2*F2+max(|S1|,|S2|))]`.

Toutes les primitives ci-dessus suivent CBD3 indépendamment dans le modèle.
Pour G paires quantifiées et 1536−2G coefficients u exacts, les deux queues
majorées et l'union des 256 sorties donnent

`Pr[échec message] ≤ 2*256*P(z)^(3072−2G)*D(z)^G*C(z)/z^h`,

où h est le seuil sûr après prise en compte du pire arrondi de v. La matrice
s'annule algébriquement. Les deux variables majorantes des queues ont la même
loi par symétrie CBD ; elles ne sont pas supposées centrées ou symétriques.

Les paires adjacentes d'un polynôme utilisent deux secrets distincts pour une
sortie donnée. Les 128 paires permutées couvrent ses 256 indices secrets sans
répétition ; les signes négacycliques ne changent pas les MGF. Les sorties
peuvent être dépendantes, puisque seule une borne d'union est utilisée.

Le masque de G paires est public et fixe, entrelacé sur les 768 positions de
paires. Pour le point retenu comme frontière, il y a 38 paires par polynôme.
Le masque ne dépend ni d'une clé ni d'un message ou d'un retour de décapsulation.

## 5. Comparaisons et limites de recherche

La grille contient 500 rationnels entre 1001/1000 et 3/2. Ses 4000 propositions
numériques couvrent huit précisions v. Les 16 frontières/pas suivants rapportés
sont recalculés en rationnels : sept reçoivent un certificat C05, neuf ne sont
pas certifiés par cette majoration. Le meilleur point trouvé ne revendique
pas un optimum global sur tous les quantificateurs ou toutes les inclinaisons.

| Point | Chiffré théorique | log2 borne supérieure |
|---|---:|---:|
| u exact, dv=4, contrôle de H01 | 2624 octets | −273,725338 |
| H01 scalaire, dv=4, 320 coefficients sur 12 bits | 2584 octets | −175,792447 |
| Meilleur point global exploré de H01, dv=3 | 2581 octets | −175,734559 |
| H02, dv=4, 228 paires quantifiées | **2567 octets** | **−175,665600** |
| H02, dv=4, 232 paires, non certifié par la borne | 2566 octets | −174,154447 |

À dv=4 identique, H02 gagne 17 octets sur le point scalaire de H01. Face au
meilleur point de H01 qui employait dv=3, le gain net est 14 octets : le
changement de précision v n'est pas omis.

Par rapport au témoin de 2656, la décomposition est 32 octets économisés sur
v et 57 sur u. Le comptage du point H02 est
`1080*13/8 + 228*24/8 + 256*4/8 = 1755+684+128 = 2567`.
Il suppose un format de masque connu du profil et n'inclut pas une enveloppe
de protocole. Ce comptage concatène les champs de u dans un flux de bits
continu, sans bourrage à chaque frontière de polynôme. Un alignement en
octets de chaque polynôme ajouterait ici trois octets ; une future
spécification devra rendre cette convention explicite. Les erreurs de
sérialisation ou la réencapsulation ne sont pas
implémentées par cette étude mathématique.

La faible marge d'environ 0,866 bit sous le seuil de la borne ne sélectionne
pas automatiquement ce point comme candidat. Un point moins compact peut
être préférable selon la marge choisie et les autres contraintes de J2.
Une non-certification ne prouve pas un taux d'échec réel trop élevé.

## 6. Contre-vérification, antécédents et décision

Les tests comparent le petit encodeur à tous les points des livres complets,
énumèrent des bits CBD pour les MGF et vérifient les masques et les permutations.
Une reconstruction indépendante, sans import de l'arithmétique du projet,
refait les listes de couverture, les MGF depuis 64 chaînes de bits CBD3 et
4096 couples élémentaires, puis retrouve la fraction rationnelle finale.
C05 est décidé par l'inégalité entière `2^874*N^5≤D^5` pour p=N/D.

Les codes multidimensionnels ont des antécédents, notamment
[Minal](https://github.com/thalespaiva/minal_mlkem/tree/6b12ae4fa24c04fe756386cb8d7e7d88d283d1a9).
Son README mentionne aussi les paramètres de compression par blocs DU0/DU1 ;
la compression mixte par blocs ne doit pas être présentée comme un principe
nouveau de H01. Aucun code de ce dépôt n'est exécuté ou intégré ici. Notre
expérience conserve sa construction explicite, son contrôle de couverture et
sa borne adaptée aux paires, sans revendiquer de nouveauté mondiale.

H02 apporte un gain positif calculé dans le modèle CBD indépendant. La portée
reste la correction honnête moyenne sur les clés, pour un message fixé
indépendamment des clés. Les comparaisons d'attaques, la transformation CCA,
les oracles, l'instanciation SHAKE et la future implémentation requièrent leurs
propres analyses avant la clôture de J2 et la sélection finale d'un profil.

## Reproduction

```powershell
python -m unittest discover -s research -p test_group_quantization.py
python research/verify_group_quantization_results.py
python research/verify_group_certificate_bits.py
python research/run_group_quantization.py --output artifacts/generated/group-quantization-nouveau
.\scripts\dev.ps1 check
```

Les sorties existantes ne sont pas écrasées. Le rejeu indépendant a sa propre
provenance, ajoutée avant le premier gel Git sans modifier les résultats initiaux.
