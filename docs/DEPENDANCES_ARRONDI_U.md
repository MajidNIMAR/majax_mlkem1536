# J2 — Dépendances de u et témoin de correction sans arrondi de u

Étude du 24 octobre 2026, conservée dans
[`run-004`](../results/j2/run-004/). Elle prolonge le diagnostic de P0 et répond
à la priorité donnée à la faisabilité. Aucun nouveau profil n'est sélectionné.

## Résultat utilisable

Un scénario de rang 6, n=256, q=7681, η1=η2=3, avec transmission exacte de u et
compression de v sur 5 bits, admet une borne supérieure d'échec d'environ
**2^-319,633504**, pour tout message fixé indépendamment des clés, dans le
modèle de primitives CBD indépendantes. Le comptage exact permet à l'arrondi
de v de dépendre arbitrairement des autres variables. Une seconde méthode,
par majoration de Chernoff rationnelle, donne **2^-310,085969** et satisfait
également C05. Aucune des deux bornes ne suppose l'indépendance des arrondis.

Il s'agit d'un **témoin de faisabilité du volet correction dans ce modèle**.
Ce résultat ne sélectionne pas le scénario et ne clôt pas l'étude des attaques
nécessaire à J2. Il ne détermine pas le taux d'échec réel de P0.

## 1. Pourquoi la loi uniforme de u doit être justifiée

Pour un vecteur polynomial y fixé, posons
`I(y) = Rq*y1 + ... + Rq*yk`. L'application additive
`(a1,...,ak) -> Σ ai*yi` a pour image I(y). Les fibres d'une application
additive entre groupes finis ont toutes la même taille. Si les ai sont
uniformes et indépendants, leur image est donc uniforme **sur I(y)**.
Après ajout de e1, u est uniforme sur la classe affine `e1 + I(y)`.

Lorsque I(y)=Rq, cette classe est tout l'anneau et l'uniformité conditionnelle
de u est exacte. Lorsque I(y) est un idéal propre, ce raisonnement ne donne
pas l'uniformité sur tout Rq. De plus, conditionner y par I(y)=Rq modifie sa
distribution : conserver ensuite sans justification toutes les lois CBD
initiales des autres termes serait incorrect.

Cette formulation par idéaux conditionnels est notamment exposée au §4.1 de
la prépublication de Duriez et Tommasini, *Dependency-Aware ROM/CBD Correctness
Bounds for ML-KEM-768 at the Heuristic Failure Scale*,
[arXiv:2609.09983v1](https://arxiv.org/html/2609.09983v1), déposée le 9 septembre
2026. Elle traite un paramétrage différent ; sa chaîne de certificats n'a pas
été reproduite ici. Aucun de ses chiffres n'est transféré au rang 6. La copie
HTML et son empreinte sont conservées dans `references/correctness-2026/`.

Une approximation par le modèle uniforme demanderait de contrôler la
contribution des idéaux propres, ou une autre borne de transport adaptée à
l'événement d'échec. La simple appellation MLWE ne fournit pas ce contrôle
probabiliste à l'échelle 2^-174,8.

## 2. Vérification exhaustive sur un petit anneau

Le programme `u_dependency.py` énumère `Rq=F5[X]/(X²+1)`, dont les deux racines
sont 2 et 3. Il construit u à partir de `Σ ai*yi + e1`, sans imposer de loi
indépendante à l'arrondi. Chaque coefficient de y suit CBD2, chaque coefficient
de e1 suit CBD1, les ai parcourent uniformément l'anneau, et du=1.

Les images et leurs multiplicités sont vérifiées pour les 25 vecteurs y au
rang 1 et les 625 vecteurs au rang 2. Les classes affines après ajout de e1
sont aussi vérifiées. Un test distinct reconstruit des images par évaluation
aux racines et inversion CRT, pour vérifier la multiplication en coefficients.

| Petit modèle | Pr[I(y) différent de Rq] | Distance TV entre la loi jointe (δu,e1) et le produit de ses vraies marginales |
|---|---:|---:|
| k=1 | 17/64 | 45/512 |
| k=2 | 257/4096 | 405/32768 |

Ces distances positives établissent une dépendance effective dans les petits
modèles. Elles ne confondent pas dépendance et simple changement de marginale.
La distance à la référence « arrondi d'une entrée uniforme, indépendant de
e1 » est enregistrée séparément. Conditionnellement à l'idéal plein, cette
dernière distance est exactement nulle dans les deux expériences.

**Aucun pourcentage de cette table ne s'applique au rang 6 et à n=256.**
L'énumération vérifie le mécanisme algébrique ; elle ne mesure pas sa fréquence
ni son effet sur les queues du bruit de nos grands paramètres.

## 3. Un témoin qui ne requiert pas cette approximation

Transmettre u exactement fait disparaître δu. Le résidu avant l'arrondi de v
est alors, algébriquement,

`B = eᵀy − sᵀe1 + e2`.

La matrice s'élimine pour toute valeur de A. Pour cette analyse de correction,
il n'est donc pas nécessaire de la supposer uniforme ni de distinguer ses
images dans différents idéaux. Cela ne remplace pas les exigences sur A
intervenant dans l'analyse de sécurité.

Pour un coefficient de sortie, les variables primitives CBD indépendantes
donnent 2*n*k=3072 produits CBD3 indépendants, puis un terme CBD3 final.
Les signes de la convolution négacyclique ne changent pas leur loi symétrique.
La variance intrinsèque est `13827/2 = 6913,5`.

À q=7681, dv=5, le parcours exhaustif des résidus donne `−120 ≤ δv ≤ 120`.
Le bruit final est `B+δv`. Les intervalles du décodeur, élargis ou érodés selon
les extrêmes permis à δv, donnent des bornes rationnelles par comptage sur le
support complet de B. La borne d'union sur les 256 sorties emploie le pire des
deux bits ; elle ne suppose pas l'indépendance des sorties.

| Scénario exploratoire, u exact | dv | log2 borne supérieure pour tout message fixé | C05 établi par cette borne ? |
|---|---:|---:|---|
| q=3329, η1=η2=2 | 5 | −136,631859 | Non, borne insuffisante |
| q=3329, η1=η2=2, v exact aussi | 12 | −155,735525 | Non ; la borne inférieure établit aussi le rejet |
| q=7681, η1=η2=3 | 5 | −319,633504 | Oui, dans le modèle CBD |
| q=7681, η1=η2=3, v exact aussi | 13 | −362,165005 | Oui, dans le modèle CBD |

Les huit marginales des deux lignes à q=3329 retrouvent exactement les bornes
correspondantes de `run-003`. Dans les lignes sans perte, le nombre de bits
désigne une transmission exacte de coefficients ; aucune API Compress_12 ou
Compress_13 de FIPS 203 n'est revendiquée.

Dans le même agencement logique que les scénarios précédents, u exact à
q=7681 occuperait `6*256*13/8 = 2496` octets et v sur 5 bits 160 octets, soit
**2656 octets** de chiffré. C'est 384 octets de plus que le scénario du=11,
dv=5 de `run-001`, qui reste étudiable. Cette augmentation est une conséquence
arithmétique du témoin, sans gel de format ni implémentation du KEM.

## 4. Seconde borne indépendante par Chernoff rationnel

Cette vérification n'utilise pas la récurrence de puissance de polynôme ni le
calcul complet des queues de `noise_exact.py`.

Pour z=13/10 et X,Y indépendants de loi CBD3, définir
`Mprod(z)=E[z^(X*Y)]`. La loi de e2 donne
`Me2(z)=((z+2+z^-1)/4)^3`. Les sommes sont évaluées exactement avec des
fractions ; Mprod est obtenu par énumération pondérée des valeurs CBD.

Les deux bits sont correctement décodés pour toute erreur de v permise si
`|B| ≤ 1799`. L'échec implique donc `|B| ≥ 1800`. Par symétrie et l'inégalité
de Markov appliquée à z^B :

`Pr[échec du message] ≤ 2*256*Mprod(z)^3072*Me2(z)/z^1800`.

Le résultat rationnel a pour logarithme affiché −310,085969. Son numérateur N
et son dénominateur D sont conservés en hexadécimal dans
`correctness-certificate.json`, afin de permettre un contrôle entier sans
limite d'export des grands entiers décimaux. Le critère C05 est décidé par
**`2^874 * N^5 ≤ D^5`**, sans recours au logarithme affiché.

Les tests comparent les MGF à l'énumération de toutes les chaînes de bits CBD,
vérifient les régions sûres par décodage exhaustif et contrôlent la majoration
sur une petite somme entièrement énumérée. Le certificat est rejoué par un
vérificateur séparé. Sa provenance a été ajoutée avant le premier gel Git de
`run-004` ; les deux premiers fichiers du run n'ont pas été modifiés.

## 5. Portée pour les clés et les usages répétés

La borne concerne des clés et des bruits honnêtement tirés selon les primitives
CBD indépendantes. Elle n'est pas une garantie pour chaque clé fixée. Pour Q
encapsulations honnêtes utilisant ces clés, une borne d'union donne Q fois la
borne moyenne, sans exiger des clés différentes à chaque usage. Avec Q=2^32,
le calcul de queues donne une borne d'environ 2^-287,633504.

Une conséquence prudente pour la variabilité est également disponible. Si
p(K) est la probabilité d'échec honnête conditionnelle à une clé, l'inégalité
de Markov donne `Pr_K[p(K)>2^-175] ≤ 2^175*E_K[p(K)]`. Le certificat Chernoff
majore ce dernier terme par environ 2^-135,085969. Cela ne décrit pas la forme
de la distribution des clés faibles et ne couvre pas des chiffrés choisis ou
un oracle d'échec.

Le modèle de primitives CBD indépendantes ne démontre pas une équivalence
informationnelle avec une instanciation SHAKE fixée. La transformation CCA,
les attaques exploitant les échecs et le traitement des entrées invalides
restent des analyses distinctes.

## 6. Décision dans J2

La correction dispose maintenant d'un témoin dont la borne ne dépend ni d'une
uniformisation de u ni d'une indépendance de δv. P0 demeure un résultat négatif
dans les modèles antérieurs ; ce travail ne transforme pas ses estimations
conditionnelles en probabilité réelle démontrée.

Avant la clôture de J2, il reste à confronter les scénarios de réparation aux
attaques récentes, à leurs modèles de score et aux budgets mémoire, puis à
consolider C01 à C06. L'option conservatrice sans arrondi u peut servir de
point de comparaison aux formats plus compacts. Le choix final des paramètres
et le développement du KEM de rang 6 suivent cette décision de faisabilité.

## Reproduction et conservation

```powershell
python -m unittest discover -s research -p test_u_dependency.py
python -m unittest discover -s research -p test_witness_chernoff.py
python research/verify_u_dependency_results.py
python research/verify_witness_certificate.py
python research/run_u_dependency.py --output artifacts/generated/u-dependency-nouveau
.\scripts\dev.ps1 check
```

Les scripts sont autonomes en Python standard et les résultats de `run-001`,
`run-002` et `run-003` restent inchangés. Les commandes de vérification
rejouent le certificat sans écraser les données. Une nouvelle conservation
scientifique reçoit un nouvel identifiant.
