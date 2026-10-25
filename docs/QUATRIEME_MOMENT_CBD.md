# H12 — Quatrième moment du score CBD complet

Étude du 25 octobre 2026, [protocole](PROTOCOLE_H12.md) préenregistré au
commit `8354d10`, [résultats run-019](../results/j2/run-019/summary.json).
Le calcul porte sur la loi de population CBD idéale des coefficients
complets ; les caractères sont évalués numériquement, sans certificat
par intervalles. Aucun coût global, profil ou seuil C05 n'est modifié.

## Périmètre et sens du résultat

Quatre matrices q=7681/η=3, réseau de dimension 5, codes répété/pondéré
140/21 de run-017. Les trois ordres publics norme/hachage/glouton de
run-018 sont repris sans ajustement, avec préfixes 4,8,16. Les 36 panneaux
désignent 32 ensembles distincts, donc **64 banques CBD** avec les deux
codes. Les quatre décalages sont vrai, unité, tout-un et premier
pseudo-aléatoire fixés, soit trois faux candidats choisis.

Les **1024 moments** correspondent à 64 banques × 4 décalages × ordres
1..4. Ils sont calculés par développement de l'espérance, sans estimation
Monte-Carlo de ces moments et sans énumération des 2^870 configurations
de bits. Les queues restent non certifiées. Ces listes ne sont pas
les listes de l'estimation d'attaque en dimension 2576.

## Développement complet, avec les phases

Pour a_i=(y_i,x_i,r_i), étiquette c_i et Z iid-CBD(3),
`S_d(Z)=somme_i cos(2*pi*(a_iᵀZ−c_iᵀd)/q)/N`.
Développer la puissance p introduit les 2N fréquences signées (±a_i,±c_i).
Pour chaque multiset de p fréquences, la multiplicité exacte vaut
`p!/produit(m_j!)`. La contribution de population est
`multiplicité*phi(somme signée a)*cos(2*pi*(somme signée c)ᵀd/q)/(2N)^p`,
où `phi(v)=produit cos(pi*center(v_j)/q)^6`.

Le code vérifie la masse totale (2N)^p et sépare les termes équilibrés,
où chaque vecteur apparaît autant avec + que −. Ces termes donnent
exactement les contributions de cosinus indépendants :

| Ordre p | Contribution équilibrée |
|---|---|
| 1 | 0 |
| 2 | 1/(2N) |
| 3 | 0 |
| 4 | 3/(4N²)−3/(8N³) |

Les contributions restantes sont calculées, avec leur signe et leur
masse absolue. On compte séparément les sommes de coefficients complets
nulles modulo q hors appariements équilibrés : **aucune n'est rencontrée**
dans cette étude. Les petits modèles de test contiennent au contraire
une relation non triviale afin de vérifier que le calcul la conserve.

Les relations sur y seules ne suffisent pas. Si une somme signée de y
est nulle, alors la somme correspondante de x est nulle modulo q et
`somme r = −G*(somme c) mod q`. Les étiquettes issues du décodage n'ont
aucune obligation de s'annuler. Le caractère du vecteur complet est donc
calculé ; il n'est pas remplacé par 1 du seul fait que les y s'annulent.
Cela distingue les moments CBD du témoin uniforme de H11.

## Résultats de population

La kurtosis est ici le quatrième moment centré divisé par la variance
au carré. Pour N cosinus indépendants uniformes, elle vaut 3−3/(2N),
alors que la normale vaut 3. Les résultats complets restent proches du
premier témoin pour les vrais et les trois faux candidats étudiés.

| N | Sélection | Kurtosis uniforme moyenne, y seuls | Référence cosinus indépendants | Kurtosis CBD complète, moyenne affichée des vrais candidats |
|---|---|---:|---:|---:|
| 4 | norme | 2,625000 | 2,625000 | ≈2,625000 |
| 4 | hachage | 2,625000 | 2,625000 | ≈2,625000 |
| 4 | glouton | 2,625000 | 2,625000 | ≈2,625000 |
| 8 | norme | 3,843750 | 2,812500 | ≈2,812500 |
| 8 | hachage | 2,882813 | 2,812500 | ≈2,812500 |
| 8 | glouton | 2,812500 | 2,812500 | ≈2,812500 |
| 16 | norme | 6,351563 | 2,906250 | ≈2,906250 |
| 16 | hachage | 3,527344 | 2,906250 | ≈2,906250 |
| 16 | glouton | 3,146484 | 2,906250 | ≈2,906250 |

Les corrections sont conservées séparément : cette proximité d'affichage
n'est pas une identité mathématique. Sur les 256 cas banque/décalage,
l'écart numérique calculé maximal à la kurtosis indépendante est environ
**5,775×10^-16**, au code pondéré, matrice 2, N=4, vrai candidat.
Pour le contrôle répété, le maximum est environ 6,843×10^-87.
La dissymétrie maximale calculée vaut environ 4,162×10^-10 au pondéré
et 1,075×10^-49 au répété. Les signes et logarithmes des petites
corrections sont fournis, y compris lorsque leur valeur flottante
ne permet plus de les distinguer d'une référence.

À N=16/code pondéré, la moyenne des log2 du biais vrai est −32,5368
pour norme, −33,7114 pour hachage et −33,7729 pour glouton. La réduction
du quatrième moment uniforme ne fournit donc pas, sur ces petites
listes, un avantage comparable sur le quatrième moment CBD complet.
Les écarts de biais entre sélections restent à considérer.

Ce résultat ne démontre ni l'indépendance des scores, ni la normalité,
ni un succès de récupération. Les moments 1..4 ne déterminent pas la
queue rare. À N=16, même le témoin indépendant a une kurtosis 2,90625,
distincte de 3 ; aucune queue normale n'est adoptée à partir du tableau.
Les trois faux décalages ne couvrent pas q^21−1 candidats.

## Stabilité des très petites contributions

La voie primaire calcule **1 537 856 multisets signés**, représentant
**27 730 176 termes ordonnés pondérés** avant évaluation des quatre
décalages. Elle sépare exactement les fractions équilibrées, puis somme
les corrections positives et négatives dans le domaine logarithmique.
Les moments centrés utilisent une arithmétique Decimal à 100 chiffres
sur ces corrections numériques ; une formule séparée conserve l'écart
à la kurtosis indépendante sans soustraire deux flottants presque égaux.
Cette précision arithmétique ne transforme pas les caractères évalués
en double précision en certificats à 100 chiffres.

Une exponentiation directe des caractères arrondirait à zéro une masse
de 95 818 termes ordonnés. Ces diagnostics sont conservés ; les sommes
logarithmiques évitent de perdre systématiquement les petites corrections
totales. Les contributions rescalées restent soumises aux arrondis
flottants. Aucun cas ne déclenche le seuil d'annulation sensible
`abs(correction)/masse_absolue < 10^-10` dans cette exécution.

Un test synthétique impose une correction de quatrième moment 2^-1200 :
la kurtosis flottante reste égale à la référence affichée, mais son
écart signé et logarithmique est correctement conservé. Cela vérifie
la représentation, sans prétendre certifier des effets physiques aussi
petits sur un KEM.

## Contrôles indépendants et échantillons réutilisés

La seconde implémentation n'importe pas l'arithmétique du projet. Elle
énumère les multisets des N indices de cosinus puis les 2^p signes,
au lieu des multisets de 2N fréquences signées. Elle effectue
**1 824 768 évaluations indice/signes** et retrouve les mêmes masses,
termes équilibrés, annulations complètes et moments.

Les facteurs de caractères sont construits par une série Decimal à
80 chiffres puis convertis pour les sommes numériques. L'écart maximal
sur les champs comparés, logarithmes compris, est environ 8,38×10^-12.
L'erreur des corrections signées, rapportée à leur propre masse absolue,
reste inférieure à 2,37×10^-13. Ces contrôles ne sont pas des encadrements
par intervalles. Les 256 contrôles séparés moyenne/variance retrouvent
les identités de covariance de run-017 appliquées aux mêmes sous-listes.

Les 16 384 états CBD de H11 sont **réutilisés**, avec mêmes étiquettes
et empreintes. Les 4 194 304 identités de phase des banques complètes
sont rejouées, sans les présenter comme des données nouvelles. Les
moments empiriques et événements de seuil sur les nouvelles sous-listes
sont reconstruits indépendamment. Par exemple à N=16/norme/pondéré,
la kurtosis empirique moyenne vaut environ 2,9245, contre une valeur
de population calculée voisine de 2,90625 : l'échantillonnage conserve
sa variabilité et ne mesure pas les corrections de l'ordre 10^-16.

Quatre nouveaux tests couvrent 243 états CBD pondérés et cinq décalages,
les relations non triviales, les multiplicités, l'arrondi extrême et
le rejet des entrées hors périmètre. La somme des temps d'expansion
instrumentés vaut environ 19,53 s, dont 17,40 s pour les banques N=16.
Les lots comptent au plus 512×145 coefficients après sommation des
fréquences ; les tableaux intermédiaires, états, phases et objets Python
ne sont pas inclus dans ce seul compte. Ces données ne représentent
ni un RSS système ni un coût extrapolé d'attaque.

## Reproduction et suite

Runtime local NumPy 2.3.5 :

```powershell
.tools/research-venv/Scripts/python.exe research/run_cbd_fourth.py --output artifacts/generated/h12-nouveau
.tools/research-venv/Scripts/python.exe research/verify_cbd_fourth_independent.py --run artifacts/generated/h12-nouveau
```

Le lanceur refuse un dossier existant. Les vérificateurs sans argument
rejouent run-019 et sont intégrés à `scripts/dev.ps1 check`.

Le contrôle atteint désormais le quatrième moment CBD complet sur les
petites listes. La prochaine étape est d'étendre aux listes de 32
vecteurs avec un encadrement explicite des contributions, afin de
maîtriser le coût combinatoire et l'erreur numérique avant extrapolation.
Conserver les trois sélections sans adopter la minimisation du moment
uniforme comme objectif du score LWE.

Les listes en dimension 2576, les queues cryptographiques rares,
les rotations MLWE et les autres critères de J2 restent ouverts.
Aucun profil, niveau global de sécurité ou nouvelle norme n'est validé.
