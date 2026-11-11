# M08 — Rejet idéal et information latérale classique

11 novembre 2026. Ce volet accompagne le durcissement de l'import des clés.
Il généralise une hypothèse du [résultat M06](REJET_IMPLICITE_R1_M06.md),
sans modifier les paramètres, les domaines ou le moteur. **C01 reste ouvert.**

## Objet et résultat conditionnel

Le programme utilise `J_z(c) = SHAKE256(TAG || "J\0" || z || c, 32 octets)`.
M06 étudie sa version idéale pour une clé z uniforme de 256 bits, indépendante
de la vue idéale de l'adversaire. Considérons ici une variable classique E
qui représente de l'information latérale corrélée à Z. Sa probabilité optimale
de deviner la clé après observation de E est

`p_guess(Z|E) = Σ_e Pr[E=e] max_z Pr[Z=z|E=e]`.

Cette quantité est une moyenne pondérée des maxima a posteriori, pas la
moyenne non pondérée des lignes ni l'entropie de Shannon. Supposons qu'un
nombre rationnel p majore cette quantité. Dans le jeu idéal défini ci-dessous,
pour q appels publics et D accès classiques à la fonction indexée :

- si D=0, les deux jeux ont exactement la même loi : écart nul ;
- si D>0, `ε_J,ROM ≤ min(1, q p)` ;
- si D>0, `ε_J,QROM ≤ min(1, 2q √p)`.

Il s'agit d'écarts absolus de probabilités de distinction dans [0,1], pas de
biais de devinette CCA dans [0,1/2]. Avec `p=2^-256`, on retrouve exactement
les deux bornes M06. Ce raffinement des hypothèses **ne resserre pas** la borne
QROM dans le cas uniforme déjà étudié.
Pour une clé de 256 bits, p_guess est toujours au moins 2^-256 ; le calculateur
refuse une borne annoncée plus petite, incompatible avec cet alphabet de clés.

## Jeu et hypothèses requises

L'adversaire reçoit E. Le domaine public J de l'oracle idéal, noté H_J,
et la fonction aléatoire indépendante R sont indépendants de la paire (E,Z).
Les oracles des autres domaines peuvent faire partie de la vue auxiliaire ;
ils ne doivent apporter aucune information supplémentaire sur Z après E.
Plus précisément, conditionnellement à E, la vue complète dans le jeu idéal
avant remplacement de la ligne secrète est indépendante de Z. Les fonctions
idéales H_J et R sont également indépendantes de ces fonctions auxiliaires.

Le jeu réel donne l'oracle public H_J et la fonction classique
`c ↦ H_J(Z,c)`. Le jeu idéal donne H_J et R indépendante. Les autres domaines
sont inchangés. Chaque appel public potentiellement en superposition entre
domaines, clés ou longueurs de sortie compte dans q ; il n'est pas gratuit
parce qu'une partie de sa superposition concerne un autre domaine. Les D
appels à la fonction indexée restent **classiques**, y compris en QROM.

Cette hypothèse d'indépendance doit être établie dans le jeu visé. Une simple
valeur annoncée de p, un champ dans une clé sérialisée ou une estimation de
l'entropie de Shannon ne la démontre pas. L'énoncé ne couvre pas une mémoire
quantique corrélée à Z. Il ne fournit pas de mesure d'entropie de l'aléa système.

## Dérivation

On reprend le couplage de M06 : remplacer simultanément toute la ligne Z
de H_J par R, avec cohérence des répétitions et des préfixes de sortie.
Pour (e,z) fixé, la table après remplacement reste uniforme et sa ligne z
vaut R. Les lois jointes sont donc celles du jeu réel et du jeu idéal.
La distribution classique de (E,Z) et les autres domaines sont inchangés.

Dans le ROM, conditionnellement à E=e, la liste de candidats publics du jeu
idéal reste indépendante de Z. Chaque candidat couvre au plus
`max_z Pr[Z=z|E=e]`. Une union sur au plus q candidats, puis l'espérance sur E,
donnent une probabilité de rencontre au plus `q p_guess(Z|E) ≤ q p`. Les jeux
classiques sont identiques jusqu'à cette rencontre. Les D réponses indexées
consultent R indépendante ; elles ne nécessitent pas un facteur D supplémentaire.

Dans le QROM, soit w_i(e,z) le poids de la ligne z dans la i-ème requête
publique du jeu idéal, avec E=e. Les lignes sont disjointes et leur poids total
est au plus 1, le reste pouvant concerner d'autres domaines. Ainsi

`E_(E,Z)[w_i(E,Z)] ≤ Σ_e Pr[E=e] max_z Pr[Z=z|E=e] ≤ p`.

La différence de deux portes d'oracle n'agit que sur la ligne remplacée.
Sa norme sur cette requête est au plus `2√w_i`. La même hybridation que M06,
la concavité de la racine et l'inégalité triangulaire donnent

`écart ≤ 2 Σ_(i=1)^q E[√w_i] ≤ 2q √p`.

Le plafonnement par 1 est celui d'un écart de probabilités. Les accès indexés
des deux hybrides utilisent le même R, avec les mêmes réponses aux répétitions.
Quand D=0, aucune corrélation indexée n'est révélée et les deux jeux publics
sont simplement les mêmes oracles aléatoires : l'écart vaut zéro.

Cette dérivation dépend du couplage et du lemme quantique explicités en M06.
Les petites énumérations du programme contrôlent des cas finis et des
inégalités exactes ; elles ne remplacent pas la preuve pour tout adversaire.

## Lien avec l'import de clés

Un import R1 valide les longueurs, les coefficients encodés, la clé publique
intégrée et son hash. **Il n'authentifie ni l'origine honnête ni l'entropie de z.**
Une clé structurellement valide peut porter un z fixé et connu de l'adversaire. L'entropie
conditionnelle est alors nulle et p_guess=1 ; la borne devient triviale dès
q≥1 et D>0. Sur un petit oracle à huit sorties, un unique test d'un candidat
connu donne déjà un écart exact 7/8, ce que retrouve l'énumération indépendante.
Cet exemple distingue les jeux de PRF de rejet ; il ne constitue pas à lui
seul une attaque IND-CCA contre le moteur KEM.

Cela ne motive pas une liste noire de valeurs de z. Rejeter une constante ne
prouve pas l'ignorance de l'adversaire et modifierait le contrat d'import.
Une valeur particulière peut également être tirée par un générateur honnête.
Le durcissement de M08 porte sur les temporaires produits pendant la validation ;
il ne transforme pas la syntaxe en certificat de génération honnête.

## Calculateur, contrôles et limites

`research/rejection_side_info_m08.py` produit dix panneaux rationnels pour des
hypothèses d'entropie conditionnelle 0/64/128/192/256 bits et q=2^32/2^64,
plus le cas D=0. Une racine générale est encadrée vers l'extérieur par des
fractions dyadiques, avec justification par inégalités entières. Les puissances
de deux p=2^-h à h pair ont ici une racine exacte.

Pour q=2^64 et D>0, les panneaux donnent :

| Hypothèse h, avec p_guess≤2^-h | Majorant ROM | Majorant QROM |
|---:|---:|---:|
| 0 | 1 | 1 |
| 64 | 1 | 1 |
| 128 | 2^-64 | 1 |
| 192 | 2^-128 | 2^-31 |
| 256 | 2^-192 | 2^-63 |

Ce tableau évalue le majorant conditionnel du jeu de rejet, sans transformer
ces valeurs en coût d'attaque ou en niveau global de sécurité du KEM. La borne
quantique uniforme reste trop lâche pour certifier le budget illustratif M05.

Les contrôles indépendants parcourent toutes les petites tables H/R pour
des clés non uniformes et E corrélée, des choix adaptatifs, un cas sans
requête indexée, un candidat entièrement révélé et des poids de requêtes
rationnels. Ils distinguent distribution jointe et moyennes de postérieurs.
Le cas uniforme 256 bits est comparé au calculateur M06, sans modifier ses
sources ni ses instantanés.

Le gel de ce volet est `results/security/m08-rejection-001`, après revue de
la dérivation. Il conserve sources, contrôles, contrat littéral J et résultats.
Le rejeu vérifie les octets et recalcule les fractions, sans expérience.

Les garanties SHAKE concrètes, le PKE à graines, les constantes du raccord
FO complet, les clés adverses du KEM et la preuve IND-CCA globale restent
distincts et ouverts. Ce travail ne prouve ni temps constant ni effacement,
et n'est pas une validation externe de la construction.
