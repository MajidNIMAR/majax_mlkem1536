# H09 — Conditions de transfert du score à q=7681

Préenregistrement du 25 octobre 2026, avant calcul des nouveaux résultats.
Entrées figées : minima de run-009 et résidus/statistiques de run-011.
Aucun nouveau profil ni coût d'attaque optimisé ; J2 reste ouvert.

## Question et périmètre

Quantifier les hypothèses qui séparent les identités CBD exactes de
l'estimation duale avec code idéal. Étudier les quatre minima existants,
avec priorité aux deux scénarios q=7681/η=3. Ne pas extrapoler les rapports
de queues observés à q=17 aux paramètres réels.

## Calculs prévus

1. Reconstituer le facteur de code GV de run-009 et séparer, par différence
   des logarithmes, son facteur réseau conditionnel. Contrôler le budget
   normal historique avec `Q(sqrt(2*N)*mu)` et `M=R*q^kfft`.
2. À N, mu et M fixés, mesurer le budget normal si la variance passe de
   1/(2N) à ν/(2N), pour ν=1, 1,01, 1,1 et 2. Ce sont des sensibilités,
   pas des distributions observées. Chiffrer la covariance moyenne
   hors diagonale compatible avec des hausses de 1 %, 10 % et 100 %.
3. Appliquer Cantelli puis l'union aux mêmes moments supposés :
   min(1,M/(1+2*N*mu²)). Chiffrer la taille N suffisante pour que cette
   borne atteigne 0,05 à mu fixé. Une borne sans information ne démontre
   ni l'échec de l'attaque, ni sa complexité ; les moments supposés ne sont
   pas validés par cette substitution.
4. Décrire le volume d'une liste sous deux représentations explicites :
   coordonnées modulo q empaquetées, ou 64 bits par coordonnée. Budgets
   illustratifs 2^40, 2^60, 2^80 octets, sans imposer une nouvelle contrainte
   au cahier des charges. Ne pas revendiquer de borne mémoire universelle.
5. Recalculer les moyennes CBD et gaussiennes des 256 résidus de chaque
   code concret apparié. Remplacer uniquement le facteur code dans une
   sensibilité à beta fixé, sans certifier de moyenne de population, sans
   supposer que le code et la liste réelle ont cette loi jointe et sans
   annoncer de coût révisé. Conserver les deux familles, même défavorables.

## Vérification et critères d'arrêt

Nouveaux scripts Python standard, résultats run-016, aucun écrasement des
quinze instantanés. Vérification indépendante sans import arithmétique du
projet : Decimal à 90 chiffres, série alternée pour l'intégrale du code,
encadrement de la queue normale par intégrations par parties (Mills),
reconstruction des statistiques et contrôles de formules. Les évaluations
numériques ne seront pas présentées comme certificats par intervalles.
Tests des bornes et des erreurs d'usage ; `scripts/dev.ps1 check` complet.

Livrable : données quantitatives et contrat d'entrée d'un futur score
complet (liste y,x,r,c, loi de sélection, moments conditionnels des faux
candidats et contrôle de queue). Refuser tout transfert de coût tant que
ces entrées manquent. Le seuil C05 et les paramètres restent inchangés.
