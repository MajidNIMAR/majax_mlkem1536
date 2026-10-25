# H05 — Comparaison de critères du décodeur auxiliaire

Protocole enregistré le 24 octobre 2026 avant l'exécution de la comparaison.
Il prolonge run-011, sans modifier les codes ou paramètres du KEM.

## Question et modèle

Sur les mêmes codes par blocs et les mêmes cibles, sélectionner un mot par
son biais CBD plutôt que par la distance euclidienne améliore-t-il assez
la contribution auxiliaire pour justifier son coût ? Le secret reste idéal,
iid-CBD et indépendant de la cible. Une amélioration de cette contribution
peut aider l'attaque ; elle n'est pas un gain de sécurité du KEM.

Le coût exact visé est `C(r)=Σ −2 ln cos(π |r_i|/q)`, pour les représentants
centrés. Maximiser `φ(r)=exp(−η C(r))` revient à minimiser C. Le choix du mot
ne dépend donc pas de η, tant que toutes les coordonnées ont le même η>0.
La somme et le produit se séparent par blocs indépendants du code.

## Calcul et garantie

Fixer `S=2^40`. Construire par arithmétique d'intervalles les entiers
`w[d]=floor(S * (−2 ln cos(π d/q)))`. Vérifier que l'intervalle est contenu
dans `[w,w+1)`, avec w[0]=0 exactement. Le décodeur minimise la somme entière
T de ces poids, en prenant le plus petit symbole en cas d'égalité.

Pour un vecteur de n coordonnées, `T/S ≤ C < (T+n)/S`. Le minimiseur entier
satisfait donc `C_choisi − C_optimal < n/S`, et son écart en log2 du biais
est au plus `η n/(S ln 2)`. Cette garantie ne suppose pas que le meilleur
symbole entier soit toujours le meilleur symbole pour le coût réel.

Un bloc est certifié optimal pour le coût réel si tous les concurrents de
coût entier inférieur à `T_min+taille_bloc` ont le même multiensemble
d'erreurs absolues que le symbole choisi. Les autres sont strictement moins
bons par les intervalles ci-dessus. Des égalités algébriques entre histogrammes
différents peuvent demeurer non résolues ; elles ne doivent pas être
présentées comme des décisions exactes. La garantie d'approximation subsiste.

## Expériences et contrôles prévus

- Six petits modèles complets de run-010 : deux familles et trois formes,
  soit 6302 cibles, avec comparaison au livre de codes entier.
- Huit expériences de run-010, chacune avec les mêmes 256 cibles : 2048
  comparaisons appariées, sans sélection de cibles favorables.
- Deux énumérations complètes de l'alphabet par bloc, pour les deux critères :
  mêmes q×k candidats et q×n contributions par appel. Le balayage rapide du
  contrôle répété historique reste une référence distincte, pas un budget égal.
- Mesures alternées à tables chaudes : sept séries de huit cibles identiques,
  génération, construction des tables et écritures exclues. Rapport des
  durées et de l'environnement local, sans conversion en unités rop.
- Oracle indépendant sur les six petits modèles et 64 blocs aux modules
  réels ; vérification indépendante par intervalles de toutes les tables.

## Données et règle d'interprétation

Conserver symboles, coûts entiers, normes, biais, nombre de blocs certifiés,
observations ambiguës et résultats négatifs. Rapporter les différences
appariées, le rapport des moyennes de biais et la concentration des poids.
Le biais peut croître au prix d'une norme supérieure. La moyenne du gain
logarithmique et le logarithme du rapport des biais moyens sont distincts.
Le rapport de temps seul ne chiffre pas l'utilité dans une attaque complète.

Ne pas ajuster le protocole à un résultat observé sans nouvelle version.
Cette comparaison ne modifie ni les coûts de run-009, ni C05, ni le profil
de recherche ; J2 reste ouvert pour l'intégration au score complet.
