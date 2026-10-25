# H12 — Quatrième moment CBD complet sur listes réduites

Préenregistrement du 25 octobre 2026 avant nouveaux résultats. Réutiliser
les quatre matrices et huit banques q=7681/η=3 de run-017 et les trois
ordres publics norme/hachage/glouton de run-018. Aucun coût d'attaque,
profil, seuil C05 ou clôture J2.

## Périmètre fixé

Préfixes de tailles N=4,8,16 dans chacun des trois ordres, mêmes candidats
et codes 140/21, réseau de dimension 5. Partager les résultats lorsque
les ensembles d'indices sont identiques. Ne pas choisir de nouvelles
matrices, graines, tailles ou sélections après observation.

Décalages de run-017 d'indices 0,1,22,24 : vrai candidat, unité, tout-un,
premier pseudo-aléatoire fixé. Trois faux candidats, pas q^21−1.
Coefficients complets a=(y,x,r), étiquettes c et Z=(e,s_l,s_f), 145
variables iid-CBD(3), score S_d= moyenne cos(2*pi*(aᵀZ−cᵀd)/q).

## Développement des moments de population

Pour p=1..4, développer S_d^p avec les fréquences signées (±a_i,±c_i).
L'identité de caractères donne chaque terme :
`phi_eta(somme signée a)*cos(2*pi*(somme signée c)ᵀd/q)/(2N)^p`,
avec `phi_eta(v)=produit cos(pi*center(v_j)/q)^(2*eta)`.

Voie primaire : multisets des 2N fréquences signées, multiplicités
exactes p!/produit(m_j!). Voie indépendante : multisets des N indices
de cosinus, puis les 2^p choix de signes, avec multiplicités d'indices.
Contrôler dans les deux voies la masse totale (2N)^p.

Séparer les termes équilibrés, où chaque vecteur apparaît autant avec
le signe + que − : contributions indépendantes exactes 0,1/(2N),0,
3/(4N²)−3/(8N³). Compter séparément les annulations complètes modulo q
qui ne sont pas de cette forme. Ne pas assimiler un petit caractère
numérique à une annulation algébrique.

Sommer les corrections hors termes équilibrés dans le domaine
logarithmique, avec signes, sommes positives/négatives et masse absolue.
Conserver toute annulation numérique sensible. Calculer les moments
centrés, dissymétrie et kurtosis ; conserver séparément le très petit
écart à la kurtosis du témoin de cosinus indépendants, sans soustraction
des flottants presque égaux. Les caractères sont évalués numériquement :
ces moments de population ne sont pas des certificats par intervalles.

## Comparaisons et contrôles

- Vérifier moyenne/variance avec les identités de covariance de run-017
  appliquées aux mêmes sous-listes ; garder les biais en logarithmes.
- Calculer les moments uniformes exacts par les fréquences y seules,
  comme dans run-018, en distinguant cette autre population.
- Réutiliser les 4096 états CBD par matrice de run-018, leurs étiquettes
  et empreintes, sans prétendre fournir de nouveaux échantillons. Vérifier
  les phases et comparer les moments empiriques jusqu'à quatre aux
  moments de population numériques. Ces mesures ne résolvent pas les
  biais très petits ni les queues cryptographiques rares.
- Tests sur un petit modèle entièrement énuméré, phases décalées,
  multiplicités, annulations non triviales et stabilité du centrage.
- Contre-vérification indépendante sans import arithmétique du projet :
  autre développement, tables de caractères calculées par une série
  Decimal à 80 chiffres puis sommation indépendante, contrôle des masses,
  des corrections signées et des événements échantillonnés. Vérifier
  les petites différences relativement à la masse absolue des corrections.

## Conservation et décision

Nouveaux scripts et run-019, sans modifier les dix-huit instantanés.
Enregistrer indices, comptes de termes et multiplicités, corrections
signées/logarithmiques, caractères arrondis à zéro, diagnostics de
conditionnement, phases reconstructibles, durées et tailles de tableaux
explicitement recensées. NumPy 2.3.5 local, aucune installation globale.
Exécuter `scripts/dev.ps1 check`, mettre rapport et journal à jour.

La proximité éventuelle de moments avec un témoin indépendant ou une
normale ne certifie pas la queue du score. Ne pas extrapoler ces petites
listes à 2^248 vecteurs, au réseau de dimension 2576 ou aux rotations
MLWE. Juger les trois sélections sur ce qui est effectivement calculé,
en conservant les cas défavorables et les limites.
