# J2 — Stabilisation locale de la recherche duale

Étape du 24 octobre 2026, conservée dans [run-009](../results/j2/run-009/study.json). Cette étude poursuit run-008 sans modifier son modèle, ses sources, ses calibrations ou ses résultats. Elle traite le plafonnement des trajectoires de recherche ; elle n'évalue pas encore un décodeur concret à q=7681.

## Développement effectué

Le module `refine_coded_dual.py` reprend les meilleurs points et les points terminaux des trajectoires de run-008. Les évaluations déjà conservées sont réutilisées par leurs indices. Toute nouvelle configuration reçoit un indice distinct, supérieur ou égal à 1043, et est enregistrée immédiatement. L'intégrité du parent est contrôlée avant les calculs.

Chaque départ suit quatre étapes de descente : pas (16,4,8,2), puis (8,2,4,1), puis (4,1,2,1), enfin (1,1,1,1). Les coordonnées sont le nombre d'échantillons m, le nombre a de coordonnées supposées nulles, nfft et kfft. La dernière étape explore les changements simultanés d'une ou deux coordonnées. Elle contrôle huit voisins sur un axe et vingt-quatre sur deux axes, soit 32 voisins au total lorsque tous sont admissibles.

À chaque balayage, la meilleure amélioration parmi les voisins est retenue si elle dépasse 10^-10 dans log2(coût). L'arrêt intervient lorsqu'aucun voisin admissible ne satisfait ce critère. Un plafond de sécurité à 1000 balayages provoque une erreur et interdit de déclarer la stabilité. Un diagnostic d'attaque non résolu dans le voisinage interdit également cette déclaration. Aucun de ces arrêts bloquants n'a été rencontré. Le maximum observé est vingt balayages pour une étape, au-delà de l'ancien plafond de douze.

Le domaine reprend les limites déclarées : 1≤m≤dimension LWE, 0≤a≤96, 8≤nfft≤256, 1≤kfft<nfft, a+nfft<dimension LWE et dimension du réseau au moins 200. L'anneau reste de degré 256, de rang 4 ou 6. Le champ `n` des sorties représente la dimension LWE aplatie 1024 ou 1536.

## Résultats

1187 évaluations nouvelles sont conservées, toutes avec un coût conditionnel retourné. Avec les 1043 évaluations du parent, l'ensemble compte 2230 points : 2156 coûts conditionnels et les 74 refus de cible de probabilité antérieurs. Les 44 trajectoires/étapes enregistrées s'achèvent sur leur critère local, sans atteindre le plafond de sécurité.

| Scénario | Convention | log2(coût) run-008 | log2(coût) après poursuite | beta0 / beta1 |
|---|---|---:|---:|---:|
| Témoin 1024, q=3329,η=2 | LWE | 258,482114 | 258,459513 | 807 / 788 |
| Témoin 1024, q=3329,η=2 | MLWE des auteurs | 256,969531 | 256,968923 | 801 / 783 |
| Rang 6, q=7681,η=3 | LWE | 381,755780 | 381,711763 | 1245 / 1205 |
| Rang 6, q=7681,η=3 | MLWE des auteurs | 379,998696 | 378,984845 | 1234 / 1195 |

Les quatre points retenus possèdent chacun leurs 32 voisins admissibles évalués et aucun n'est sur une frontière du domaine déclaré. Ils sont les meilleurs rencontrés à la tolérance de recherche près. Les vérifications finales sont rattachées aux indices des points, aux coordonnées et aux résultats des voisins ; la reconstruction de ces voisinages utilise une autre formulation dans le vérificateur.

Le point MLWE de rang 6 utilise m=1230,a=50,nfft=140,kfft=21. La baisse de l'exposant du coût estimé est 1,013851, soit un coût modélisé environ deux fois plus petit que le meilleur point précédent. Cela resserre notre estimation d'une attaque : il ne s'agit pas d'un gain de sécurité du candidat. La construction du KEM et ses paramètres n'ont pas changé.

La stabilité est limitée aux déplacements unitaires d'une ou deux coordonnées dans cette boîte de recherche et à la tolérance donnée. Un déplacement plus grand, une modification de trois coordonnées ou le franchissement d'un plateau peut conduire à un meilleur point. Aucun optimum global ni convergence de toutes les recherches possibles n'est revendiqué.

## Vérifications et portée

Quatre tests supplémentaires contrôlent le voisinage de 32 points, un piège où seul un mouvement simultané améliore le coût, la descente sur une fonction connue avec un arrêt de sécurité explicite, et les frontières du domaine.

La voie numérique de run-008 est réutilisée sans modification pour les quatre nouveaux points : fonctions des auteurs avec plafond de réduction adapté, champ Sage de 2048 bits et gamma inférieure/erfc à 160 décimales. Les résultats et leur provenance propre sont conservés. Le contrôle courant Python vérifie les empreintes du parent et de cette étude, la cohérence des coûts, les trajectoires strictement décroissantes, la couverture complète des voisinages finaux et le rattachement des contre-vérifications numériques. Il ne relance pas Sage.

Les hypothèses cryptanalytiques restent celles de [l'étude initiale](DUAL_CODES_ROTATIONS.md) : décodage idéal au rayon GV, coût de décodage supposé, heuristique binomiale MLWE des auteurs, score normal, mémoire exponentielle et extrapolation des coefficients de réduction au-delà de beta=1024 pour le rang 6. La liste du meilleur point MLWE est de l'ordre de 2^247,985 vecteurs. La contre-vérification numérique ne valide pas ces hypothèses et ce coût ne définit pas la sécurité globale du KEM.

## Conséquence pour la suite

Le point qui restait en progression au plafond de run-008 dispose maintenant d'un contrôle local complet sur les 32 voisins définis. La priorité suivante est le décodage concret à q=7681 et l'analyse des scores, plutôt qu'une nouvelle prolongation arbitraire de cette même descente. Une méthode de décodage propre au projet peut être étudiée ; ses performances et ses propriétés devront être comparées aux hypothèses de ce modèle. Les distributions des chiffrés H01/H02, la mémoire et la transformation CCA restent également ouvertes. Aucun profil n'est choisi et J2 reste ouvert.

## Reproduction

Avec le runtime Sage local disponible : `wsl -d Ubuntu-22.04 -- bash scripts/coded-dual-refine.sh --output artifacts/generated/nom-inexistant`. Le calcul refuse de remplacer une étude existante. La contre-vérification utilise `verify_coded_dual_numeric.py` avec `--run` et un nouveau `--output` dans le dossier du calcul. Rejeu courant de l'instantané conservé : `python research/verify_coded_dual_refinement.py`.
