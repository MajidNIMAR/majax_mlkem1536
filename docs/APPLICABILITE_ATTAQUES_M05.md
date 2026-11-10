# M05 — applicabilité de la veille aux comparaisons

26 octobre 2026. Cette lecture ciblée accompagne le protocole M05 et les
nouveaux calculs comparatifs. Elle complète la veille du 24 octobre sans
réécrire ses résultats. Elle ne constitue pas une intégration de toutes les
publications dans l'estimateur figé.

## Corrélations et compression

La notice primaire de Xiao, [ePrint 2026/2250](https://eprint.iacr.org/2026/2250),
reçue le 28 septembre et approuvée le 30 septembre 2026, décrit des
réévaluations du taux d'échec de plusieurs candidats NGCC. Elle distingue
les dépendances entre blocs, les termes de compression omis et la recherche
de chiffrés faibles sous plafond de requêtes. Les auteurs ne revendiquent
pas une récupération de clé par les attaques décrites. Les estimations
lointaines de queue restent soumises à leurs modèles et extrapolations.
La consultation M05 porte sur cette notice, pas sur une reproduction des
expériences ou une lecture vérifiée de tous les détails du PDF.

Conséquence pour R1 : son certificat conserve les dépendances possibles
entre coefficients grâce à une borne d'union ; il ne multiplie pas des
probabilités marginales. Il n'existe pas de compression de la clé publique
ou de u à ajouter à sa formule de bruit. L'erreur de quantification de v
est traitée par son support, sans indépendance supposée. Ces propriétés
répondent à des erreurs de modélisation identifiées ; elles ne démontrent
pas à elles seules une sécurité contre une recherche adaptative d'échecs.
Cette dernière dépend du jeu et de la réduction FO du volet sécurité.

Conséquence pour le panel M05 : une clé publique arrondie ou tronquée doit
être représentée comme telle. Ajouter un bruit indépendant de variance
semblable n'est pas une identité de distributions pour son programme.
Un proxy précompression et une sensibilité d'arrondi doivent rester
séparés du problème publié et du classement des moteurs complets.

## Scores du dual

[Li et Zheng, ePrint 2026/1048](https://eprint.iacr.org/2026/1048), révisé
le 14 octobre 2026, examine les covariances des scores et les distributions
des bonnes et mauvaises hypothèses dans plusieurs variantes de l'attaque
duale. La notice primaire confirme que remplacer les scores par une somme
de contributions supposées indépendantes pose un problème de variance.
Le texte n'est pas transformé ici en facteur numérique correctif de R1.

Les sorties de l'estimateur figé sont donc conservées sous leur propre
contrat heuristique. Ni une valeur `rop` ni un coût de réduction ne fournit
directement une borne d'avantage IND-CPA, une probabilité globale de succès
ou une validation des queues du score. Le travail J2 déjà figé sur les
scores n'est pas crédité comme une résolution de cette obligation.

## Hybride primal et ressources

[Karenin et al., Fast Slicer, ePrint 2025/1910](https://eprint.iacr.org/2025/1910),
dernière révision annoncée le 27 octobre 2025, fournit un algorithme et une
implémentation de Batch-CVP dans une attaque hybride. La notice primaire
rapporte des essais LWE en dimensions 160 à 210, y compris une distribution
binomiale centrée, et un résultat asymptotique dépendant de l'entropie.

Le facteur pratique maximal annoncé sur ces essais n'est pas soustrait
des coûts de dimension 1024 ou 1536. Une comparaison intégrant cet algorithme
doit expliciter son modèle de dimension, sa précomputation, sa distribution,
son stockage et sa probabilité de réussite. L'absence de ce transfert
interdit de présenter le panel M05 comme une borne sur toutes les meilleures
attaques connues. Les compromis quantiques temps/mémoire déjà recensés
restent également séparés du coût classique MATZOV.

## Accès aux sources et décisions

Les notices primaires 2026/2250, 2026/1048 et 2025/1910 ont été consultées
le 26 octobre 2026, heure locale Europe/Paris. L'accès direct à
2026/2565 a encore échoué pendant cette séance ; cet échec ne valide ni
n'invalide son résultat. Aucun coût de cet article n'est appliqué à R1.

Le panel calculé doit être présenté comme une extension reproductible de
modèles explicités, avec les proxys signalés. La fermeture du coût du
dual avec score validé, la mémoire bornée et les adaptations récentes
demeurent des obligations distinctes. Le résultat utile pour le moteur
est une décision justifiée sur la conservation ou la modification de R1,
pas un nombre global de bits ni une affirmation de supériorité universelle.
