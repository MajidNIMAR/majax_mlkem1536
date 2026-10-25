# H13 — Bornes à 32 vecteurs et retour au moteur

Préenregistrement du 25 octobre 2026, après H12 et avant nouveaux calculs.
L'objectif central reste un moteur KEM de rang 6. Cette étude bornée doit
conclure le diagnostic des moments sur les petites listes, sans engager
automatiquement une nouvelle extension à 64/128 ou des moments supérieurs.

## Entrées et question

Reprendre les quatre matrices q=7681, η=3 et deux codes 140/21 de run-017,
les trois ordres publics de run-018, préfixe N=32. Aucun nouvel ordre,
matrice ou choix après résultat. Les certificats seront uniformes en
décalage d dans (Z/qZ)^21, grâce à |cos(phase)|≤1 ; ce n'est pas une
analyse de récupération simultanée parmi tous les candidats.

Pour p=1..4, séparer exactement les termes équilibrés du développement
des 2N fréquences. Pour chaque autre terme, v est la somme signée des
coefficients complets (y,x,r), centrée modulo q. Utiliser

`phi_CBD3(v) ≤ exp(-3*pi²*||v||²/q²) ≤ 2^(-42*||v||²/q²)`.

La première inégalité découle de log(cos t)≤−t²/2 pour |t|<pi/2.
La constante 42 est justifiée par pi>157/50 et ln(2)<7/10, donc
3*pi² > 42*ln(2). Vérifier les constantes par fractions rationnelles :
Machin et séries alternées pour pi ; somme des quatre premiers termes
de exp(7/10)>2 pour le logarithme.

## Certificat fini

Avec B=128 fixé, classer chaque terme dans
`K=min(B,floor(42*||v||²/q²))`. La somme rationnelle des multiplicites
fois 2^-K, divisée par (2N)^p, majore la valeur absolue de la correction
au moment brut indépendant. Conserver l'histogramme entier complet,
la masse équilibrée et la masse des coefficients complets nuls.

Voie primaire : multisets des 2N fréquences, lots de 2048, coordonnées
traitées par groupes de 32. Arrêter les coordonnées d'un terme dès que
42*norme_partielle²≥B*q² : sa contribution est majorée par 2^-B,
sans approximation transcendante. Pour les autres, calculer toute la norme.
La masse ainsi plafonnée et sa borne d'erreur sont publiées séparément.

Voie indépendante : multisets des N indices, puis 2^p signes ; sommer
toutes les coordonnées, puis plafonner K. Pas d'import de l'arithmétique
primaire. Retrouver exactement histogrammes, masses et bornes rationnelles.

Propager les quatre bornes aux moments centrés et à un encadrement de
la kurtosis avec fractions exactes. Si la borne inférieure de variance
n'est pas positive, signaler que le certificat est non informatif.
Ne pas substituer de flottant à une comparaison rationnelle décisive.

## Contrôles et sortie

Tests : développement ordonné littéral, relation complète non triviale,
loi CBD(3) pondérée sur un petit modèle, arrêt anticipé contre calcul
complet et propagation rationnelle. Calibrer les mêmes bornes sur les
64 banques H12 : toutes leurs corrections numériques doivent être dans
les bornes, sans transformer ces corrections en valeurs certifiées.

Créer run-020, préserver les dix-neuf instantanés, publier ressources
explicitement instrumentées et provenance. Aucun nouvel échantillon.
Ce certificat porte sur des moments finis, sans queue normale, coût
d'attaque révisé, clôture J2 ni choix de profil.

## Livrable pour le moteur

Ajouter une arithmétique polynomiale de référence en Rust dans
Z_q[X]/(X^256+1), modulo explicite, sans dépendance nouvelle. Tester
les témoins q=3329 et q=7681, les coefficients canoniques et l'identité
X^255*X=−1. Cette brique n'implémente pas le KEM et ne revendique pas
de temps constant. Elle prépare une référence vérifiable pour le futur
moteur. Actualiser la feuille de route avec les critères J2 restants,
la séquence de développement J3 et les conditions d'arrêt des études.
