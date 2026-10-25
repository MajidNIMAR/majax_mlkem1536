# H07 — Famille élargie et vecteurs issus de LLL

Protocole enregistré avant exécution. Tous les paramètres du KEM et les
treize instantanés précédents restent inchangés.

## Famille et génération de vecteurs

Reprendre les matrices 2×5 et le flux `nist-j2-full-dual-v1:{q}:{identifiant}`
de H06, pour q=5/17 et les identifiants 0 à 15 : 32 matrices fixes, dont
les quatre premières de H06. Secret de dimension 5 et erreur de dimension
2, iid-CBD(1). Lois LWE entièrement énumérées, dénominateur 16384.

Listes imbriquées de tailles N=4,8,12, deux familles de codes de longueur
4/dimension 1 et deux critères de décodage (euclidien/CBD entier de H05).
Deux sources de vecteurs, soit 768 panneaux prévus :

1. Les plus courts représentants du quotient dual de H06, énumération
   complète de Z_q² non nul, un par paire de signes.
2. Réduire exactement la base entière de lignes
   `[(1,0,A_l[0]),(0,1,A_l[1]),(0,0,q)]` par LLL, delta=3/4, avec
   Gram-Schmidt rationnel, arrondi au plus proche avec demi-entiers vers
   +infini et parcours déterministe. Conserver la matrice unimodulaire et
   la trace. Énumérer ensuite les 125 combinaisons de coefficients dans
   [-2,2]^3, projeter leurs coordonnées dans le cube centré modulo q,
   retirer zéro et doublons à signe près, puis trier comme la référence.

L'ensemble LLL est une énumération bornée après réduction et projection,
pas un crible ni un échantillonneur de vecteurs indépendants. Contrôler la
relation duale, les témoins de combinaison, l'unimodularité, le déterminant,
la réduction en taille et toutes les inégalités de Lovasz. Si une liste
ne contient pas douze représentants, déclarer l'échec du protocole sans
remplacer sa matrice. Le plafond LLL est 10000 itérations, avec arrêt explicite.

## Scores et comparaisons fixées

Réutiliser les tables encadrées et le score complet de H06 : DFT directe
sur tous les candidats, lois jointes de (b,u_vrai), rangs et événements aux
seuils 0 et 1/2 certifiés. Aucun changement de seuil selon les observations.
Les moments restent numériques ; les probabilités de rang/seuil sont exactes.

Par strate (q,source,famille,N), rapporter sur les seize matrices les succès
stricts et avec départage uniforme, les signes des différences CBD/euclidien
et les cas où une meilleure moyenne donne un moins bon classement. Mesurer
les accords de listes LLL/référence et leurs différences de norme. Comparer
les queues du témoin uniforme à la normale de variance 1/(2N). Signaler les
panneaux identiques : ils ne sont pas des répétitions indépendantes.

Les vecteurs, lois et scores identiques peuvent être calculés une seule
fois et référencés par empreinte. Conserver toutes les matrices, bases et
témoins, chaque panneau et ses résultats, ainsi que les empreintes des
tables de scores et distributions exactes reconstructibles. Une table
reconstruite doit donner la même empreinte, sans écraser une étude existante.

## Vérifications et portée

Un contrôle indépendant, sans import de l'arithmétique du projet, reconstitue
les bases et leurs certificats, les candidats LLL, les décisions des codes,
les tables de scores et les événements. Il énumère littéralement les 16384
configurations de bits par matrice pour retrouver les lois de H06.
Le vérificateur standard rejoue tous les panneaux en utilisant un cache
uniquement lorsque l'égalité des données exactes est vérifiée par empreinte.

Cette famille déterministe est un contrôle élargi, sans intervalle de
confiance sur l'ensemble des matrices ni transfert vers le rang 6. Aucun
coût BKZ, crible, attaque MLWE, niveau global, paramètre ou seuil C05 ne
sera déduit de ces petites dimensions ; J2 reste ouvert.
