# H06 — Score dual complet dans un modèle LWE fini

Protocole enregistré avant l'exécution, le 24 octobre 2026. Il prolonge
run-012 sans changer ses entrées ni aucun paramètre du KEM.

## Construction fixée

Quatre matrices publiques synthétiques : deux identifiants 0/1 pour chacun
des modules premiers q=5 et q=17. Chaque matrice A a deux lignes et cinq
colonnes : une colonne A_l et quatre colonnes A_f. Génération par le flux
SHAKE/rejet de run-010 avec l'étiquette ASCII
`nist-j2-full-dual-v1:{q}:{identifiant}`. Aucun choix après observation.

Les cinq coordonnées de s et les deux coordonnées de e suivent CBD(1),
indépendamment. Énumérer les 3^7=2187 états distincts avec leurs poids de
bits CBD, dénominateur 4^7=16384 par matrice. Calculer b=A s+e modulo q
et conserver exactement la loi jointe de (b,u_vrai).

Pour chaque y non nul de Z_q², choisir son représentant centré et garder
un seul représentant de la paire ±y (première coordonnée non nulle positive).
Poser x=centre(A_l^T y), puis trier les représentants par
`(||y||²+x²,y,x)`. Deux listes imbriquées : les 4 et 8 premiers éléments.
Ce sont des représentants d'une relation duale effectivement vérifiée,
énumérés dans un petit quotient ; aucun crible, BKZ ou modèle de coût réel.

Coder t=A_f^T y par les codes répétés et pondérés de run-010, longueur 4,
dimension 1, avec les critères euclidien et CBD entier de H05. Le poids CBD
à q=5 reprend run-012 ; les poids nécessaires à q=17 sont encadrés et
contre-vérifiés par intervalles. Garder c, le symbole, et r=centre(t−G c).

## Score et événements

Pour chaque b et chaque u de Z_q, former
`S_b(u)=Σ_y cos(2π(y^T b−c_y u)/q)/N`.
La vraie hypothèse est `u_vrai=G^T s_f mod q`. Vérifier l'identité de phase
`y^T b−c_y u_vrai ≡ y^T e+x_y s_l+r_y^T s_f (mod q)`.
Calculer la même table par une DFT directe de l'accumulateur en c ; pas de
FFT optimisée dans cette petite expérience.

Les 32 panneaux sont les produits des quatre matrices, deux familles,
deux critères et deux tailles de liste. Conserver les égalités, le succès
strict, l'appartenance du vrai u à l'argmax et le succès avec départage
uniforme entre ex aequo. L'objet deviné est u, pas nécessairement le secret s.

Seuils fixés : 0 et 1/2. Mesurer exactement les événements sur le vrai score,
sur chaque décalage faux u_vrai+d, et sur leur maximum. Comparer la probabilité
jointe au produit des probabilités marginales et à la borne d'union exacte.
Le produit est un témoin d'indépendance, pas une probabilité démontrée.

## Comparaisons et vérifications

Utiliser des histogrammes de phases et des poids entiers. Des cosinus
encadrés, quantifiés à 2^48, certifient les rangs et seuils. Les mêmes
histogrammes symétrisés certifient les égalités ; si des intervalles se
chevauchent pour des histogrammes distincts, arrêter au lieu de départager
par des flottants non certifiés.

Retrouver les moyennes et covariances du score complet par la fonction
caractéristique CBD sur (e,s_l,s_f), y compris pour chaque décalage faux.
Les comparer aux moments de la loi entièrement énumérée. Séparer la variance
diagonale et les covariances hors diagonale.

Ajouter le témoin b uniforme dans Z_q², indépendant, avec hypothèse fixée
u=0 et maximum sur tous les u. Sa variance ponctuelle attendue est 1/(2N)
si les y sont distincts à signe près ; ne pas en déduire la normalité.
Comparer ses queues aux queues normales de moyenne zéro et variance 1/(2N).
Les approximations normales sont des diagnostics, pas des bornes garanties.

Un programme indépendant reconstruit les listes et scores, énumère
littéralement les 2^14 configurations de bits CBD par matrice, puis retrouve
les lois et événements. Un second calcul d'intervalles vérifie toutes les
tables transcendantes. Aucun coût, niveau de sécurité du rang 6, profil ou
clôture J2 ne découle de ce petit modèle.
