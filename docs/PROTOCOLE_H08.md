# H08 — Dimensions 3/5 et distributions CBD(1/2/3)

Protocole enregistré avant exécution, le 25 octobre 2026. Aucun paramètre
du KEM ni résultat des quatorze études précédentes n'est modifié.

## Cas fixés

q=17, deux architectures (m échantillons, l coordonnées secrètes liées au
réseau, quatre coordonnées secrètes liées au code) : `(m,l)=(2,1),(3,2)`.
Le réseau a dimension m+l, soit 3 ou 5. Huit identifiants 0..7 par forme.
La forme 3 reprend les matrices de H07 ; la forme 5 utilise le flux public
de run-010 avec l'étiquette
`nist-j2-cbd-dimension-v1:17:3:2:{identifiant}` et trois lignes/six colonnes.

Secret et erreurs suivent tous la même CBD(η), η=1,2,3, sans changement de
matrice, liste ou code entre les trois distributions. Deux sources de
vecteurs (quotient exhaustif et LLL exact puis boîte [-2,2]^(m+l)), deux
familles de codes longueur 4/dimension 1, deux critères (euclidien et CBD
entier de H05), et listes N=4,8,12 : 1152 panneaux prévus.

Généraliser LLL par un nouveau module, sans modifier celui figé de H07.
δ=3/4, Gram-Schmidt rationnel, départage et plafond 10000 identiques.
La base est `[I_m | A_l]` au-dessus de `[0 | q I_l]`, de déterminant q^l.
Conserver transformation unimodulaire, trace, témoins de combinaisons et
écarts de listes face à l'énumération exhaustive du quotient Z_q^m.
Arrêter explicitement si une capacité ou une certification échoue.

## Lois exactes et comparaison de scores

Calculer la loi jointe entière de `(b,u_vrai)` dans Z_q^(m+1) par convolution
des colonnes associées aux m erreurs et l+4 secrets, avec les poids binomiaux
de CBD(η). Le dénominateur est `2^(2η(m+l+4))`, jusqu'à 2^54. Employer des
entiers 64 bits seulement après contrôle du budget ; aucun flottant ou
troncature dans ces lois. Les contributions peuvent se confondre modulo q
et doivent alors être additionnées, jamais éliminées.

Une méthode indépendante part des bits Bernoulli : pour chaque variable,
appliquer η couches de décalage positif et η de décalage négatif. Elle
doit retrouver exactement toute la loi, sans énumération littérale des 2^54
issues. Des petits cas parcourus entièrement par états/poids de bits
contrôlent les deux récurrences.

Conserver le score complet `Σ cos(2π(y^T b−c u)/q)/N`, avec coefficient
de bruit `(y,x,r)` adapté aux dimensions. Calculer toutes les hypothèses,
contrôler la DFT directe et les moments/covariances via
`Φη(a)=∏ cos(π a_i/q)^(2η)`. Garder les seuils 0 et 1/2 et les décisions
certifiées de H06, avec les mêmes tables encadrées à q=17.

Rapporter succès strict, appartenance à l'argmax et départage uniforme,
événements faux individuels et joints, moments, comparaison des critères
et des sources par strate. Partager les géométries et scores seulement
après égalité de toutes les données exactes. Les changements d'η modifient
la loi LWE et les moments, pas la table publique des scores d'une banque.

Les lois, phases et scores exacts reconstructibles sont liés par SHA-256
avec forme, type entier et ordre d'octets explicites. NumPy 2.3.5, déjà
verrouillé dans l'environnement local, sert à l'arithmétique entière et
à l'accélération des calculs, sans installation globale.

## Validation et portée

Le vérificateur indépendant n'importe pas l'arithmétique du projet. Il
contrôle les certificats de réduction, listes et choix de codes, retrouve
les lois par couches de bits et les scores par une construction distincte,
puis compare les décisions exactes et les moments numériques. Le contrôle
courant rejoue toutes les banques et toutes les identités de partage.

Ces cas rapprochent les distributions des scénarios réels, mais q=17 et
les dimensions 3/5 restent réduits. Aucun coût réel BKZ/crible, rotation
MLWE, niveau global, profil, propriété CCA ou clôture J2 n'en est déduit.
