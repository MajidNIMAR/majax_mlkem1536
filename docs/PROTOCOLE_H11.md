# H11 — Relations additives, moments supérieurs et sélection des listes

Préenregistrement du 25 octobre 2026 avant calcul des nouveaux résultats.
Entrées figées : quatre matrices, huit banques et 128 candidats de run-017.
Aucun profil, coût global ou seuil C05 modifié ; J2 reste ouvert.

## Comparaison publique fixée

Même ensemble de 128 candidats par matrice, mêmes codes déjà décodés,
préfixes de tailles 32/64/128. Trois ordres complets, sans accès aux
échantillons ou à leurs scores :

1. `norm` : ordre de norme de run-017.
2. `hash` : tri par SHA256 de l'étiquette ASCII
   `nist-j2-additive-v1:hash:{matrix_id}:{candidate_index}`, puis indice.
3. `energy` : partant de la liste vide, ajouter le candidat qui minimise
   le quatrième moment uniforme de la nouvelle liste ; égalité départagée
   par l'indice de run-017, donc par norme puis y,x. Les 128 candidats
   sont tous considérés à chaque étape où ils restent disponibles.

Le budget fixé est l'ensemble des candidats, pas un temps de sélection
identique. Conserver chaque choix, nombre d'évaluations, empreinte de tous
les coûts proposés, temps et variation des normes. Aucune recherche de
graines, de matrices ou de seuils après observation. À N=128, les trois
ordres définissent le même score ; partager les résultats par ensemble
d'indices, sans les compter comme observations indépendantes.

## Identités et calculs exacts du témoin uniforme

Pour B={±y_i}, de taille 2N, et b uniforme dans Z_q^3,
S(b)=somme_{v dans B} exp(2*pi*i*vᵀb/q)/(2N). Les y sont non nuls et
distincts à ± près. Si P(z) compte les paires ordonnées de B de somme z,
calculer exactement :

- E[S]=0 et E[S²]=1/(2N) ;
- E[S³]=somme_{v dans B}P(v)/(2N)^3 ;
- E[S⁴]=somme_z P(z)^2/(2N)^4, puisque B=−B.

Conserver les rationnels, la taille et l'empreinte du spectre de paires,
la dissymétrie et la kurtosis. Comparer à la kurtosis 3−3/(2N) des cosinus
indépendants et à la normale (3). Conserver le surplus entier de quadruples
par rapport à 12N²−6N. La borne de Markov au seuil trois écarts types vaut
min(1,kurtosis/81) ; elle ne certifie pas une queue normale et concerne
seulement ce témoin uniforme à candidat zéro.

## Nouveaux échantillons et compromis LWE

8192 observations uniformes synthétiques par matrice, générateur rejet
16 bits existant, étiquette `nist-j2-additive-v1:uniform:{id}`. Évaluer les
moments empiriques 1..4 et queues aux seuils 2/√(2N), 3/√(2N), 1/2.
Ces fréquences ne sont pas des probabilités exactes sur q^3 observations.

4096 nouveaux états CBD(3) par matrice, 145 variables, étiquette
`nist-j2-additive-v1:CBD:{id}`, même règle de six bits bas de run-017.
Recalculer et vérifier les deux formes des phases pour les 128 vecteurs,
une fois par matrice/code, puis réutiliser ces phases selon les sélections.
Évaluer les décalages run-017 d'indices 0,1,22,24 : vrai, une coordonnée
unité, tout-un et premier décalage pseudo-aléatoire. Ce sont trois faux
candidats choisis, pas q^21−1, ni un taux de récupération global.

Pour chaque liste/code, calculer la moyenne et covariance CBD complète
par les identités existantes, les biais en logarithmes, les moments
empiriques jusqu'à quatre et les queues. Aucun quatrième moment CBD de
population n'est revendiqué. Garder les deux familles même défavorables,
les normes du réseau/résidus, ambiguïtés numériques à 10^-12 et les
intervalles Wilson approximatifs sous modèle iid du générateur. Ne pas
transférer une baisse de kurtosis uniforme en gain LWE ou sécurité.

## Vérification et conservation

Nouvel instantané run-018, aucun écrasement des dix-sept précédents.
NumPy 2.3.5 local. Contrôles : petits tores exhaustifs, identité du
quatrième moment indépendant, incréments gloutons vérifiés, égalités de
N=128, rattachement de 12 témoins et 96 moments CBD de run-017.

Seconde implémentation sans import de l'arithmétique du projet :
convolution par paires vectorisées/encodage, autre formule d'incrément
pour rejouer tous les choix, états CBD extraits bit par bit, phases et
moments/queues reconstruits. Les moments uniformes sont exacts, les
moments CBD restent numériques et les moments empiriques échantillonnés.
Conserver scripts, étiquettes, empreintes, traces et ressources ; intégrer
les vérificateurs à `scripts/dev.ps1 check` et mettre à jour le rapport.
