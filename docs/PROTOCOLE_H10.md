# H10 — Listes duales effectives à q=7681

Préenregistrement du 25 octobre 2026 avant calcul des résultats. Suite du
contrat H09 : coefficients complets, phases, sélection et ressources.
Aucun nouveau coût global, profil ou clôture J2.

## Construction fixée

- q=7681, η=3, m=3 observations, l=2 coordonnées secrètes dans le réseau,
  nfft=140 coordonnées restantes, kfft=21 symboles du code. Réseau de
  dimension 5 ; ce n'est pas le réseau de dimension 2576 de run-009.
- Quatre matrices A de forme 3×142, identifiants 0..3, issues du générateur
  SHAKE/rejet 16 bits existant, étiquette
  `nist-j2-real-dual-v1:matrix:{id}`. Décomposition A=[A_l|A_f].
- Base lignes [I_m|A_l] et [0|q I_l], LLL rationnel δ=3/4 avec certificat.
  Énumération de la boîte [-2,2]^5, projection centrée modulo q, suppression
  du zéro et des paires ±, tri (norme²,y,x). Garder les 128 premiers et
  les préfixes 32/64. Aucun oracle exhaustif du quotient q^3 ; ne pas
  prétendre que la boîte donne tous les plus courts vecteurs.
- Codes répété et pondéré existants, décodeurs euclidiens exacts. Sélection
  et décodage fondés uniquement sur A et les vecteurs publics, sans accès
  aux secrets ou aux scores de l'expérience. Conserver y,x,t,c,r et les
  coefficients complets a=(y,x,r).

## Moments et observations

Le vrai symbole projeté est u=Gᵀs_f, et les phases doivent vérifier
`yᵀb−cᵀu = yᵀe+xᵀs_l+rᵀs_f mod q` pour chaque échantillon et vecteur.
Les secrets et erreurs sont CBD(3). Calculer les moyennes/covariances
par les identités de caractères CBD, sans supposer l'indépendance des
vecteurs ni la normalité du score.

Tester 27 décalages : zéro, les 21 vecteurs unité, tout-un, alterné 1/−1,
et trois vecteurs SHAKE/rejet sous `nist-j2-real-dual-v1:offsets`. Il
s'agit de 26 faux candidats choisis, pas de l'ensemble q^21−1.

Pour chaque matrice, 4096 configurations synthétiques de 145 variables
CBD(3), étiquette `nist-j2-real-dual-v1:CBD:{id}`. SHAKE fournit un octet
par variable ; prendre la différence des poids binaires des deux groupes
de trois bits bas, ignorer les deux bits hauts. Conserver étiquette et
empreintes des tableaux reconstructibles. Ce sont des échantillons,
pas une loi exacte sur les 2^870 configurations de bits. Ne pas demander
à ces quelques milliers de mesures de valider un biais de l'ordre 2^-33.

Scores numériques, moments empiriques et queues aux seuils 2/√(2N),
3/√(2N), 1/2. Comparaisons numériques avec marge 10^-12 ; conserver
tout événement ambigu, sans le convertir en égalité ou décision certaine.
Une récupération parmi 27 candidats n'est pas un succès sur q^21 candidats.
Témoin séparé : 4096 b uniformes synthétiques par matrice, étiquette
`nist-j2-real-dual-v1:uniform:{id}`, candidat fixé à zéro. Les y distincts
à ± près donnent exactement moyenne 0 et variance 1/(2N) sous ce témoin,
sans théorème de queue normale. Intervalles de Wilson 95 % éventuels :
approximatifs et conditionnels au modèle iid du générateur.

## Vérification et conservation

Nouvel instantané run-017, sans modification des sources figées. Enregistrer
les certificats, listes, phases par empreintes, tous les moments/événements,
durées par étape et volumes des tableaux explicités (pas un RSS système).
NumPy 2.3.5 dans le runtime local existant ; aucune installation globale.

Seconde implémentation sans import de l'arithmétique du projet : certificats
LLL/listes, énumération du code avec autre expression des distances,
générateur CBD par extraction individuelle de bits, phases complètes,
scores et événements. Vérifier les caractères par une table calculée en
Decimal à 80 chiffres et des sommes scalaires, avec contrôles à haute
précision sélectionnés avant résultats. Les moments numériques ne sont
pas des certificats par intervalles. Tests ciblés puis `scripts/dev.ps1 check`.

Décision attendue : préciser ce que la chaîne au module réel contrôle et
ce qui manque encore pour extrapoler en dimension 2576, pour les rotations
MLWE, les queues rares et le coût d'attaque. Conserver tous résultats
négatifs et les écarts de simulation sans ajuster matrices, tailles ou seuils.
