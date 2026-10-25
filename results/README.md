# Résultats conservés

`j0-j1/milestone.json` conserve l’état du témoin avant J2. `j2/run-001/` contient les premières analyses du bruit et des attaques, avec les empreintes des entrées et sorties dans `provenance.json`.

`j2/run-002/` conserve la comparaison moderne sous Sage 10.7 : 120 évaluations, 118 coûts retournés et deux erreurs BKW conservées. Les huit reprises d'export ont leurs premières tentatives enregistrées. Les diagnostics de rotations sur CBD denses restent exploratoires et ne sont pas inclus dans les minima communautaires du rapport.

Ces fichiers sont versionnés pour la recherche. Une nouvelle étude reçoit un nouveau numéro ; les résultats négatifs restent disponibles. Les versions précédentes des scripts sont conservées dans Git. Les sorties courantes non figées restent dans `artifacts/generated/`.

La probabilité calculée est exacte dans le modèle discret décrit dans le rapport. Les hypothèses de ce modèle et les estimations heuristiques d’attaques restent distinctes de ce calcul arithmétique.

## Diagnostic prioritaire de décapsulation

`j2/run-003/` conserve les six scénarios du diagnostic de P0, les bornes avec arrondi v arbitrairement dépendant, les contributions de variance et la provenance. Il ne sélectionne aucun nouveau profil et ne clôt pas J2. Les hypothèses CBD/δu restent nécessaires. Vérifier avec `python research/verify_decapsulation_results.py`. Ne pas écraser cet instantané ; consulter `docs/DIAGNOSTIC_DECAPSULATION_P0.md` pour la dérivation et les limites.

`j2/run-004/` conserve les expériences exactes de dépendance de u et quatre témoins avec u exact. Le scénario q=7681/η=3/dv=5 satisfait C05 dans le modèle CBD sans indépendance des arrondis. `correctness-certificate.json` fournit une seconde borne par Chernoff rationnel, avec `certificate-provenance.json` en supplément de la provenance initiale inchangée. Vérifier avec `verify_u_dependency_results.py` et `verify_witness_certificate.py`. Voir `docs/DEPENDANCES_ARRONDI_U.md` pour les hypothèses, les coûts de format et les critères encore ouverts de J2.

`j2/run-005/` conserve H01 : 240 bornes rationnelles de précision mixte, 4000 propositions numériques séparées, le certificat du point de 2581 octets et sa reconstruction indépendante par bits. 25 cas sont certifiés pour la correction dans le modèle, 215 ne le sont pas par cette méthode. Les deux provenances préservent les sorties initiales et la vérification indépendante ajoutée avant gel. Le meilleur point n'est pas un profil sélectionné. Vérifier avec `verify_mixed_precision_results.py` et `verify_mixed_certificate_bits.py`.

`j2/run-006/` conserve H02 : cinq petits tores avec trois règles de quantification, la couverture du quantificateur décalé à q=7681, 4000 propositions et 16 bornes rationnelles, puis la reconstruction indépendante. Le plus court certificat trouvé occuperait 2567 octets ; il reste exploratoire et n'établit pas un niveau global du KEM. Vérifier avec `verify_group_quantization_results.py` et `verify_group_certificate_bits.py`. La provenance indépendante complète la provenance initiale sans modifier les sorties initiales.

`j2/run-007/` conserve neuf comparaisons à seuil commun (C05, 2^-200, 2^-225), leurs certificats rationnels et les références aux trente évaluations de clé publique de run-002. Aucun nouveau coût d'attaque n'est calculé. À 2^-200, H02 économise neuf octets sur le témoin simple. Vérifier avec `python research/compare_compression.py --verify`. Voir `docs/UTILITE_COMPRESSION.md` pour les limites et l'audit documentaire séparé du dual avec rotations.

`j2/run-008/` conserve six calibrations publiées, 1043 évaluations du dual avec codes dans un modèle idéal GV, quatre contre-vérifications numériques et leurs deux provenances. Les 74 refus de cible de probabilité sont conservés. La limite beta=1000 est explicitement diagnostiquée comme inadmissible aux deux points du rang 6. Les résultats conditionnels ne sélectionnent aucun profil et ne ferment pas J2. Vérifier avec `python research/verify_coded_dual_results.py` ; la vérification haute précision exige le runtime Sage. Voir `docs/DUAL_CODES_ROTATIONS.md`.

`j2/run-009/` conserve la stabilisation locale du dual : 1187 nouvelles évaluations rattachées aux 1043 du parent, 44 trajectoires et quatre points avec leurs 32 voisins unitaires sur un ou deux axes, puis quatre contre-vérifications numériques. Les paramètres et le modèle sont inchangés. Le point MLWE de rang 6 descend à log2(coût)=378,984845 ; la stabilité est locale et ne définit aucun niveau global de sécurité. Vérifier avec `python research/verify_coded_dual_refinement.py`. Voir `docs/STABILISATION_DUAL.md`.

`j2/run-010/` conserve les décodeurs auxiliaires concrets : deux familles de codes, huit expériences/2048 cibles, six livres de codes exhaustifs/6302 cibles, 64 blocs vérifiés indépendamment et mesures brutes de temps local. `independent-provenance.json` complète la provenance principale sans réécrire les résultats initiaux. Vérifier avec `python research/verify_block_decoder_results.py` puis `python research/verify_block_decoder_independent.py`. Les erreurs observées et durées ne valident pas le score idéal ou un nouveau coût d'attaque. Ce n'est pas le décodeur de décapsulation du KEM ; aucun profil n'est sélectionné.

## run-011 — Erreurs et contribution CBD aux scores

`j2/run-011` conserve les 2048 résidus reconstruits de run-010, huit matrices
de moments entiers empiriques, huit banques de 32 termes avec covariances,
dix-huit contrôles à norme égale et six lois exhaustives (6302 cibles).
La vérification indépendante et les 114 contrôles à 160 décimales ont leurs
provenances propres. Aucun coût d'attaque, seuil C05 ou profil n'est modifié.
Ne pas écraser les fichiers ni modifier leurs entrées sans versionnement.
Voir [SCORES_DECODEUR.md](../docs/SCORES_DECODEUR.md).

## run-012 — H05, décodage selon le biais CBD

`j2/run-012` conserve les poids entiers encadrés, six comparaisons exhaustives,
2048 comparaisons appariées, certificats et temps à budget de candidats égal.
Le protocole H05 est figé avant l'exécution au commit 17f30d3. Les 5513 poids
passent un contrôle indépendant par intervalles ; un oracle indépendant
retrouve les petits modèles et 64 blocs réels. Les trois provenances lient
les sources et sorties, sans modifier les études antérieures ou coûts
d'attaque. Voir [l'analyse](../docs/DECODEUR_CRITERE_CBD.md).

## run-013 — H06, score dual complet dans un modèle fini

`j2/run-013` conserve quatre matrices publiques fixées, 32 panneaux, les
lois jointes de (b,u_vrai), 80 608 scores par histogrammes de phases et les
probabilités exactes de rang/seuil. Les moments du score incluent toutes
les covariances. Le protocole est préenregistré au commit 3cbbd7c ; les
provenances primaire, indépendante et d'intervalles sont séparées.
Les douze études précédentes sont préservées et aucun coût de sécurité
du rang 6 n'est modifié. Voir [l'étude](../docs/SCORE_DUAL_COMPLET_REDUIT.md).

## run-014 — H07, famille étendue et LLL effectif

`j2/run-014` conserve 32 cas avec bases, transformations, traces et témoins,
768 panneaux et 224 banques de scores distinctes. Chaque banque possède
les empreintes de sa loi, table complète de scores et distributions exactes,
reconstructibles par le vérificateur. Le protocole préenregistré est le
commit 9dfeefa. Les 32 certificats et 822 808 scores distincts sont vérifiés
indépendamment avec 524 288 configurations de bits CBD. Préserver toutes
les entrées/sorties et les treize instantanés précédents. Voir
[LLL_ET_FAMILLE_ELARGIE.md](../docs/LLL_ET_FAMILLE_ELARGIE.md).

## run-015 — H08, distributions CBD(2)/CBD(3) et dimension 5

`j2/run-015` conserve les 16 matrices, bases, candidats, 1152 panneaux,
155 banques et résultats des trois distributions, ainsi que les empreintes
des 96 lois jointes et des tableaux complets exacts reconstructibles.
Le protocole préenregistré est 128c463. Les deux méthodes entières couvrent
jusqu'à 2^54 issues de bits par récurrence, sans énumération littérale.
Les 192 calibrations H07 sont exactes. Préserver toutes les entrées/sorties,
les deux provenances et les quatorze études antérieures. Voir
[CBD_ET_DIMENSIONS_SUPERIEURES.md](../docs/CBD_ET_DIMENSIONS_SUPERIEURES.md).
