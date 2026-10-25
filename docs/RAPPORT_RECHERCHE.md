# Rapport de recherche — KEM à six blocs de 256 coefficients

Version de travail du 25 octobre 2026. Ce document est la base évolutive du futur article. Le [journal](JOURNAL_RECHERCHE.md) conserve les étapes et décisions ; les [résultats figés de J2](../results/j2/run-001/) conservent les calculs et leur provenance. Une modification du rapport doit rester cohérente avec ces données.

**Première publication GitHub du moteur 1536.** Le dépôt public
[MajidNIMAR/majax_mlkem1536](https://github.com/MajidNIMAR/majax_mlkem1536)
est créé, distinct du démonstrateur 1024 du même auteur. L'export conserve
les sources et résultats d'un commit avec un manifeste SHA-256, une licence
Apache-2.0 des contributions propres et les attributions tierces. Trois
copies externes sont récupérées chez leur auteur par URL et empreinte.
Le signalement privé des vulnérabilités est activé. La reconstruction des
sources exportées dans une cible neuve réussit : 16 échanges et 16 rejets.
Le contrôle complet termine avec code 0 : tests Rust, 91 tests Python,
vingt études J2 et preuves du moteur. Les outils et caches locaux ont été
réutilisés ; ce n'est pas une installation à neuf ou une preuve de binaires
identiques. Les [journaux et leur portée](../results/publication/initial-001/)
sont conservés. La CI prépare désormais Python/NumPy et les références
avant les contrôles Windows/Ubuntu ; sa réussite distante reste à constater.
La campagne longue M03 continue séparément, sans résultat final anticipé.
Voir [la procédure de publication](PUBLICATION_GITHUB.md).

**Actualisation bibliographique.** La [revue des attaques au 24 octobre 2026](VEILLE_ATTAQUES_2026.md) complète maintenant l'étude initiale : variantes duales avec codes, hybrides avec rotations, critiques des modèles de score, corrélations du bruit, progrès quantiques et oracles d'échec. Le tableau Core-SVP historique ci-dessous reste celui de `run-001` ; il ne doit pas être présenté comme une synthèse des meilleures attaques connues à cette date.

## Résultat principal

**M03 — Benchmarks mesurés, inspection tracée et campagne prolongée lancée.** Le [dossier M03](M03_FUZZ_BINAIRES_BENCHMARKS.md) consigne 60000 observations P01, soit 30000 sous Windows et 30000 sous Linux/WSL sur le même Ryzen 7 2700. R1 atteint des médianes KeyGen/Encaps/Decaps de 1,987/2,168/2,544 ms sous Windows et 2,033/2,402/2,772 ms sous Linux ; le témoin ML-KEM-1024 est plus rapide dans ces réalisations, qui diffèrent par le profil et par l'optimisation (convolution directe contre NTT). Les pics mémoire sont ceux des processus, sans mesure isolée de la mémoire algorithmique. Les binaires complets sont désassemblés ; aucune division entière n'est repérée dans les 26/16 fonctions R1 retenues sous Windows/Linux. La fermeture reste incomplète face aux appels indirects et aux bibliothèques système. La revue relève M03-A01 : une zone résultat temporaire de 512 octets sur pile, copiée puis non explicitement effacée dans la multiplication Windows. Cette limite documentée doit être qualifiée ; elle n'est pas une fuite de protocole démontrée. Le premier test court de fuzzing a réussi, avec 84,23 s CPU cumulées ; le passage final a réussi avec 85,01 s CPU et 511 requêtes déterministes confrontées entre Rust et Python. La campagne prolongée a été lancée depuis 8ef4ceb sur quatre cibles, à six heures CPU chacune. Son état réel est conservé dans artifacts/generated/m03-long-001/progress.json, avec bilan automatique prévu à la fin. Aucune réussite des 24 heures CPU cumulées n'est encore revendiquée. Profil R1 et instantanés M01/M02/J2 inchangés ; J2/J3/J4 et le constat mémoire restent ouverts.

**M02 — Durcissement implémenté et campagnes bornées terminées.** Le [protocole](PROTOCOLE_DURCISSEMENT_M02.md), commit 63fd895, précède le code des classes et les mesures. Les clés privées sont construites dans une allocation fixe ; les tableaux secrets possédés, accumulateurs et réencapsulation sont effacés. Decaps n'effectue plus d'allocation dynamique explicite dans le cœur du dépôt. L'arithmétique R1 spécialisée utilise des réciproques entières et corrections bornées, confrontées à l'oracle générique. Sur Windows et Linux/WSL2, les 1000 vecteurs complets et 10000 remplacements M01 sont identiques ; 20000 imports et 10000 mutations sont contrôlés par cible, toutes les mutations étant aussi confrontées à Python. Ces 10000 cas comprennent 5351 chiffrés distincts. Les tests et les deux campagnes complètes passent sous AddressSanitizer avec détection de fuites, sans erreur signalée, avec bibliothèque standard précompilée non réinstrumentée. Le diagnostic préenregistré de 6000 observations ne dépasse pas |t|=4,5 (maximum observé 3,027) ; les deux sondes scalaires assembleur par cible n'ont ni division ni branche conditionnelle. Ces périmètres limités ne démontrent pas le temps constant global ou l'effacement de toutes les copies. Les [résultats, sources, preuves et limites](DURCISSEMENT_MOTEUR_M02.md) sont conservés dans hardening-001. Fuzzing long à couverture guidée, revue complète du binaire, benchmarks P01 et audit externe restent ouverts, ainsi que J2/J3/J4.

**M01 — Moteur R1 fonctionnel et confronté.** Sur instruction de poursuivre sans nouvelle validation de routine, le [bilan J2](BILAN_J2_ET_DECISION_PROTOTYPE.md) autorise le prototype expérimental en parallèle des questions ouvertes. La [spécification R1](SPECIFICATION_DEV_Q7681_R1.md) fixe q=7681/η=3/u exact/dv=5 et ses domaines/formats propres, sans modifier P0. Le cœur Rust réalise KeyGen, Encaps et Decaps, avec aléa système, réencapsulation et secret de remplacement. Les 1000 vecteurs synthétiques et leurs douze champs concordent avec une seconde réalisation Python par convolution entière indépendante. Une campagne distincte réussit 10000 échanges frais et 10000 rejets Rust ; le corpus apparié de 10000 chiffrés non canoniques retrouve exactement les 10000 remplacements entre Rust et Python, sans acceptation par la référence. Les deux instantanés moteur conservent les sources utilisées, leurs empreintes et les corpus compressés ; les vingt études J2 restent préservées. Les contrôles de longueurs ±1..32, canonicité, clé importée et défaut d'aléa sont ajoutés. L'implémentation reste une référence sans validation temporelle, audit ou preuve IND-CCA propre à R1 ; elle ne clôt pas J2/J3. Voir le [guide, les résultats et la suite](MOTEUR_KEM_R1.md).

**Objectif moteur et H13.** À la demande de l'utilisateur, les études doivent servir une décision de construction du KEM. [run-020](../results/j2/run-020/summary.json), préenregistré au commit 5fc45d1, conclut l'extension des moments sur petites listes : 24 banques à N=32, bornes rationnelles exactes uniformes en décalage. L'écart à la kurtosis indépendante 2,953125 est strictement inférieur à 3×10^-13 dans chaque banque ; il s'agit d'une majoration d'écart, sans queue normale validée ni coût d'attaque révisé. Une seconde expansion indépendante retrouve exactement les histogrammes et fractions ; les 1024 moments numériques H12 entrent dans les bornes. La première brique Rust d'arithmétique dans Z_q[X]/(X^256+1) est développée, avec convolution directe et oracle distinct. Elle prépare le moteur sans implémenter KeyGen/Encaps/Decaps, ni établir des propriétés de temps constant. Voir [calcul, code et limites](BORNES_N32_ET_MOTEUR.md) et la [feuille de route](FEUILLE_DE_ROUTE_MOTEUR.md). Arrêt de l'extension automatique des listes : la prochaine étape principale est le bilan de passage J2 → J3, avec critères C01–C06, obstacles classés et recommandation motivée. Aucun profil sélectionné.

**H12 — Quatrième moment CBD complet.** [run-019](../results/j2/run-019/summary.json), préenregistré au commit 8354d10, développe les moments de population 1..4 des scores complets (y,x,r,c) : préfixes 4/8/16 des trois sélections H11, 32 ensembles et 64 banques, vrais candidats et trois faux décalages fixés. Les 1024 moments utilisent la loi CBD(3) idéale, avec évaluation numérique des caractères ; aucune énumération des 2^870 configurations. Les kurtosis calculées restent proches de celles de cosinus indépendants, 2,625/2,8125/2,90625 selon N, avec écart maximal calculé ≈5,775×10^-16, malgré des différences nettement plus grandes du témoin uniforme. Aucune annulation supplémentaire des coefficients complets jusqu'à quatre n'apparaît hors appariements équilibrés. Les corrections signées/logarithmiques sont conservées ; les valeurs affichées égales ne sont pas des identités mathématiques. Un autre développement par indices de cosinus et signes retrouve masses, moments et mesures réutilisées de H11, avec 256 calibrations de covariance. Ce résultat ne valide pas une queue normale rare ou l'utilité de la sélection uniforme. Voir [développement, contrôles et limites](QUATRIEME_MOMENT_CBD.md). Aucun profil ou clôture J2.

**H11 — Moments supérieurs et sélection publique.** [run-018](../results/j2/run-018/summary.json), préenregistré au commit cfc924c, compare norme, hachage fixé et minimisation gloutonne du quatrième moment uniforme sur les mêmes 128 candidats de H10. Les 36 panneaux partagent 28 ensembles distincts, soit 56 panneaux avec les deux codes. Les relations additives donnent exactement les moments uniformes 1..4, sans énumération des q^3 observations : à N=128, kurtosis moyenne 44,8121 et dissymétrie 4,9351, contre 3 et 0 pour la normale. À N=32, le glouton réduit la kurtosis de 12,1641 à 4,3110 et les dépassements uniformes observés de 806 à 209 sur 32 768 nouveaux états ; il augmente la norme réseau au carré moyenne d'environ 89 % et abaisse la moyenne des log2 du biais vrai pondéré d'environ 1,198 bit. Une matrice améliore ce biais, trois le dégradent ; aucun gain d'attaque universel. Les 224 moments CBD numériques et les moments LWE empiriques restent séparés des moments uniformes exacts. Une seconde implémentation retrouve 33 024 coûts gloutons, les comptages, phases et événements ; 12/96 calibrations H10. Aucun quatrième moment CBD de population calculé, profil ou clôture J2. Voir [preuves, résultats et compromis](SELECTION_ET_MOMENTS_SUPERIEURS.md).

**H10 — Listes effectives au module réel.** [run-017](../results/j2/run-017/summary.json), préenregistré au commit 6827a5a, construit quatre instances LWE q=7681/η=3, réseaux de dimension 5 et codes concrets 140/21. Huit banques de 128 vecteurs, préfixes 32/64, conservent les coefficients complets ; 4 194 304 identités de phase et 648 enregistrements de moments sont contrôlés. Les 16 384 états CBD sont échantillonnés, sans énumération de la loi sur 2^870 configurations. Les variances calculées sont numériquement très proches de 1/(2N), sans validation de queue normale. Au témoin uniforme/N=128, 296/16 384 dépassements de trois écarts types donnent 1,8066 %, contre 0,1350 % pour la normale ; les observations LWE donnent d'autres fréquences et aucun facteur uniforme n'est transféré aux faux candidats. Les 26 faux candidats choisis ne couvrent pas q^21−1. Vérification indépendante des certificats/listes, de tous les décodages et événements, avec caractères Decimal à 80 chiffres ; écart maximal 8,99×10^-12. Le réseau de dimension 2576 et sa liste théorique ne sont pas réalisés. Aucun nouveau coût global, profil ou clôture J2. Voir [construction, résultats, ressources et limites](LISTES_DUALES_Q7681.md).

**H09 — Conditions de transfert à q=7681.** [run-016](../results/j2/run-016/study.json), préenregistré au commit a0b9fab, audite les quatre minima run-009 et les 2048 résidus run-011. Au point MLWE des auteurs à q=7681, le facteur code idéal vaut 2^-24,925654 contre une moyenne observée 2^-33,380947 pour le code pondéré sur 256 résidus, soit un rapport de 350,99 ; cette moyenne ne certifie pas la population. À seuil et liste historiques fixés, une hausse de variance de 0,173146 % suffit à épuiser le budget normal 0,05 ; une hausse de 1 % donne un budget supérieur à 0,05. Sous diagonale moyenne 1/2, la covariance moyenne admissible à cette limite serait environ 2^-258,159. Cantelli et l'union, même avec moyenne nulle et variance historique supposées, donnent seulement la borne 1 ; cela ne prouve pas l'échec de l'attaque. La liste dense de résidus modulo q représenterait 2^260,016 octets dans la représentation explicitée, sans borne mémoire universelle. Contre-vérification Decimal à 90 chiffres, 192 champs et tous les résidus, écart maximal 9,30×10^-12. Les données précisent les exigences d'un futur score complet au module réel ; aucun nouveau coût d'attaque, profil ou clôture J2. Voir [méthodes, résultats et contrat de transfert](TRANSFERT_SCORE_Q7681.md).

**H08 — Dimensions 3/5 et CBD(2)/CBD(3).** [run-015](../results/j2/run-015/summary.json) compare 16 matrices, réseaux de dimensions 3/5, trois distributions CBD et listes 4/8/12 : 1152 panneaux, 155 banques de scores distinctes et 96 lois jointes exactes. Le protocole est préenregistré au commit 128c463. Les lois sont calculées par convolution entière sur le groupe des observations, puis retrouvées par des couches Bernoulli indépendantes, jusqu'au dénominateur 2^54, sans énumération littérale de toutes ces issues ni simulation. Les 192 contrôles CBD(1)/dimension 3 retrouvent exactement H07. En dimension 5, les préfixes LLL+boîte égalent la référence dans les huit cas pour chaque taille testée. Au code pondéré/N=12, CBD(2) et CBD(3) donnent chacun trois pertes de classement et cinq égalités malgré une meilleure moyenne dans les pertes ; les succès moyens euclidiens/CBD sont respectivement 13,2684/13,2067 % et 8,2826/8,2560 %. Le témoin uniforme, indépendant d'η, garde une queue moyenne de 3,1447 % contre 0,7153 % pour la normale à N=12. Une contre-vérification indépendante retrouve les 5 949 643 scores, les lois, réductions et événements, avec écart numérique maximal des moments ≈2,44×10^-15. q=17 et les dimensions restent réduits ; aucun nouveau coût, profil ou clôture J2. Voir [méthodes et limites](CBD_ET_DIMENSIONS_SUPERIEURES.md).

**H07 — Famille élargie et réduction LLL effective.** [run-014](../results/j2/run-014/summary.json) étend H06 à 32 matrices q=5/17, listes de 4/8/12 vecteurs et 768 panneaux, regroupés par données exactes en 224 banques de scores. Le protocole est préenregistré au commit 9dfeefa. Une réduction LLL en dimension 3, Gram-Schmidt rationnel et certificat unimodulaire, fournit les bases d'une énumération bornée de 125 combinaisons projetées dans le quotient. À q=17, les préfixes égalent la référence exhaustive dans 15/16, 13/16 et 9/16 cas pour N=4,8,12 : la réduction certifiée ne rend pas l'énumération bornée exhaustive. Au code pondéré q=17/N=8/source LLL, CBD perd sur deux matrices et reste égal sur quatorze, malgré une meilleure moyenne du vrai score dans les deux pertes ; le succès strict moyen passe de 29,8553 % à 29,6196 %. Les queues uniformes restent éloignées de la normale de même variance : à q=17/N=12/source LLL, moyenne 3,9792 % contre 0,7153 %. Une énumération indépendante de 524 288 configurations de bits vérifie les 32 certificats, lois, événements et 822 808 scores de banques distinctes. Ces constats restent limités à CBD(1) et aux petits réseaux ; aucun coût du rang 6, profil ou clôture J2. Voir [méthode et résultats](LLL_ET_FAMILLE_ELARGIE.md).

**H06 — Score dual complet sur un modèle réduit.** [run-013](../results/j2/run-013/study.json) relie des vecteurs duaux effectifs, les codes concrets, les erreurs LWE et la DFT directe sur toutes les hypothèses. Le protocole est préenregistré au commit 3cbbd7c : quatre matrices fixes à q=5/17, CBD(1), listes de 4/8 vecteurs, 32 panneaux dont plusieurs identiques. Les 419 904 identités de phase sont vérifiées ; une énumération indépendante de 65 536 configurations de bits retrouve les lois jointes et 80 608 scores, avec décisions de rang et de seuil certifiées par intervalles. Résultat négatif utile : au premier cas q=17, code pondéré/N=8, le critère CBD augmente la moyenne du bon score de 0,409556 à 0,410652 mais baisse le succès strict de 35,7544 % à 32,0068 %. Au témoin uniforme, la variance vaut exactement 1/16 mais la queue au seuil 1/2 est 19/289≈6,5744 %, contre 2,2750 % pour la normale. Ce facteur n'est pas transféré aux paramètres réels. La chaîne est contrôlée dans le petit modèle ; aucun crible/BKZ, modèle MLWE à grande dimension, nouveau coût ou profil du KEM n'est validé. Voir [construction, résultats et limites](SCORE_DUAL_COMPLET_REDUIT.md). J2 reste ouvert.

**H05 — Critère CBD comparé à la distance.** [run-012](../results/j2/run-012/study.json) exécute le [protocole préenregistré](PROTOCOLE_H05.md) sur les mêmes codes et 2048 cibles. Une somme de poids entiers encadrés à l'échelle 2^40 approche le critère CBD avec un défaut uniforme inférieur à 5,99×10^-10 en log2 du biais optimal pour les formes étudiées. Les 38 400 blocs aux modules réels obtiennent aussi un certificat de minimum réel. Au point pondéré q=7681,140/21, 67 mots sur 256 changent : biais moyen +0,427541 %, norme moyenne +0,007432 %, durée locale 8,499721 ms contre 6,807785 ms à même budget de candidats, certification CBD comprise. Les six petits modèles complets ne montrent aucun changement de mot. Les 5513 poids passent une vérification indépendante par intervalles à 160 décimales ; un autre oracle retrouve les livres de codes complets et 64 blocs réels. Conserver le critère comme témoin certifié, avec un gain observé limité sur les codes pondérés. Le score complet, ses queues et ses coûts restent ouverts : aucun coût d'attaque ou profil du KEM n'est modifié, J2 reste ouvert. Voir [méthode, résultats et décision](DECODEUR_CRITERE_CBD.md).

**Erreurs et contribution CBD aux scores.** [run-011](../results/j2/run-011/study.json) reconstruit les 2048 résidus de run-010 et calcule une contribution cosinus sous un secret CBD idéal indépendant des résidus. Sa moyenne conditionnelle est exactement un produit de cosinus à la puissance 2η ; sa majoration gaussienne dépend de la norme, mais la valeur CBD dépend aussi de la direction. Au point pondéré q=7681,140/21, la moyenne gaussienne dépasse la moyenne CBD d'un facteur 1,617665 sur les 256 résidus ; remplacer la loi empirique jointe par le produit des marginales coordonnées donne un facteur 3,084988. Ce sont des diagnostics finis, sans facteur de population certifié. Six modèles exhaustifs confirment la factorisation par blocs et rejettent celle par coordonnées ; huit banques de 32 termes conservent les covariances dues au secret partagé. Les 114 contrôles à 160 décimales passent (écart logarithmique maximal ≈3,41×10^-13). Le score complet et les queues d'attaque restent ouverts : aucun nouveau coût, profil ou clôture J2. Voir [formules, données et limites](SCORES_DECODEUR.md).

**Décodeurs concrets exécutés en 7681.** [run-010](../results/j2/run-010/study.json) implémente deux codes par blocs et un décodage exact, jusqu'aux dimensions auxiliaires 140 coordonnées/21 symboles de l'attaque duale. Huit expériences, 2048 cibles synthétiques et 6302 cibles de petits modèles exhaustifs sont conservées. Une vérification indépendante retrouve les histogrammes complets et 64 blocs aux modules réels. Au point q=7681,140/21, les blocs pondérés donnent une norme moyenne de 1,177973 fois le rayon idéal de référence, contre 3,332703 pour le contrôle répété ; leur décodage exhaustif exact prend environ 6,752 ms dans le prototype Python/NumPy local. Ce résultat améliore le contrôle mais ne réalise pas l'hypothèse idéale de run-009. L'étude suivante run-011 traite la contribution CBD directionnelle et des covariances auxiliaires ; le score complet et le modèle de coût restent à étudier. Aucun coût d'attaque ou paramètre du KEM n'est modifié. Il s'agit du décodeur auxiliaire de l'analyse duale, pas de Decaps du rang 6. Voir [construction, preuve, mesures et limites](DECODEUR_CONCRET.md).

**Recherche duale stabilisée localement.** [run-009](../results/j2/run-009/study.json) poursuit le modèle inchangé de run-008 avec 1187 évaluations nouvelles, soit 2230 points conservés au total. Les quatre points retenus sont contrôlés sur les 32 déplacements unitaires d'une ou deux coordonnées, sans amélioration supérieure à 10^-10 en log2(coût). Le panneau MLWE du rang 6 passe de 379,998696 à 378,984845 (beta0=1234,beta1=1195) : coût estimé d'attaque plus bas, sans changement du KEM. Les autres panneaux sont conservés et quatre contre-vérifications à haute précision sont rattachées aux nouveaux points. La stabilité est locale, pas un optimum global ; les hypothèses GV, score, mémoire et réduction de run-008 restent conditionnelles. Voir [la méthode et ses limites](STABILISATION_DUAL.md). J2 reste ouvert ; la priorité suivante est le décodeur concret et les scores.

**Orientation de recherche.** Le 24 octobre 2026, l'utilisateur précise que l'approbation préalable du NIST ou d'un autre organisme n'est pas nécessaire à l'exploration. Les variantes peuvent modifier les distributions, les encodages, la réconciliation ou la construction du KEM, avec leur propre spécification et analyse. Cette décision élargit les méthodes admissibles ; elle n'apporte aucun résultat cryptographique nouveau, ne modifie pas les paramètres de P0 et ne clôt pas J2. Le cahier des charges et le registre des hypothèses intègrent cette orientation. La validation externe future reste un objectif à organiser, sans résultat présumé.

**Dual avec codes : adaptation exécutée.** [run-008](../results/j2/run-008/study.json) reproduit six points publiés avec la dépendance des auteurs, puis conserve 1043 évaluations : 969 coûts conditionnels et 74 points hors cible de probabilité dans la limite de répétitions. Le meilleur point exploré au rang 6 sous l'heuristique MLWE et un décodeur idéal GV donne log2(coût)=379,998696, beta0=1237, beta1=1197 ; le panneau LWE donne 381,755780. Quatre contre-vérifications à 2048 bits/160 décimales retrouvent les résultats. Ces valeurs ne sont pas un niveau global de sécurité : code idéal non mesuré à q=7681, score normal, mémoire exponentielle, coefficients de réduction extrapolés au-delà de 1024, et trajectoire gagnante encore en progression au plafond de recherche local. La version e2104 employée possède déjà l'intégrale pondérée cohérente ; l'ancien signalement n'est pas une correction originale du projet. Voir [méthode, résultats et limites](DUAL_CODES_ROTATIONS.md). J2 reste ouvert.

**Utilité et confrontation H01/H02.** [run-007](../results/j2/run-007/comparison.json) compare neuf propositions à trois exigences communes, avec validation rationnelle. À une borne ≤2^-200, H02 atteint 2583 octets, contre 2592 pour u exact et H01 : 9 octets (0,347 %) de gain. Les paramètres de clé publique identiques correspondent aux mêmes trente évaluations de run-002 : aucun nouveau coût ni gain de sécurité n'est calculé. La compression et ses dépendances ne sont pas prises en entrée par ces estimateurs. L'audit documentaire du dual avec rotations conserve aussi une incohérence d'intégrande signalée dans une version des auteurs, dont l'impact n'est pas chiffré. Conserver H02 pour la recherche et le témoin simple comme contrôle ; aucun profil choisi, J2 ouvert. Voir [l'analyse d'utilité et ses limites](UTILITE_COMPRESSION.md).

**H02 — quantification décalée par paires.** [run-006](../results/j2/run-006/pair-study.json) ajoute un contrôle fini de couverture qui garantit `|δ1|+|δ2|≤1` pour chaque paire à q=7681 avec deux indices sur 12 bits. Le plus court certificat trouvé correspond à 2567 octets, 228 paires quantifiées, 1080 coefficients exacts et dv=4 : borne 2^-175,665600 dans le modèle CBD indépendant, sans indépendance des arrondis. Le gain est de 14 octets sur H01 et 89 sur le témoin de 2656. La fraction finale est reconstruite indépendamment depuis les bits CBD. Les cinq petits tores, le contrôle négatif q=17/b=3 et l'absence de gain supplémentaire du critère local MGF sont conservés. La marge sous C05 n'est qu'environ 0,866 bit ; aucun profil n'est sélectionné. Voir [H02 en détail](QUANTIFICATION_PAR_PAIRES.md).

**H01 — précision mixte mise à l'épreuve.** L'expérience [run-005](../results/j2/run-005/mixed-precision.json) rapporte 240 bornes rationnelles, dont 25 satisfont C05 dans le modèle CBD sans indépendance des arrondis. Le plus court certificat trouvé correspond à 2581 octets, avec 88 coefficients u sur 12 bits, 1448 exacts et dv=3 : borne 2^-175,734559, reconstruite aussi par énumération indépendante des bits CBD3. Le gain total est 75 octets sur le témoin de 2656 ; 64 viennent de v et 11 de la précision mixte de u. Le point n'a qu'environ 0,935 bit de marge dans la borne et n'est pas sélectionné comme profil. Les 215 cas non certifiés ne sont pas des preuves d'échec réel. Le [détail H01](PRECISION_MIXTE.md) et le [registre des hypothèses](REGISTRE_HYPOTHESES.md) distinguent idées proposées, contrôles, résultats et antécédents.

**Témoin de correction sans indépendance des arrondis.** L'étude [des dépendances de u](DEPENDANCES_ARRONDI_U.md), conservée dans [run-004](../results/j2/run-004/u-dependency.json), établit une borne supérieure de 2^-319,633504 dans le modèle CBD indépendant pour le scénario exploratoire q=7681, η1=η2=3, u transmis exactement et v sur 5 bits. Une seconde méthode, sans récurrence de distribution, fournit le [certificat Chernoff rationnel](../results/j2/run-004/correctness-certificate.json), de borne 2^-310,085969. L'arrondi de v peut dépendre arbitrairement des autres variables ; la matrice s'annule algébriquement et aucune uniformité de u n'est requise. Ce témoin occuperait 2656 octets de chiffré dans le même agencement logique. Il établit la correction à l'échelle C05 sous les hypothèses de primitives précisées, sans sélection de profil ni clôture de J2.

**Priorité de travail confirmée.** Terminer la faisabilité J2, en commençant par le défaut de décapsulation, avant la sélection finale des paramètres. Le [diagnostic détaillé de P0](DIAGNOSTIC_DECAPSULATION_P0.md) et l'instantané [run-003](../results/j2/run-003/decapsulation.json) isolent les deux compressions et retirent l'hypothèse d'indépendance de l'arrondi final v pour le rejet de P0. Sous les hypothèses restantes sur CBD et u, une borne inférieure valable pour tout message fixé est encore 2^-155,184, au-dessus de C05. La décomposition de variance et les quatre probabilités reprises de `run-001` sont vérifiées exactement. Ce diagnostic renforce un résultat négatif ; il ne clôt pas J2 et ne choisit aucun nouveau profil.

L'instantané [run-002](../results/j2/run-002/modern-attacks.json) ajoute désormais 120 évaluations sous Sage : 118 coûts retournés et deux erreurs BKW explicites. La section « Comparaison moderne » fournit les minima observés parmi les familles de réseaux calculées. Les résultats de correction de `run-001` restent inchangés.

Le profil initial **KEM1536-EXP-P0** ne satisfait pas le critère de correction C05 dans le modèle étudié. À n=256, k=6, q=3329, η1=η2=2, du=11, dv=5, la borne d’union calculée vaut environ **2^-118,44**, contre un objectif de **2^-174,8**. Le défaut dépasse celui d’une simple borne d’union trop large : la probabilité d’échec d’un seul coefficient, dans ce même modèle, est déjà d’environ **2^-126,44**.

La suppression de toute erreur de compression à q=3329 ne suffit pas : le scénario correspondant donne une borne d’union d’environ 2^-155,83 et un événement sur un seul coefficient d’environ 2^-163,83. Il faut donc étudier les autres paramètres, conformément à C06.

Une piste mesurée est **q=7681, η1=η2=3, du=11, dv=5**, toujours avec six blocs de 256 coefficients. Elle donne une borne d’union d’environ **2^-227,53**. Les premières comparaisons d’attaques sur réseaux sont favorables par rapport au témoin dans le modèle historique retenu. Cette piste reste un scénario d’étude : aucun nouveau profil algorithmique n’est sélectionné et J2 n’est pas clos.

## Objet et état du projet

1536 désigne n×k, le nombre de coefficients du vecteur polynomial. Le projet recherche un KEM de rang 6, indépendant des systèmes Majax existants. Le cahier des charges initial, le profil P0 et leurs résultats négatifs sont conservés. Une future évolution utilisera une nouvelle identité de profil.

J0 a figé FIPS 203, examiné les errata et défini le contrat initial. J1 a établi un témoin ML-KEM-1024 avec RustCrypto `ml-kem 0.3.3` : 145 cas officiels ACVP retenus sont vérifiés, dont 15 rejets implicites, et 32 échanges avec des clés fraîches passent sous Windows. Le cœur KeyGen/Encaps/Decaps du rang 6 reste à construire.

J2 fournit ici une analyse de correction et une première comparaison heuristique primal/dual. Les résultats de correction ne sont pas des fréquences mesurées sur une implémentation du rang 6.

## Méthode de calcul du bruit

Le résidu de déchiffrement avant décision binaire est modélisé par

`E = eᵀy − sᵀ(e1 + δu) + e2 + δv`.

Les coefficients de s, e et y suivent CBD(η1) ; ceux de e1 et e2 suivent CBD(η2). δu et δv représentent l’erreur de décompression après compression. Les signes des produits n’affectent pas leur loi puisque le facteur secret est symétrique.

Pour un coefficient de sortie, chaque produit scalaire contribue n×k produits de coefficients. Le calcul traite les variables CBD comme indépendantes et les valeurs avant compression comme uniformes modulo q, avec des erreurs d’arrondi indépendantes des autres termes. **Cette dernière indépendance est une hypothèse de modèle** : le chiffré réel dépend des mêmes polynômes secrets et éphémères. Le calcul exact ci-dessous ne démontre pas cette hypothèse pour le KEM.

`research/noise_exact.py` construit les histogrammes d’arrondi en parcourant tous les x de 0 à q−1. Il utilise les arrondis entiers de FIPS 203, y compris les demi-entiers arrondis vers le haut lors de la décompression. Il n’emploie pas une approximation gaussienne des queues. [Source des conventions : FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).

Les lois discrètes sont représentées par des poids entiers et un dénominateur entier. Pour calculer la puissance N=n×k d’un polynôme générateur A, le programme utilise l’identité `A Q′ = N A′ Q`, avec Q=A^N. Si a_j et c_i sont les coefficients de A et Q :

`i a0 c_i = Σ[j≥1] ((N+1)j − i) a_j c_(i−j)`.

Chaque division est vérifiée comme exacte. La symétrie permet de calculer la moitié des coefficients. La masse totale et le second moment sont ensuite contrôlés par des identités indépendantes. Il n’y a ni troncature du support, ni FFT, ni virgule flottante dans la formation de la loi ou le comptage des échecs. Les logarithmes et écarts types affichés sont des représentations numériques de résultats rationnels.

Le comptage final applique les régions de décodage réelles modulo q, séparément pour les bits 0 et 1. Le résultat principal est `n × (p0+p1)/2`, une **borne d’union pour un message aux bits uniformes**, sans supposer l’indépendance entre les n événements de décodage. Les fichiers donnent aussi `n × max(p0,p1)` et la probabilité moyenne d’échec d’un seul coefficient. Cette dernière est une borne inférieure de l’événement « au moins un coefficient échoue », dans le modèle.

Une seconde convention, `n × Pr[|E| ≥ ceil(q/4)]`, sert à comparer le calcul avec les scripts historiques des auteurs de Kyber. Elle n’est pas substituée au décodage modulo q dans la colonne principale.

La revue 2026 inclut l'étude *Thorns in Polynomial Convolution* sur les dépendances du bruit. Notre borne d'union ne demande pas d'indépendance entre les coefficients de sortie. Cela ne valide pas pour autant les hypothèses d'indépendance de l'arrondi employées pour calculer les marginales. Un petit exemple exact indépendant, `research/joint_noise_check.py`, illustre cette distinction ; ses résultats ne sont pas une nouvelle estimation de DFR du rang 6.

## Vérification indépendante

Les outils des auteurs sont figés au commit `75c26949a902ca297b181375bfb7cfaf22cce784` de [pq-crystals/security-estimates](https://github.com/pq-crystals/security-estimates). Chaque fichier téléchargé est vérifié par taille et SHA-256 dans `research/tools-manifest.json`. Aucune licence explicite n’a été trouvée dans cet instantané ; les fichiers sont donc récupérés dans le cache local ignoré `.tools/`, sans être redistribués dans le dépôt.

La contre-vérification conserve leur construction séparée des deux puissances de convolution et leur arrondi Python historique. Seule la convolution est accélérée avec `numpy.convolve`, qui additionne directement des produits positifs. Le seuil de suppression passe de 2^-300 à 2^-600, explicitement enregistré : le seuil original est trop élevé pour vérifier le scénario à 2^-433. NumPy est verrouillé à 2.3.5.

Sur les huit scénarios, les logarithmes de la queue historique calculée exactement et par cette méthode numérique diffèrent de **moins de 2×10^-10 bit**. Ce contrôle vérifie le calcul de la loi sous les hypothèses communes ; il ne constitue pas une validation indépendante de ces hypothèses.

Six tests Python complètent ce contrôle : énumération des bits des CBD, convolutions ordinaires de petites lois contre la récurrence, énumération exhaustive d’un petit modèle avec décodage modulo q, arrondis et encodages sans perte, refus des entrées invalides et calibration du témoin avec détection de l’échec P0. Le petit modèle énumère directement les cinq variables CBD et les deux valeurs uniformes avant compression.

## Résultats de correction — instantané run-001

Toutes les lignes utilisent n=256. La borne d’union est à lire comme 2 élevé au logarithme indiqué ; un logarithme plus négatif est préférable. Les lignes autres que P0 et le témoin sont des scénarios, sans identité de profil algorithmique.

| Scénario | k | q | η1=η2 | du / dv | Écart type d’un coefficient | log2 borne d’union |
|---|---:|---:|---:|---|---:|---:|
| Témoin 1024 | 4 | 3329 | 2 | 11 / 5 | 57,84 | −175,074 |
| P0 1536 | 6 | 3329 | 2 | 11 / 5 | 67,57 | −118,440 |
| Compression v réduite | 6 | 3329 | 2 | 11 / 6 | 62,37 | −125,398 |
| Compression u sans perte | 6 | 3329 | 2 | 12 / 5 | 63,05 | −141,401 |
| Deux composantes sans perte | 6 | 3329 | 2 | 12 / 12 | 55,43 | −155,833 |
| Module 7681, bruit 2 | 6 | 7681 | 2 | 11 / 5 | 99,61 | −433,693 |
| Module 7681, bruit 3 | 6 | 7681 | 3 | 11 / 5 | 121,60 | −227,531 |
| Module 7681, bruit 3, du=12 | 6 | 7681 | 3 | 12 / 5 | 113,09 | −282,744 |

Le témoin donne −175,074 avec le décodage entier, ou −175,196 avec la queue historique. La valeur publiée de comparaison est −174,8. L’écart, inférieur à 0,5 bit, est conservé explicitement : nous ne prétendons pas reproduire exactement la valeur tabulée. L’origine complète de cet écart de méthode reste à documenter. [Valeur publiée : FIPS 203, tableau 1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).

Pour Q décapsulations honnêtes, une autre borne d’union donne `Q × p`. Par exemple, Q=2^32 déplace le logarithme de la colonne de +32 : environ −86,44 pour P0 et −195,53 pour q=7681, η=3. Ce calcul ne couvre pas des chiffrés choisis par un attaquant, la sélection de clés faibles ou un oracle de rejet.

## Première comparaison d’attaques sur réseaux

Le même instantané des outils Kyber est utilisé pour tous les paramètres. La dimension LWE est n×k ; le nombre maximal d’échantillons est n×(k+1), suivant la convention de comparaison des auteurs. La distribution du secret est CBD(η1), avec σ=√(η1/2). Le bruit additionnel de compression n’est pas compté comme un gain de résistance dans cette comparaison.

L’optimiseur primal et dual conserve son pas d’échantillons de 1. Pour le dual, le calcul du premier vecteur de la forme GSA est accéléré par la somme d’une progression arithmétique, avec la même équation de volume. Cette substitution est vérifiée contre la construction originale sur 180 points synthétiques, puis chaque coût optimal rapporté est recalculé avec la fonction originale. Les deux validations sont enregistrées dans le JSON.

Les modèles asymptotiques historiques sont `log2 coût = c × β`, avec c≈0,29248 pour le modèle classique, 0,26526 pour le modèle quantique et 0,20752 pour le modèle quantique optimiste. Le modèle dual ajoute le coût de répétition prévu par le script. Ces nombres décrivent des **coûts Core-SVP heuristiques** ; ils ne sont ni des durées, ni des comptes de portes détaillés, ni des niveaux de sécurité complets du KEM.

Le tableau retient le minimum primal/dual dans chaque modèle. Ici, le dual fournit les minima.

| Scénario | Échantillons du minimum dual | β | log2 coût classique | log2 coût quantique | log2 coût quantique optimiste |
|---|---:|---:|---:|---:|---:|
| Témoin 1024 | 838 | 868 | 253,874 | 230,243 | 180,126 |
| P0 1536 | 1256 | 1378 | 403,229 | 365,714 | 286,151 |
| q=7681, η=2 | 1294 | 1256 | 367,502 | 333,309 | 260,789 |
| q=7681, η=3 | 1347 | 1318 | 385,651 | 349,770 | 273,671 |

Augmenter q à bruit identique facilite ces attaques dans le modèle, alors qu’augmenter η récupère une partie de cette marge. C’est pourquoi la correction seule ne suffit pas à sélectionner q=7681, η=2, même si sa queue est plus faible. Les variantes du/dv à mêmes q, η et rang partagent le modèle d’attaque de base de leur ligne ; leur résistance aux attaques exploitant les échecs doit être étudiée séparément.

Les graines de 32 octets, le message d’encapsulation de 32 octets, le secret partagé de 32 octets et les primitives symétriques restent des contraintes distinctes. Un coût Core-SVP de 385 ou 403 bits ne donne pas une sécurité globale de ce niveau. Les coûts quantiques des recherches génériques doivent aussi être traités dans leur propre modèle de ressources. Aucune sécurité de 1536 ou 384 bits n’est revendiquée.

## Conséquences arithmétiques de la piste 7681

Le module 7681 a déjà été employé dans la première version de Kyber : la [spécification historique des auteurs](https://www.pq-crystals.org/kyber/data/kyber-specification.pdf), section 1.1, fixe n=256 et q=7681. Notre piste de rang 6 doit donc être située par rapport à cet antécédent ; le choix du module lui-même n'est pas une nouveauté revendiquée. Les paramètres et formats historiques ne sont pas substitués implicitement à ceux de notre étude.

7681 est premier et 7681−1=15×512. La primalité a été vérifiée par division jusqu’à la racine carrée. La valeur 62 fournit un exemple vérifiable : `pow(62, 512, 7681) == 1` et `pow(62, 256, 7681) == 7680`. Une NTT complète de longueur 256 pour `X^256+1` peut donc utiliser une racine primitive d’ordre 512. Les constantes et le produit de la NTT incomplète de Kyber à q=3329 ne doivent pas être réutilisés sans adaptation. L’échantillonnage uniforme et les encodages doivent également être redéfinis et vérifiés.

Les coefficients bruts nécessitent 13 bits au lieu de 12. Avec le même format logique de clés, les tailles calculées seraient 2528 octets pour ek et 5088 pour dk développé. À du=11 et dv=5, le chiffré resterait de 2272 octets ; à du=12, il passerait à 2464 octets. Ces tailles sont des conséquences arithmétiques du scénario, sans promesse de format définitif.

Le changement de q est une modification substantielle de la construction. Une nouvelle séparation des profils, un échantillonnage spécifié, des vecteurs et une comparaison indépendante seront nécessaires avant une implémentation du KEM correspondant.

## Limites et travaux restant dans J2

L’analyse actuelle ne clôt pas C01 à C06. Il reste notamment :

- Compléter le panneau moderne maintenant exécuté : dual avec codes et rotations, modèles de score révisés, budgets de mémoire et nombre de cibles. Le commit `f31b86fe490ab11abb4a69efa13007583791e10a` de [malb/lattice-estimator](https://github.com/malb/lattice-estimator) est celui utilisé dans `run-002` ; il ne contient pas à lui seul tous les travaux récents de la revue.
- L’analyse des attaques exploitant les échecs, des dépendances de l’arrondi et de la variabilité entre clés.
- La justification du choix de q et du bruit avec une recherche de paramètres plus large. Les deux modules étudiés ne constituent pas une recherche optimale.
- Le traitement complet de la transformation CCA, des primitives symétriques et de la séparation des domaines d’un éventuel nouveau profil.
- La vérification indépendante de la future arithmétique et les mesures de performance, puis l’examen externe du code et de l’argument de sécurité.

`run-001` a été exécuté sous Windows, Python 3.13.7, alors que Sage était encore absent. Docker avait échoué au démarrage. `run-002` utilise désormais Sage 10.7 sous WSL Ubuntu 22.04 avec son Python dédié ; le Python 3.10 système est conservé. Les contrôles Rust et la chaîne complète GitHub/Ubuntu restent distingués de cette exécution mathématique sous WSL.

## Comparaison moderne — run-002

Exécution sous Sage 10.7, Python 3.12.15 et WSL Ubuntu 22.04. Les archives des 158 paquets ont été vérifiées par SHA-256. Deux budgets sont évalués, m=256k et m=256(k+1), sur une cible, sans oracle et sans plafond de mémoire exponentielle. Chaque appel dispose d'une limite de 240 secondes ; aucun dépassement de temps n'est survenu.

Le panneau communautaire couvre uSVP, BDD, hybride primal, hybride primal avec rencontre au milieu, dual et dual hybride. BKW et Arora–GB utilisent leurs propres formules : leur étiquette de panneau classique ne signifie pas qu'ils emploient MATZOV en interne. Huit appels supplémentaires au primal avec rotations sont des diagnostics exploratoires sur nos CBD denses, hors des minima ci-dessous.

Le modèle classique emploie les coûts de réduction MATZOV de l'outil. La sensibilité BCSS23 remplace seulement le coût de réduction par `2^(0,2563 β)`, dans le régime de crible à deux tuples. Les autres étapes restent celles de l'outil ; cela n'est pas une optimisation complète de toutes les étapes quantiques. Les facteurs sous-exponentiels, les portes physiques, la profondeur et la mémoire quantiquement accessible ne sont pas chiffrés.

Le tableau donne les **minima observés parmi les six familles du panneau communautaire**, en logarithme base 2 du coût. Ce n'est pas une borne inférieure démontrée sur la sécurité. Le dual hybride fournit ici les minima. Les deux budgets donnent les mêmes minima sur ces instances, mais restent distingués dans les données.

| Scénario | Classique MATZOV | Sensibilité de réduction BCSS23 | β du minimum classique |
|---|---:|---:|---:|
| Témoin 1024, q=3329, η=2 | 262,336 | 214,789 | 823 |
| P0 1536, q=3329, η=2 | 397,033 | 338,836 | 1302 |
| 1536, q=7681, η=2 | 366,394 | 309,354 | 1192 |
| 1536, q=7681, η=3 | 383,773 | 325,958 | 1254 |

À titre de calibration, uSVP classique du témoin donne 275,104 dans le même outil, et le dual hybride 262,336. Les nombres de `run-001` appartiennent à un autre modèle de coût et ne doivent pas être soustraits directement à ceux-ci. Le plus grand β rapporté dans la matrice est 1461, inférieur à la borne logicielle globale de 1754 ; cela ne prouve pas l'optimalité des recherches de paramètres.

Les sorties gagnantes ne fournissent pas toutes un champ mémoire complet. Les paramètres de liste et de crible disponibles sont conservés dans les dictionnaires de coût, avec l'hypothèse de mémoire non plafonnée. Une comparaison sous un budget physique de temps/mémoire et un nombre de cibles différent reste à effectuer.

### Résultats indisponibles et correction de l'export

Les deux appels BKW de P0 échouent après amplification interne des échantillons, avec `Calling ceil() on infinity or NaN`. Leur trace est conservée. Cela n'est ni une estimation infinie de sécurité, ni la démonstration qu'une attaque BKW ne pourrait pas être plus efficace. Pour les autres cas, le budget initial et les échantillons générés par amplification sont distinguables dans les entrées et sorties.

Huit calculs Arora–GB ont initialement échoué lors de l'export JSON : des logarithmes de coûts très grands avaient produit un infini en double précision. Ils ont été réexécutés avec **le même cœur de calcul**, et un exporteur qui recalcule ces logarithmes depuis le texte numérique du coût à 80 chiffres décimaux. Les coûts ainsi représentés sont finis, jusqu'à plusieurs milliers de bits de logarithme, et ne fournissent pas les minima du tableau. Les huit premières tentatives sont conservées dans `prior_export_attempt` ; les deux exporteurs et leurs empreintes figurent dans la provenance. Aucun coût fini n'a été remplacé par un infini favorable.

### Décision après actualisation

La piste q=7681, η=3 conserve une marge de coût dans les modèles examinés et la correction calculée dans `run-001`. Elle reste à l'étude. Le dual avec codes et rotations doit être adapté au rang 6, les révisions des modèles de score doivent être traitées, et la sécurité en présence d'échecs ou de fuites exige une analyse distincte. Ce tableau ne ferme donc pas J2 et ne valide pas un niveau global du futur KEM.

## Reproduction et traçabilité

Depuis NIST, sous PowerShell :

```powershell
.\scripts\research-setup.ps1
.\scripts\dev.ps1 analysis
.\scripts\dev.ps1 check
```

L’analyse courante écrit dans `artifacts/generated/j2/`. Les résultats conservés pour cet article sont dans `results/j2/run-001/`. `provenance.json` enregistre les versions, les empreintes des scripts et paramètres, et celles des deux sorties. `noise.json` conserve les huit scénarios et leurs contrôles ; `attacks.json` conserve les 24 estimations et leurs paramètres.

Pour la comparaison moderne :

```powershell
.\scripts\bootstrap-modern.ps1
.\scripts\dev.ps1 modern
```

Les sorties courantes vont dans `artifacts/generated/modern/`. L'instantané `results/j2/run-002/` conserve les 120 appels, le tableau agrégé, l'exemple de bruit joint et la provenance. Les empreintes des scripts PowerShell sont calculées après normalisation CRLF vers LF, explicitement indiquée dans la provenance. La vérification ordinaire contrôle les deux instantanés sans exiger Sage ni les caches d'outils.

Une nouvelle étude doit créer un nouveau numéro d’exécution et conserver le code correspondant dans Git. Les dates, durées et empreintes peuvent varier entre exécutions ; les probabilités exactes et les optima, sous les mêmes hypothèses et conventions, doivent rester identiques à la précision numérique annoncée. La commande `check` vérifie les empreintes de l’instantané actif en plus des sources et des tests.

Avant publication, il faudra stabiliser le profil, compléter J2, faire relire l’analyse, préciser les auteurs et contributions, fournir les licences, identifier le commit exact de l’article et du logiciel, puis déposer les artefacts cités. Ce rapport conserve le travail préparatoire ; aucun article ni dépôt distant n’a été publié.


## Actualisation automatique M03 — 2026-10-25T14:59:22.748948+00:00

Temps CPU de fuzzing cumulé mesuré : 85.01 s. Budgets atteints : True. Post-traitements : {"coverage_exported": true, "independent_corpus_replayed": true}. Preuves dans results/engine/m03-smoke-001. La revue finale reste requise ; T07 et la validation globale ne sont pas déclarés acquis automatiquement.
