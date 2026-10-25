# Journal de recherche — KEM 1536

Journal créé le 24 octobre 2026 à la demande de l’utilisateur pour préparer un futur article et le dépôt des sources. Les étapes antérieures sont reconstituées à partir des fichiers et comptes rendus existants ; aucune heure d’exécution non enregistrée n’est inventée. Le [rapport courant](RAPPORT_RECHERCHE.md) présente les méthodes et conclusions consolidées.

## 24 octobre 2026 — Mise en place locale, rappel des étapes déjà réalisées

**Objectif.** Étudier six polynômes de 256 coefficients dans `Codex/NIST`, indépendamment des projets Majax. Ne créer aucun dossier daté à la racine de Codex.

**Travail.** Conservation du cahier des charges, initialisation Git locale, infrastructure Rust/Python, profil P0 figé, commandes et contrôles Windows. Le premier compte rendu d’installation enregistre huit tests Rust et un accord Rust/Python sur les dimensions. Il est conservé comme état historique, sans être présenté comme l’état courant.

**Décision.** Le nombre 1536 désigne la dimension du vecteur. Les opérations du KEM de rang 6 restent absentes tant que leur faisabilité mathématique n’est pas examinée.

## 24 octobre 2026 — J0, références et contrat initial

**Travail.** Copie de FIPS 203, examen du fichier d’errata, manifeste SHA-256, contrat algorithmique initial. Les corrections examinées concernent l’indexation de l’annexe A et un commentaire d’algorithme. Les conventions de FIPS sont conservées.

**Preuves.** `references/manifest.json`, `docs/ERRATA_FIPS203.md`, `docs/CONTRAT_ALGORITHMIQUE.md`.

## 24 octobre 2026 — J1, témoin ML-KEM-1024

**Travail.** Intégration séparée de RustCrypto `ml-kem 0.3.3`, données ACVP au commit figé, comparaison des sorties attendues et vérification indépendante des rejets implicites. Préparation locale de l’outil LLVM nécessaire à l’import des fonctions d’aléa Windows.

**Résultat.** 145 cas officiels retenus passent, dont 15 rejets implicites ; 32 échanges frais passent. Les 13 tests Rust, rustfmt, Clippy et le contrôle des sources passent sous Windows. Les scripts Ubuntu et GitHub Actions sont préparés, sans exécution attestée à ce stade.

**Preuve conservée.** `results/j0-j1/milestone.json`. Les résultats du témoin ne sont pas attribués au rang 6.

## 24 octobre 2026 — J2-N1, calcul exact du bruit

**Question.** P0 respecte-t-il le seuil C05 de 2^-174,8 ?

**Méthode.** Lois CBD et erreurs de compression discrètes, puissance d’un polynôme générateur par récurrence entière, contrôles de masse et de second moment, décodage modulo q séparé pour chaque bit. Hypothèses d’indépendance et d’uniformité inscrites dans le rapport et les sorties.

**Résultat.** Témoin : borne d’union 2^-175,074. P0 : 2^-118,440 ; événement d’un coefficient 2^-126,440. L’écart avec la valeur publiée du témoin, 2^-174,8, est signalé et reste à expliquer entièrement.

**Décision.** P0 échoue à C05 dans le modèle. Conserver le profil sans le modifier ni le geler pour implémentation. Un premier prototype de calcul est remplacé par les scripts reproductibles et l’instantané ci-dessous ; ses sorties partielles ne servent pas de preuve finale.

## 24 octobre 2026 — J2-N2, compression puis module et bruit

**Travail.** Huit scénarios : témoin, P0, trois variantes de compression à q=3329 et trois variantes à q=7681. La suppression complète des erreurs de compression à q=3329 laisse une borne d’union de 2^-155,833 : cela ne suffit pas.

**Résultat exploratoire.** q=7681, η1=η2=3, du=11, dv=5 donne 2^-227,531. Le même q avec η=2 donne 2^-433,693, mais une moindre résistance aux attaques du modèle utilisé ensuite. Une variante η=3 et du=12 donne 2^-282,744 avec un chiffré plus long.

**Décision.** Étudier la piste q=7681, η=3 sans créer de nouveau profil définitif. Documenter l’encodage 13 bits et la NTT à adapter. Les modules et bruits étudiés ne sont pas une recherche exhaustive.

## 24 octobre 2026 — J2-V1, contre-vérification et estimations d’attaques

**Travail.** Sources des auteurs Kyber figées par commit et empreintes, récupérées dans un cache ignoré. Contre-vérification par convolutions positives NumPy, avec seuil explicite 2^-600. Comparaison des attaques primales et duales dans trois modèles historiques Core-SVP, identiques pour les quatre scénarios comparés.

**Résultat.** Accord des queues sur huit scénarios à moins de 2×10^-10 bit. Minima classiques du modèle : environ 253,87 bits pour le témoin, 403,23 pour P0, 367,50 pour q=7681/η=2 et 385,65 pour q=7681/η=3. Ces nombres ne sont pas des niveaux de sécurité complets du KEM.

**Contrôle de l’accélération.** Forme GSA duale vérifiée sur 180 points contre le code original ; chaque coût optimal est recalculé avec la fonction originale. Les trois modèles et les deux familles restent séparés dans les données.

**Limite.** Comparaison moderne avec hybrides non exécutée : Sage absent, démarrage Docker en échec. Aucun résultat moderne n’est inventé ; aucune réinitialisation du poste n’est effectuée. J2 reste ouvert.

## 24 octobre 2026 — J2-T1, conservation pour l’article

**Livrables.** Rapport évolutif, présent journal, scripts, six tests Python et instantané `results/j2/run-001/` avec huit scénarios de bruit, 24 estimations d’attaque et provenance. Les commandes courantes écrivent dans les artefacts ignorés ; un instantané scientifique ne doit pas être écrasé.

**Validation exécutée.** `scripts/dev.ps1 check` passe : intégrité des huit sources figées, rustfmt, Clippy sans avertissement, 13 tests Rust, six tests Python, accord du profil, empreintes des 13 entrées et deux sorties de l’instantané. Le témoin conserve ses 145 cas officiels et 32 échanges frais. La primalité de 7681, la racine d’ordre 512 proposée et les tailles exploratoires ont aussi été vérifiées par calcul entier local.

**Conservation des octets.** Git préserve les fins de ligne exactes du manifeste d’outils et des instantanés. Les 15 empreintes d’entrée/sortie ont été vérifiées contre les octets indexés dans Git, afin que le clonage ne modifie pas les résultats ou leur provenance par conversion des fins de ligne.

**Règle durable.** Après chaque étape significative, noter la question, la méthode, les données obtenues, les limites et la décision. Conserver les résultats négatifs. Git assure l’historique du code ; le rapport consolide les conclusions et le journal explique le chemin suivi.

**Suite.** Compléter les modèles modernes et les analyses d’échec, comparer d’autres paramètres si nécessaire, puis sélectionner et spécifier un nouveau profil avant de construire son KEM. La publication Zenodo/GitHub interviendra sur un état identifié et relu.

## 24 octobre 2026 — J2-V2, mise à jour demandée sur les nouvelles attaques

**Demande.** Actualiser les comparaisons et l'état des connaissances, les nouvelles attaques devant être prises en compte avant un choix de paramètres.

**Revue.** Les travaux CRYPTO 2025/2026 sur les variantes duales, les hybrides et les rotations, les résultats sur les scores et corrélations, les progrès quantiques et les oracles d'échec sont recensés dans `VEILLE_ATTAQUES_2026.md`. Les prépublications et les annonces d'implémentation restent distinguées des résultats reproduits. Une notice consultée sur miroir n'est pas présentée comme un texte intégral vérifié.

**Constats techniques.** Le dernier instantané communautaire repéré est daté du 22 octobre 2026. Le code des rotations de l'article a ses propres dépendances figées. Le pilote dual spécialisé borne β à 1000 ; une adaptation est nécessaire pour le rang 6. Une simple substitution des paramètres produirait un risque de résultat trompeur.

**Vérification des dépendances du bruit.** Un exemple exact de convolution CBD(1) modulo X^4+1 montre que deux coefficients peuvent avoir covariance nulle tout en étant dépendants. La borne d'union employée dans `run-001` reste la convention appropriée pour éviter une hypothèse d'indépendance entre coefficients de sortie ; les hypothèses de ses lois marginales restent séparées.

**Infrastructure en cours.** Préparation de Sage 10.7 sous WSL, exclusivement sous `.tools/`, avec environnement de 383 paquets figé. Les paramètres, versions, limites de calcul et erreurs seront conservés dans un nouvel instantané, sans modifier `run-001`.

## 24 octobre 2026 — J2-V3, comparaison moderne exécutée

**Infrastructure retenue.** L'installation a été réduite à 158 paquets nécessaires, tous vérifiés par SHA-256. Les collisions de casse et lenteurs de métadonnées de NTFS ont conduit à retenir un cache temporaire Linux sous `.tools/sage-ram/`, avec archives persistantes dans NIST. Un processus WSL borné garde le cache disponible entre commandes. L'essai d'image ext4 n'est pas retenu ; son nettoyage a été refusé automatiquement et l'image reste dans les outils ignorés.

**Calculs.** 120 évaluations : quatre scénarios, deux budgets d'échantillons, modèles classique MATZOV et sensibilité de réduction BCSS23, familles primales/duales/hybrides, BKW, Arora–GB et huit diagnostics de rotations. Une cible, aucun oracle, mémoire exponentielle non plafonnée, limite de 240 secondes par appel. Le degré de l'anneau transmis aux rotations est 256.

**Résultats.** 118 coûts retournés, deux erreurs BKW de P0 conservées, aucun dépassement de temps. Parmi les six familles de réseaux du panneau communautaire, les minima classiques sont 262,336 pour le témoin, 397,033 pour P0, 366,394 pour q=7681/η=2 et 383,773 pour q=7681/η=3. Les minima sont duaux hybrides dans ces modèles. Les sorties de rotations sur CBD denses restent exploratoires.

**Correction d'outil.** Huit premiers exports Arora–GB ont échoué sur des logarithmes trop grands pour le chemin de conversion utilisé. Un exporteur distinct a recalculé les logarithmes depuis le texte numérique à 80 chiffres, sans modifier le cœur d'estimation. Les huit calculs ont été repris et leurs tentatives initiales restent dans `prior_export_attempt`. Les erreurs BKW ne sont pas masquées par cette correction.

**Conservation.** `results/j2/run-002/` fige les entrées, sorties, versions et erreurs. `run-001` est conservé octet pour octet. Le rapport distingue les modèles et ne transforme pas les minima observés en preuve de sécurité globale. La revue a aussi identifié l'antécédent du module 7681 dans la première spécification Kyber.

**Décision.** P0 reste rejeté par le critère de correction du modèle initial. q=7681/η=3 reste une piste, sans nouveau profil sélectionné. Compléter le dual avec codes/rotations, l'analyse des scores et des oracles d'échec, ainsi que les budgets de mémoire, avant de clore J2.

**Validation finale de l'étape.** `scripts/dev.ps1 check` passe : huit sources de référence, rustfmt, Clippy sans avertissement, 13 tests Rust, dix tests Python, profil et deux instantanés. Les 145 cas ACVP et 32 échanges frais du témoin passent toujours. Les données modernes conservent deux erreurs d'estimation ; leur intégrité vérifiée ne les transforme pas en calculs réussis.

**Conservation Git.** Les 152 empreintes d'entrée/sortie des deux instantanés ont été vérifiées contre les octets indexés dans Git, en respectant la normalisation LF explicitement déclarée pour le script PowerShell du nouvel environnement. La syntaxe des scripts PowerShell et Bash modifiés est vérifiée.

## 24 octobre 2026 — J2-N3, priorité au défaut de décapsulation de P0

**Demande.** Terminer d'abord la faisabilité et travailler sur le rejet de P0 avant la sélection finale des paramètres et la suite du développement.

**Travail.** Diagnostic à q=3329 et η1=η2=2 inchangés : rangs 4/5/6, P0 avec u sans perte, v sans perte, puis les deux. Décomposition rationnelle de la variance en cinq termes. Nouveau comptage d'intervalles périodiques pour borner les échecs lorsque δv peut dépendre arbitrairement du bruit et du message, sous sa borne déterministe [-52,52]. Les hypothèses CBD et δu indépendant/uniforme restent explicites.

**Résultats.** P0 a une variance intrinsèque de 3073 sur une variance totale d'environ 4566,094379. Retirer seulement l'erreur de v donne une borne d'union de 2^-130,072783 ; retirer les deux retrouve 2^-155,832785, avec un événement sur un coefficient de 2^-163,832785. Les quatre scénarios déjà calculés dans `run-001` concordent exactement. Même sans indépendance de δv, une borne inférieure d'échec de P0 pour tout message fixé vaut 2^-155,183698 : C05 reste rejeté dans le modèle restant.

**Limites.** Ce contrôle ne prouve pas la loi de δu pour le KEM réel. Une borne qui ne rejette pas un scénario n'en certifie pas la correction : le nouvel encadrement prudent ne suffit pas à établir C05 pour le témoin. Le cas sans perte qui échoue ne démontre pas l'impossibilité de toute autre construction de réconciliation à q=3329. Aucun scénario de réparation n'est sélectionné.

**Contrôle de développement.** Une première décomposition de variance a été rejetée par le contrôle exact parce qu'elle omettait le carré de la moyenne de δu. L'arrondi a une moyenne 1/3329 ; utiliser E[δu²], et non seulement Var(δu), corrige le diagnostic. Les calculs figés antérieurs étaient déjà corrects et restent inchangés. Aucun résultat de cette tentative n'a été figé. Quatre nouveaux tests couvrent les bornes adaptatives par énumération exhaustive, le cas sans perte, les amplitudes refusées et ce second moment non centré.

**Conservation et décision.** `results/j2/run-003/` conserve six scénarios, leurs bornes, les contrôles et la provenance. `DIAGNOSTIC_DECAPSULATION_P0.md` présente la dérivation et les conditions de clôture de J2. La faisabilité reste ouverte : justifier les dépendances pour les scénarios de réparation, puis compléter les attaques et documenter C01 à C06 avant le choix final des paramètres.

**Validation.** `scripts/dev.ps1 check` passe : intégrité des huit sources, rustfmt, Clippy sans avertissement, 13 tests Rust, 14 tests Python, profil et trois instantanés. Le test du témoin exécute toujours les 145 cas officiels et 32 échanges frais. Les deux erreurs d'estimation de `run-002` restent conservées. Aucune nouvelle estimation d'attaque n'est attribuée à ce diagnostic.

## 24 octobre 2026 — J2-N4, dépendances de u et témoin de correction

**Question.** Justifier le traitement de l'arrondi u, ou trouver un témoin de correction qui s'en dispense, avant de sélectionner les paramètres.

**Source primaire consultée.** Duriez et Tommasini, arXiv:2609.09983v1, septembre 2026, traite les dépendances pour ML-KEM-768. La copie HTML et sa provenance sont conservées séparément, sans modification du manifeste initial figé. Sa chaîne de preuves/artefacts n'est pas reproduite et ses chiffres ne sont pas transférés au rang 6.

**Analyse et contrôle.** La loi de Aᵀy est uniforme sur l'idéal I(y), puis u sur e1+I(y), ce qui ne donne pas toujours l'uniformité sur tout l'anneau. Énumération exacte à q=5,n=2 pour 25 puis 625 vecteurs y : images uniformes et classes affines vérifiées. Les distances TV entre la vraie loi jointe (δu,e1) et le produit de ses marginales sont 45/512 au rang 1 et 405/32768 au rang 2. Ces chiffres concernent uniquement le petit modèle. Conditionner par l'idéal plein donne la référence uniforme pour l'arrondi, mais ne conserve pas automatiquement les lois CBD de y dans les autres termes.

**Témoin.** Transmettre u sans perte fait disparaître δu et annule A algébriquement dans le résidu, sans hypothèse d'uniformité de la matrice pour cette correction. À q=7681,η1=η2=3,dv=5, l'erreur v reste dans [-120,120] et peut dépendre arbitrairement du bruit. Le comptage entier complet donne une borne d'union sur le pire bit de 2^-319,633504. Les deux scénarios à q=3329 reproduisent exactement huit marginales de `run-003` ; ils n'établissent pas C05.

**Contre-vérification.** Une majoration de Chernoff à z=13/10, entièrement rationnelle et sans récurrence de distribution, donne 2^-310,085969. Les deux bits sont sûrs lorsque |B|≤1799 ; l'échec implique |B|≥1800. Le certificat conserve le numérateur et le dénominateur en hexadécimal et décide C05 par `2^874*N^5≤D^5`. Les MGF sont testées contre l'énumération des bits CBD et les intervalles sûrs contre le décodeur entier.

**Portée.** Correction moyenne sur les clés et bruits idéaux CBD, pour un message fixé indépendamment des clés ; pas de preuve pour chaque clé ou pour SHAKE fixé. L'étude quantifie aussi les usages répétés et donne une conséquence de Markov pour les clés à plus forte probabilité d'échec. Aucun oracle malveillant ni nouvelle estimation d'attaque n'est couvert.

**Conservation et décision.** `run-004` conserve l'étude et un certificat secondaire ajouté avec sa propre provenance avant le premier gel Git. Le témoin demanderait 2656 octets de chiffré ; il ne sélectionne pas un nouveau profil. Le volet correction dispose d'un témoin satisfaisant C05 dans un modèle explicite sans indépendance des arrondis. J2 reste ouvert pour la confrontation aux attaques récentes, les ressources mémoire et la consolidation des critères C01 à C06.

**Validation exécutée.** `scripts/dev.ps1 check` passe : sources, rustfmt, Clippy, 13 tests Rust, 21 tests Python, profil, quatre instantanés et rejeu rationnel du certificat secondaire. Les 145 cas ACVP et les 32 échanges frais du témoin passent dans les tests Rust. Les deux erreurs BKW historiques restent conservées. Les empreintes des sources et des sorties précédentes restent inchangées.

**Conservation Git.** 177 empreintes des entrées/sorties des quatre instantanés, du certificat et de la copie primaire ont été contrôlées contre les octets indexés. Les espaces et fins de ligne de la source HTML sont préservés, sans réécriture pour satisfaire une règle de présentation du dépôt.

## 24 octobre 2026 — J2-H01, mise à l'épreuve d'une proposition propre

**Demande.** Dépasser la comparaison des paramètres existants, formuler nos propres hypothèses et tester des alternatives en conservant les résultats. La primauté d'un moteur open source n'est pas établie par l'absence d'un dépôt repéré. Le registre cite l'antécédent théorique Kyber1536 et distingue les hypothèses locales d'une nouveauté vérifiée.

**Hypothèse.** Répartir publiquement la précision entre les coefficients u, à q=7681,η1=η2=3,n=256,k=6 inchangés. Le contrôle u exact avec v moins précis sépare les gains de v et de la répartition de u. Aucun masque ne dépend d'une clé, d'un message ou d'un retour de décapsulation.

**Méthode.** La majoration point par point `−s*δu≤r*|s|` permet une MGF rationnelle sans indépendance des arrondis. Les deux queues ont des variables majorantes de même loi ; la majorante n'est pas supposée centrée ou symétrique. Cauchy–Schwarz montre que remplacer une paire (11,13) par (12,12) ne dégrade pas cette borne à nombre de bits égal. Tests exhaustifs par bits des majorations et vérification des masques/rotations.

**Calculs.** 4000 propositions numériques de recherche puis 240 configurations rapportées et recalculées exactement : 224 par blocs, 16 frontières/pas suivants par coefficients. 25 obtiennent un certificat C05 dans le modèle, 215 ne sont pas certifiées par cette borne. Aucun échec de certificat n'est interprété comme un taux d'échec réel prouvé.

**Résultat.** Plus court certificat trouvé : 2581 octets, 88 coefficients u sur 12 bits, 1448 exacts, dv=3, inclinaison z=1201/1000, borne 2^-175,734559. Le pas suivant à 2580 octets donne seulement 2^-173,551044 et n'est pas certifié. Le gain total de 75 octets sur 2656 se décompose en 64 octets dus à v et 11 à u. La marge logarithmique du point le plus compact n'est qu'environ 0,935 bit ; aucun profil n'est sélectionné. Le contrôle u exact/dv=3 conserve 2592 octets avec une borne de 2^-200,803593.

**Contre-vérification.** Un programme indépendant, sans import du moteur arithmétique, énumère les 64 entrées binaires CBD3 et les 4096 couples, contrôle les supports et la région sûre, puis reconstruit le rapport rationnel complet. Il retrouve le certificat principal et décide C05 en entiers. Sa provenance a été ajoutée avant le premier gel Git sans modifier les sorties initiales.

**Conservation.** `run-005`, `PRECISION_MIXTE.md` et `REGISTRE_HYPOTHESES.md`. H01 a un gain limité mais positif dans le modèle. H02 (quantification par groupes) et H03 (contrainte de norme à l'échantillonnage) restent des propositions non testées. J2 reste ouvert pour les attaques, l'analyse CCA et les autres critères du cahier des charges.

**Validation exécutée.** `scripts/dev.ps1 check` passe : sources figées, rustfmt, Clippy, 13 tests Rust, 25 tests Python, profil et cinq instantanés. Les 145 cas ACVP et 32 échanges frais du témoin passent dans les tests Rust. Le certificat de H01 est rejoué par le moteur rationnel puis par l'énumération indépendante des bits. Les 4000 scores de recherche sont séparés des 240 bornes rapportées ; les deux erreurs BKW antérieures restent conservées.

**Conservation Git.** Les 191 empreintes d'entrées/sorties des cinq instantanés, des vérifications complémentaires et de la copie primaire sont vérifiées contre les octets indexés avant commit.

## 24 octobre 2026 — J2-H02, quantification par paires

**Demande.** Poursuivre les hypothèses du registre après H01, en commençant par des petits cas entièrement énumérables et en vérifiant l'utilité dans la borne complète.

**Construction.** Grille dont une ligne sur deux est décalée horizontalement d'une demi-maille. Deux indices de 12 bits définissent une reconstruction à q=7681. Le contrôle fini des lignes, écarts et phases établit la couverture de toutes les paires avec `|δ1|+|δ2|≤1`. Les 4096 lignes ont 511 écarts de 1 et 3585 de 2, et l'union des deux phases de colonnes couvre les 7681 résidus. Le petit encodeur déterministe est comparé au livre complet sur quatre modules.

**Petits modèles.** Cinq tores entièrement parcourus, trois quantificateurs chacun. L'erreur quadratique moyenne diminue dans tous les cas avec la grille décalée. À q=17,b=3, la garantie de support échoue pourtant : la meilleure moyenne ne suffit pas. Le critère MGF local produit les mêmes histogrammes que le critère euclidien dans les cinq expériences ; ce non-gain est conservé.

**Borne.** Le support joint donne `−s1δ1−s2δ2≤max(|s1|,|s2|)`, au lieu de la somme des valeurs absolues des supports séparés. MGF rationnelle par paires avec primitives CBD3 indépendantes, sans indépendance des arrondis, matrice annulée algébriquement et union des sorties. Masque public fixe de paires adjacentes. 4000 propositions numériques puis 16 bornes rationnelles rapportées : sept certifiées C05 dans le modèle, neuf non certifiées par la méthode.

**Résultat.** Plus court certificat trouvé : 2567 octets, 228 paires (38 par polynôme), 1080 coefficients u exacts, dv=4, borne 2^-175,665600. Le pas à 232 paires et 2566 octets donne seulement 2^-174,154447. Gain net de 14 octets sur le meilleur H01 ; à dv=4 identique, gain de 17 octets sur le H01 scalaire. Sur le témoin de 2656, les 89 octets se décomposent en 32 pour v et 57 pour u. La marge de borne est seulement environ 0,866 bit.

**Contre-vérification et sources.** Un programme sans import de l'arithmétique du projet reconstruit la couverture, les MGF depuis les 64 chaînes de bits CBD3 et 4096 couples, puis la même fraction finale et la décision entière C05. L'inspection du README Minal au commit `6b12ae4fa24c04fe756386cb8d7e7d88d283d1a9` confirme un antécédent explicite de précision par blocs DU0/DU1 : H01 ne revendique pas ce principe comme nouveau. Aucun code externe n'est exécuté ou intégré.

**Conservation et décision.** `run-006`, `QUANTIFICATION_PAR_PAIRES.md`, rapport et registre. La construction a un gain positif calculé dans le modèle, avec une faible marge au point de frontière. Les quantificateurs Python sont des outils mathématiques, sans garantie de temps constant. Aucun nouveau profil, moteur de rang 6 ou résultat d'attaque n'est livré par cette étape. J2 reste ouvert.

**Validation exécutée.** `scripts/dev.ps1 check` passe : sources, rustfmt, Clippy, 13 tests Rust, 29 tests Python, profil, six instantanés et reconstructions indépendantes. Les 145 cas ACVP et 32 échanges frais passent dans le témoin Rust. Les deux erreurs BKW antérieures restent conservées. Le calcul de 2567 octets suppose un flux de bits u continu ; aligner chaque polynôme en octets ajouterait trois octets, ce qui est consigné dans l'étude.

**Conservation Git.** Les 208 empreintes des entrées/sorties des six instantanés, des contre-vérifications et de la source primaire conservée sont contrôlées contre les octets indexés avant commit.

## 24 octobre 2026 — J2, utilité des gains et confrontation H01/H02

**Demande.** Confronter les variantes aux attaques et juger si une petite marge justifie la suite de la recherche.

**Calcul.** Trois familles, trois exigences de borne (2^-174,8, 2^-200, 2^-225), 500 inclinaisons, huit précisions v, masques publics fixes. Neuf propositions sont validées en rationnels et par décision entière du seuil ; pas de revendication d'optimalité globale. À 2^-200 : u exact et H01 2592 octets/borne 2^-200,803593 ; H02 2583 octets, 164 paires,dv=4,borne 2^-200,795235. Le gain n'est que neuf octets (0,347 %). À 2^-225 : respectivement 2624,2606,2598 octets ; les marges obtenues diffèrent et restent affichées.

**Attaques.** Les trois formats ont les mêmes entrées de clé publique pour les estimateurs de run-002. Trente évaluations sont rattachées sans recalcul ni nouveau résultat de sécurité. Les modèles ne prennent pas la compression en entrée et ne couvrent pas ses distributions conditionnelles ou la transformation CCA. Les coûts minimums conservés restent 383,772563 et 325,958069 dans leurs deux panneaux distincts, sans interprétation comme sécurité globale.

**Audit documentaire.** Copies exactes de deux versions du code dual des auteurs, empreintes conservées, aucune exécution. Version e2104 : pilote q=3329/alpha spécialisé/beta0≤1000. Version 7b7e8000 : appel nfft avec préfacteur beta1 dans l'intégrale de find_relative_threshold, conforme au signalement du dépôt identitymapping. Le contrôle de normalisation donne beta1/nfft au lieu de 1 dans la limite sans facteur exponentiel ; impact concret non chiffré, correction globale non validée. Aucun coût antérieur n'utilise ce fichier dual.

**Décision.** Conserver H02 comme piste utile et le témoin simple comme contrôle. Un gain inférieur à 1 % ne justifie pas seul la complexité applicative. Temps constant, performances, distributions du chiffré et attaques/CCA restent ouverts. Aucun profil sélectionné, aucune implémentation du rang 6. Conservation dans run-007 et UTILITE_COMPRESSION.md ; deux tests supplémentaires portent le total Python à 31.

**Validation exécutée.** `scripts/dev.ps1 check` passe : sources, rustfmt, Clippy, 13 tests Rust, 31 tests Python, profil, sept instantanés et certificats indépendants antérieurs. Les neuf nouveaux résultats sont rejoués exactement et les trente références d'attaque contrôlées, sans nouveaux coûts. Les 145 cas ACVP et 32 échanges frais du témoin passent. Les 223 empreintes des entrées/sorties et références sont vérifiées contre les octets indexés ; les deux erreurs BKW historiques sont conservées.

## 24 octobre 2026 — J2, dual avec codes et heuristique de rotations

**Demande.** Poursuivre le développement et traiter le prochain point de faisabilité ouvert après la comparaison H01/H02.

**Infrastructure.** Runtime Sage local reconstitué depuis les 158 archives vérifiées, sans installation globale. Archive CodedDualAttack e2104 verrouillée par SHA-256 ; sources Python comparées à l'archive avant utilisation. Aucun pickle, bytecode ou objet natif fourni n'est chargé. Les fonctions de référence sont sélectionnées par AST, sans les imports polaires et les scripts à effets de bord.

**Calibration.** Six points CC publiés (dimensions 512/768/1024, panneaux LWE/MLWE) reproduits à 2048 bits avec la dépendance des auteurs. L'adaptateur retrouve les coûts à moins de 10^-8 dans leurs logarithmes et les mêmes blocs beta0/beta1. La version e2104 utilise déjà une intégrale cohérente en beta1 ; l'incohérence de la version 7b7e8000 n'est pas présentée comme notre correction. Les statistiques polaires publiées sont limitées aux contrôles q=3329.

**Adaptation.** Paramètres explicites, budget de clé m≤dimension aplatie, degré polynomial 256 et rangs 4/6. Plafond beta relevé à la dimension du réseau, contrôle du prédécesseur et diagnostic de monotonie sur maillage. Intégrales sans soustraction instable de gamma, queues normales en logarithmes et probabilités de sous-ensemble nul testées contre des petits cas rationnels. Code mathématique d'analyse uniquement, aucun moteur de rang 6.

**Calcul.** Grille de 576 points, amorces issues des découpages publiés puis recherche locale depuis trois départs, douze balayages au maximum. 1043 évaluations conservées : 969 coûts conditionnels et 74 points non admissibles à la cible de sous-ensemble nul dans la limite de 2^100 répétitions. Les meilleurs log2(coûts) LWE/MLWE sont 258,482114/256,969531 au témoin et 381,755780/379,998696 au rang 6. Le meilleur MLWE du rang 6 utilise beta0=1237,beta1=1197, avec environ 2^248,4 vecteurs dans la liste du modèle. Le plafond initial 1000 est inadmissible pour les deux points du rang 6. Une trajectoire par panneau du rang 6 atteint le plafond local en progressant encore ; celle du panneau MLWE donne le meilleur point. Pas de convergence ni d'optimum global revendiqués.

**Contre-vérification.** Quatre points retrouvés par les fonctions des auteurs avec plafond adapté, champ Sage 2048 bits, gamma inférieure et erfc à 160 décimales. Mêmes blocs, écarts de coûts/répétitions/seuils inférieurs à 10^-8 ; maximum observé environ 3,54*10^-12. Ce contrôle vérifie la numérique du même modèle, pas la validité cryptanalytique de ses hypothèses.

**Limites et décision.** Résultats conditionnels au rayon GV idéal et au coût de décodage supposé conjointement atteignables, au score normal, à l'heuristique binomiale des auteurs pour les rotations et à la mémoire exponentielle sans plafond. Les coefficients de réduction, documentés jusqu'à beta=1024, sont extrapolés et marqués comme tels. Aucun transfert de statistiques q=3329 vers q=7681. Les coûts précédents restent conservés ; aucune sécurité globale, aucune résistance des formats H01/H02 aux chiffrés choisis n'est déduite. Continuer la convergence, le décodeur concret et les modèles de score/covariance avant de clore J2. Aucun profil sélectionné. Conservation dans run-008, DUAL_CODES_ROTATIONS.md et copies documentaires.

**Validation exécutée.** `scripts/dev.ps1 check` passe : sources, rustfmt, Clippy, 13 tests Rust, 35 tests Python, profil, huit instantanés et reconstructions indépendantes antérieures. Les 145 cas ACVP et 32 échanges frais passent dans le témoin. Le contrôle standard du nouveau panneau vérifie les empreintes, six calibrations, sommes de coûts, contraintes et quatre contre-vérifications enregistrées ; il ne relance pas Sage. Les 242 empreintes des instantanés et références ont été contrôlées contre les octets indexés. Les deux erreurs BKW historiques restent conservées.

## 24 octobre 2026 — Orientation explicite : exploration hors standards

**Demande.** L'utilisateur précise que des méthodes non approuvées par le NIST ou d'autres organismes peuvent être employées et développées ; la validation extérieure viendra après la construction et l'étude du candidat.

**Décision appliquée.** Inscription dans AGENTS, le cahier des charges, le rapport et le registre des hypothèses. A01 impose désormais la base FIPS 203 pour P0 historique seulement ; des constructions alternatives sont admises avec une spécification et une identification propres. A02 conserve l'accord octet pour octet pour les optimisations d'un profil inchangé et distingue les nouvelles variantes. L'approbation institutionnelle n'est pas un préalable à l'expérimentation. Correction, sécurité visée, comparabilité et reproductibilité restent les objectifs scientifiques ; les propriétés démontrées et les hypothèses sont distinguées.

**Portée et contrôle.** Révision documentaire uniquement : aucun nouveau calcul, modification de profil, baisse de seuil, clôture de J2 ou publication externe. Les huit instantanés et leurs entrées sont préservés. Contrôle des différences et des empreintes effectué ; la suite de tests n'est pas relancée puisque le code et les données de calcul n'ont pas changé.

## 24 octobre 2026 — J2, stabilisation locale de la recherche duale

**Demande.** Continuer le développement. Le point opérationnel traité est l'arrêt de trajectoires encore en progression au plafond de run-008, avant le travail sur un décodeur concret à q=7681.

**Développement.** Nouveau module indépendant des entrées figées : reprise des meilleurs points et des fins de trajectoires, cache des évaluations du parent, descente à quatre échelles, puis déplacements unitaires sur un ou deux axes. Le dernier voisinage contient 32 points. Une amélioration doit dépasser 10^-10 en log2(coût). Le plafond de sécurité à 1000 balayages ou un diagnostic non résolu interdit de déclarer une stabilité. Quatre tests couvrent la géométrie du voisinage, un piège qui nécessite un mouvement simultané, une fonction de coût connue avec arrêt explicite et les frontières du domaine.

**Calcul et conservation.** 1187 évaluations nouvelles, toutes avec coût conditionnel, et 44 trajectoires/étapes enregistrées. Le maximum observé est vingt balayages ; aucun plafond de sécurité atteint. Les données contrôlées du calcul de développement ont été conservées octet pour octet dans run-009, sans recalcul arbitraire ni modification de run-008. Le total cumulé est 2230 points : 2156 coûts et 74 refus de probabilité antérieurs. Les quatre points retenus ont chacun leurs 32 voisins admissibles évalués et sont intérieurs au domaine déclaré.

**Résultats.** Les meilleurs log2(coûts) LWE/MLWE passent de 258,482114/256,969531 à 258,459513/256,968923 pour le témoin, et de 381,755780/379,998696 à 381,711763/378,984845 pour le rang 6. Le point MLWE utilise m=1230,a=50,nfft=140,kfft=21,beta0=1234,beta1=1195. La baisse de 1,013851 dans l'exposant représente une attaque modélisée environ deux fois moins coûteuse, pas un gain de sécurité du KEM. Aucun paramètre du candidat n'est changé.

**Contrôles et limites.** Les quatre nouveaux points sont retrouvés avec les fonctions des auteurs, champ Sage 2048 bits et gamma inférieure/erfc à 160 décimales : mêmes blocs et écarts logarithmiques sous 10^-8 (maximum observé environ 3,41*10^-12). Le vérificateur courant reconstruit les voisinages d'une autre manière et vérifie les trajectoires, les voisinages terminaux, les coûts et les liens aux contre-vérifications. Stabilité locale seulement, dans la boîte et à la tolérance définies ; plateaux, mouvements plus grands ou sur trois axes et optimum global restent ouverts. Modèle GV, score normal, mémoire exponentielle, heuristique MLWE et extrapolation de réduction inchangés. Aucun profil sélectionné ni clôture J2.

**Suite.** Le point encore en progression dispose maintenant du contrôle local défini. Passer au décodeur concret en 7681 et aux hypothèses de score, avec possibilité d'une construction propre au projet. Les autres surfaces du KEM, dont les chiffrés H01/H02 et la transformation CCA, conservent leurs analyses distinctes. Méthode complète dans STABILISATION_DUAL.md.

**Validation exécutée.** `scripts/dev.ps1 check` passe : sources, rustfmt, Clippy, 13 tests Rust, 39 tests Python, profil et neuf instantanés. Les 145 cas ACVP et 32 échanges frais du témoin passent. Le vérificateur de run-009 contrôle les 44 trajectoires et les quatre voisinages complets, ainsi que le rattachement des quatre contre-vérifications numériques déjà exécutées. Les 260 empreintes des instantanés et références sont vérifiées contre les octets indexés. Les instantanés précédents et les deux erreurs BKW historiques restent conservés.

## 24 octobre 2026 — J2, décodeurs auxiliaires concrets en 7681

**Demande.** Développer le décodeur concret après la stabilisation de la recherche duale. Le périmètre est le code auxiliaire de l'attaque, distinct de Decaps du KEM de rang 6.

**Construction et algorithmes.** Deux codes de même longueur et même nombre de symboles : blocs indépendants à coordonnées répétées et blocs pondérés par puissances d'une base entière. Le premier coefficient de chaque bloc vaut un, ce qui donne q^d mots distincts. La métrique se sépare entre blocs : leurs minima donnent le mot complet le plus proche. Pour le contrôle répété, balayage exact des intervalles quadratiques entre changements de représentant centré, au plus 2(s+1) scores pour un bloc de taille s. Pour le code pondéré, énumération exacte des q symboles de chaque bloc accélérée par NumPy, sans approximation. Départage déterministe des égalités. Aucun objet natif fourni ni pickle chargé.

**Contrôles.** Cinq tests couvrent petits alphabets complets, égalités et frontières, factorisation d'un code, forme 140/21 et formats. Six petits modèles parcourent 6302 cibles contre les livres de codes complets. Un programme indépendant sans import de l'arithmétique du projet retrouve les histogrammes et vérifie 64 blocs aux modules réels, en parcourant 352320 symboles candidats : accord exact sur distances et symboles. Les 2048 cibles synthétiques et sorties des huit expériences sont reconstructibles par leurs graines publiques et empreintes.

**Mesures.** Quatre dimensions de décodage de run-009, deux familles chacune, 256 cibles identiques entre familles pour chaque panneau. Les ratios norme moyenne/rayon GV passent de 2,742035 à 1,144659 pour q=3329,114/16 ; de 2,814699 à 1,147038 pour 3329,111/16 ; de 3,211444 à 1,165069 pour 7681,152/22 ; et de 3,332703 à 1,177973 pour 7681,140/21. Le rayon est le repère géométrique du modèle antérieur, pas une couverture garantie. Aucun des 256 résidus du dernier panneau pondéré n'est dans ce rayon ; ce compte ne devient pas une borne probabiliste.

**Performance locale.** AMD Ryzen 7 2700, WSL2/Linux x86-64, Python 3.12.15, NumPy 2.5.4. Sept séries de huit décodages, tableaux préchauffés, hors génération/validation des résultats/écritures, avec contrôles d'entrée et allocations du décodeur inclus. Au point 7681,140/21 : médiane environ 0,457 ms pour le contrôle répété et 6,752 ms pour le code pondéré. Données brutes conservées ; aucun transfert direct vers les unités rop de l'estimateur ou un budget de production.

**Décision et limites.** Un décodeur exact est maintenant exécuté aux dimensions auxiliaires 140/21 en 7681. Le code pondéré améliore le contrôle mais laisse une norme moyenne environ 17,8 % au-dessus du repère idéal. Ses erreurs sont structurées : moyenne et écart type des normes ne valident pas le score dual. Ne pas injecter ces mesures dans le coût antérieur en gardant les autres hypothèses inchangées. Aucun coût d'attaque, profil du KEM ou seuil C05 modifié ; J2 reste ouvert. L'entrée H04 du registre consigne rétrospectivement cette expérience sans préinscription ni revendication de nouveauté. Suite : distribution des erreurs, scores et compromis coût/distance.

**Conservation.** Le calcul contrôlé est conservé octet pour octet dans run-010 ; sa contre-vérification possède une provenance supplémentaire. Les dix instantanés restent distincts. Méthode et reproduction dans DECODEUR_CONCRET.md.

**Validation exécutée.** `scripts/dev.ps1 check` passe : sources, rustfmt, Clippy, 13 tests Rust, 44 tests Python, profil et dix instantanés. Les 145 cas ACVP et 32 échanges frais du témoin passent. Le nouveau vérificateur reconstruit les 2048 observations ; l'énumération indépendante est rejouée sur 6302 cibles et 64 blocs réels, avec accord exact. Les 279 empreintes des instantanés et références sont vérifiées contre les octets indexés. Les calculs et les deux erreurs BKW historiques restent conservés.

## 24 octobre 2026 — J2, distribution des erreurs et contribution CBD aux scores

**Demande.** Continuer après les décodeurs concrets : confronter leurs résidus
aux hypothèses de score, avec une analyse propre aux distributions étudiées.

**Développement.** Reconstruction des 2048 résidus figés de run-010. Fonction
caractéristique exacte pour un secret idéal iid-CBD indépendant des résidus,
majoration gaussienne ponctuelle et covariance de deux cosinus avec le même
secret. Huit matrices de moments empiriques en entiers, huit banques de 32
termes, dix-huit contrôles à norme égale et six lois exhaustives. Conservation
des dépendances de blocs et des petites valeurs en logarithmes signés.

**Résultats.** Sur les 256 résidus pondérés à q=7681,140/21, la moyenne
gaussienne vaut 1,617665 fois la moyenne CBD ; le produit des marginales
coordonnées vaut 3,084988 fois la moyenne jointe empirique. Taille effective
pondérée 39,98/256, plus grande contribution 8,49 %. Ces rapports incluent
les fluctuations de cet échantillon et ne sont pas des facteurs de population.
À norme exactement égale, trois directions produisent des biais différents.
Les 6302 cibles des petits modèles réfutent six fois la factorisation par
coordonnées et vérifient six fois celle par blocs, par identités entières.
Les multiensembles exhaustifs contiennent des résidus répétés ; leurs fortes
covariances ne sont pas transférées aux listes du crible.

**Contrôles exécutés.** Cinq tests nouveaux. Programme indépendant sans import
de l'arithmétique du projet : livres de codes, phases, factorisations et
moments à secret partagé retrouvés. Sous le runtime local WSL, 114 comparaisons
mpmath à 160 décimales passent ; écart logarithmique maximal 3,41×10^-13.
Le vérificateur standard reconstruit les résidus, matrices, banques et liens
aux deux contre-vérifications. Les données contrôlées sont préservées dans
run-011 avec trois provenances distinctes.

**Veille et portée.** Métadonnées primaires de Ducas–Pulles et de Li–Zheng
(révision du 14 octobre 2026) consignées avec l'étendue de consultation.
Pas de reproduction complète de leurs modèles. Notre contribution de code
ne contient ni vecteurs courts duaux, ni FFT, ni score complet de bonne ou
mauvaise hypothèse. Les banques de 32 termes ne valident pas l'indépendance
ou les queues d'environ 2^248 termes. Aucun nouveau coût ou niveau global,
profil sélectionné, modification de C05 ou clôture J2. Rapport détaillé :
SCORES_DECODEUR.md. Prochain test possible : critère CBD contre distance,
à code et budget comparables ; l'intégration au score complet reste nécessaire.

**Validation finale.** `scripts/dev.ps1 check` passe : sources, rustfmt,
Clippy, 13 tests Rust, 49 tests Python, profil et onze instantanés. Les 145 cas
ACVP et 32 échanges avec clés fraîches du témoin passent. Les nouveaux
vérificateurs standard et indépendant sont intégrés aux scripts Windows et
Linux. Les 307 empreintes des instantanés et références ont été vérifiées
contre les octets indexés dans Git. Les dix études précédentes et les deux
erreurs BKW historiques restent conservées.

## 24 octobre 2026 — J2, H05 : décodage guidé par le biais CBD

**Demande.** Continuer en comparant le critère CBD au critère euclidien, à
codes, cibles et budget de candidats comparables, avec mise à jour du rapport.

**Préenregistrement et infrastructure.** Protocole PROTOCOLE_H05.md enregistré
au commit 17f30d3 avant l'exécution. Runtime temporaire Sage reconstitué à
partir des 158 archives vérifiées, sans installation globale. Nouveau code
séparé des entrées figées : oracle scalaire, énumération NumPy et runner.
Une table de poids floor(2^40×(−2 ln cos)) est formée par boules réelles
à 192 bits. La sélection utilise des sommes entières et un départage fixe.
Garantie uniforme d'écart en log2 du biais optimal <ηn/(2^40 ln 2).

**Exécution.** Six petits modèles complets et les huit panneaux aux modules
réels de run-010, soit 6302 cibles exhaustives et 2048 comparaisons appariées.
Les deux critères parcourent les mêmes q×k candidats et q×n contributions
par appel. Le contrôle euclidien retrouve exactement les sorties historiques.
Les données du calcul de développement sont copiées octet pour octet dans
run-012 après contrôle des empreintes. Les dix études antérieures et run-011
restent inchangés.

**Résultats et limites.** Tous les 38 400 blocs réels obtiennent un certificat
de minimum du coût réel, au-delà de la garantie d'approximation uniforme.
À q=7681,140/21 pondéré : 67 mots changés sur 256, 75 blocs sur 5376, biais
moyen +0,427541 %, norme moyenne +0,007432 %. Temps à tables chaudes :
8,499721 ms CBD contre 6,807785 ms euclidien ; ordre alterné, sept séries
de huit cibles, certification CBD comprise. Les six petits modèles conservent
les mêmes mots ; un test séparé q=17 montre une différence effective.
Les grands rapports des contrôles répétés restent très concentrés sur peu
d'observations et ne justifient pas une conclusion de population.

**Vérifications indépendantes.** Tous les 5513 poids individuels
passent mpmath.iv à 160 décimales, sans Sage ni arithmétique du projet.
Un oracle Python indépendant retrouve les livres de codes complets, puis
64 blocs réels et 352 320 symboles par critère. Le vérificateur standard
reconstruit toutes les cibles et sorties choisies et rejoue les petits cas.
Quatre tests nouveaux contrôlent les livres de codes, certificats, un échange
distance/biais et les entrées invalides. Un premier candidat de test q=11
ne montrait aucun échange de distance : il n'est pas présenté comme un
contre-exemple ; le cas q=17 explicite est vérifié.

**Décision et suite.** Conserver le critère comme témoin presque optimal,
avec certificats observés, mais gain limité sur les codes pondérés dans
cet échantillon. Priorité au lien entre résidus, vecteurs duaux et score
complet sur un modèle réduit vérifiable. Aucun gain de sécurité du KEM,
coût d'attaque actualisé, profil sélectionné, modification de C05 ou clôture
J2. Rapport détaillé : DECODEUR_CRITERE_CBD.md.

**Validation finale.** `scripts/dev.ps1 check` passe : sources, rustfmt,
Clippy, 13 tests Rust, 53 tests Python, profil et douze instantanés. Les
145 cas ACVP et 32 échanges à clés fraîches du témoin passent. Les deux
vérificateurs H05 sont intégrés aux tâches Windows et Linux ; le contrôle
par intervalles à 160 décimales a été exécuté séparément et rattaché par
sa provenance. Les 342 empreintes des instantanés et références correspondent
aux octets indexés dans Git. Les onze instantanés antérieurs et les deux
erreurs BKW historiques sont conservés.

## 24 octobre 2026 — J2, H06 : score dual complet sur un modèle LWE fini

**Demande.** Continuer après H05 en reliant décodeur, vecteurs duaux et
score complet dans un petit cadre entièrement vérifiable.

**Préenregistrement.** PROTOCOLE_H06.md enregistré au commit 3cbbd7c avant
exécution : quatre matrices fixes à q=5/17, deux échantillons, cinq
coordonnées secrètes et deux erreurs CBD(1). Listes imbriquées de 4/8
représentants duaux, codes longueur 4/dimension 1, critères euclidien/CBD,
seuils 0 et 1/2. Aucun choix de matrices après observation. À q=5 la base
pondérée vaut 1 : les deux familles coïncident, sans réplication indépendante.

**Développement.** Construction et contrôle de x=A_l^T y, décodage de
t=A_f^T y, résidu r et score sur tous les u. DFT directe depuis les bacs
de symboles c, vérifiée contre les phases ; écart maximal 8,22×10^-15.
Décomposition publique/bruits contrôlée 419 904 fois. Lois de (b,u_vrai)
en entiers, probabilités exactes et histogrammes de cosinus. Poids de cosinus
encadrés sur 2^48 pour certifier rangs, seuils et égalités ; arrêt explicite
en cas d'intervalle non résolu. Aucun cas non résolu observé. Formules CBD
de moyenne et covariance sur les sept variables, confrontées à la loi
complète pour chaque décalage faux et vrai.

**Exécution et conservation.** 32 panneaux, 2187 états distincts par matrice,
dénominateur 16384, et 80 608 scores de toutes les hypothèses. Données du
calcul de développement copiées octet pour octet dans run-013 après contrôle
des empreintes. Aucun crible ou BKZ exécuté : représentants triés d'un
quotient dual fini. La récupération porte sur u=G^T s_f, pas nécessairement s.

**Résultats.** Au premier q=17/code pondéré/N=8, moyenne du vrai score
0,409555761 vers 0,410652443 avec CBD, mais succès strict 35,7544 % vers
32,0068 %. La probabilité d'au moins un faux score ≥1/2 passe de 52,5269 %
à 61,0107 %. Au second q=17/code répété/N=8, le succès augmente de 11,5356 %
à 14,7949 % : pas d'ordre uniforme des deux critères. Le produit des
événements marginaux peut surestimer ou sous-estimer leur union ; la borne
d'union exacte est conservée. Au témoin b uniforme, variance 1/16 pour N=8,
mais queue au seuil 1/2 égale à 19/289≈6,5744 % au premier q=17 contre
2,2750 % pour la normale de mêmes moments. Ces petits résultats ne donnent
aucun facteur de correction à grande dimension.

**Vérifications exécutées.** Quatre tests nouveaux : relation duale et
listes imbriquées, phases complètes, Fourier et moments, refus des décisions
non certifiées. Un programme indépendant régénère matrices/listes/codes,
énumère littéralement 65 536 configurations de bits CBD et retrouve lois,
80 608 scores, événements et distributions ; écart maximal observé des
moments environ 1,69×10^-15. Les 24 entrées transcendantes sont retrouvées
par mpmath.iv à 160 décimales, sans Sage ni arithmétique du projet.

**Portée et suite.** Chaîne complète de score dans le modèle réduit, sans
attaque du rang 6, mémoire/coût réel, rotations MLWE ou preuve CCA. Étendre
le contrôle à une famille de matrices/listes puis à une génération de
vecteurs par réduction, sans sélectionner après coup un exemple favorable.
Aucun nouveau coût de sécurité, profil, seuil C05 ou clôture J2. Rapport :
SCORE_DUAL_COMPLET_REDUIT.md.

**Validation finale.** `scripts/dev.ps1 check` passe : sources, rustfmt,
Clippy, 13 tests Rust, 57 tests Python, profil et treize instantanés. Les
145 cas ACVP et 32 échanges à clés fraîches du témoin passent. Les deux
nouveaux vérificateurs sont intégrés aux tâches Windows et Linux ; le
contrôle d'intervalles a été exécuté séparément et rattaché par provenance.
Les 368 empreintes des instantanés et références sont vérifiées contre les
octets indexés dans Git. Les douze instantanés antérieurs et les deux
erreurs BKW historiques sont conservés.

## 24 octobre 2026 — J2, H07 : famille étendue et vecteurs issus de LLL

**Demande.** Élargir les matrices et tailles de liste, puis intégrer des
vecteurs obtenus par réduction de réseau, en gardant les scores vérifiables.

**Préenregistrement.** PROTOCOLE_H07.md au commit 9dfeefa, avant exécution :
16 identifiants par module q=5/17, listes N=4/8/12, deux sources de vecteurs,
deux familles et deux critères, soit 768 panneaux. Les anciennes matrices
0/1 sont conservées. Secret/erreurs CBD(1), dénominateur 16384 et seuils
0 et 1/2, comme H06.

**Développement.** LLL exact en dimension 3, delta=3/4, Gram-Schmidt rationnel,
arrondi déterministe, matrice unimodulaire et trace complète. Contrôles de
réduction en taille, Lovasz, déterminant et relation duale. Énumération des
125 coefficients de [-2,2]^3 autour de la base, projection centrée, retrait
de zéro et des doublons à signe près, témoins conservés. Quatre tests
couvrent les certificats et leur altération, témoins et normes face à
l'oracle, identité du cache et score complet N=12, bases invalides.

**Exécution et conservation.** 32 matrices et 768 panneaux, avec partage
des données exactes donnant 224 banques de scores distinctes. Toutes les
matrices, bases, traces, candidats et panneaux sont conservés. Lois, tables
de scores et distributions exactes sont reconstructibles et liées par
empreintes ; aucun regroupement sur de simples noms de critères. Le
calcul utilise la bibliothèque standard Python sous Windows, sans nouvelle
installation. Résultats de développement copiés octet pour octet dans
run-014 après contrôle des empreintes. Les treize études antérieures sont
préservées.

**Résultats.** LLL+boîte retrouve les préfixes de référence dans les seize
cas à q=5 et, à q=17, dans 15/16,13/16,9/16 cas pour N=4,8,12. Les excès
totaux de norme au carré sur seize listes sont 5,18,70 à q=17. Au code
pondéré q=17/N=8, chaque source donne zéro gain CBD, deux pertes et quatorze
égalités ; les deux pertes gardent une meilleure moyenne du vrai score.
Source LLL : succès strict moyen 29,8553 % euclidien contre 29,6196 % CBD.
Le code répété LLL/N=12 donne six gains, sept pertes et trois égalités,
avec une moyenne CBD supérieure : pas d'ordre uniforme des critères.

**Queues et portée.** À q=17/N=12, queue uniforme au seuil 1/2 moyenne
4,2388 % pour la référence et 3,9792 % pour LLL+boîte, contre 0,7153 %
sous la normale de variance 1/24. Aucun transfert de ces rapports aux
dimensions réelles. Le cas complet q=5/N=12 a exactement une queue 1/25
par orthogonalité ; ce quotient entier n'est pas une liste de crible.

**Contrôle indépendant exécuté.** Programme sans arithmétique importée du
projet : Gram exact par récurrence sur la matrice de Gram, traces et témoins,
listes et décisions, 524 288 configurations littérales de bits CBD. Il
retrouve les lois, événements, empreintes et 822 808 scores de banques
distinctes ; écart maximal observé des moments environ 3,17×10^-15. Les
tables encadrées sont celles, préservées, de run-013. Le vérificateur
standard rejoue chaque panneau et chaque identité de partage.

**Décision et suite.** Certificat LLL, qualité de la liste et utilité des
scores restent distincts. Étendre vers des dimensions et CBD(2)/CBD(3)
plus proches des scénarios étudiés, avant transfert aux paramètres réels.
Aucun nouveau coût global, profil, seuil C05 ou clôture J2. Rapport :
LLL_ET_FAMILLE_ELARGIE.md.

**Validation finale — 25 octobre 2026.** `scripts/dev.ps1 check` passe :
sources, rustfmt, Clippy, 13 tests Rust, 61 tests Python, profil et quatorze
instantanés. Les 145 cas ACVP et 32 échanges à clés fraîches du témoin
passent. La relecture de H07 reconstruit les 224 banques de scores et leurs
empreintes, puis l'oracle indépendant rejoue les certificats et événements.
Les 392 empreintes des instantanés et références correspondent aux octets
indexés dans Git. Les deux nouveaux vérificateurs sont intégrés aux scripts
Windows et Linux. Les treize instantanés précédents et les deux erreurs
BKW historiques sont préservés.

## 25 octobre 2026 — J2, H08 : dimensions 3/5 et distributions CBD(2)/CBD(3)

**Demande.** Augmenter la dimension du réseau et traiter CBD(2)/CBD(3)
avec une seconde méthode exacte, en conservant les contrôles précédents.

**Préenregistrement.** PROTOCOLE_H08.md et NumPy 2.3.5 verrouillés au commit
128c463 avant exécution. q=17, huit matrices par architecture (m,l)=(2,1)
ou (3,2), quatre secrets liés au code, η=1/2/3, N=4/8/12, deux sources,
deux familles et deux critères. 1152 panneaux fixés sans choix après coup.

**Développement.** Nouveau LLL générique rationnel, déterminant exact et
certificats en dimensions 3 et 5 ; module de H07 inchangé. Lois conjointes
(b,u) formées par convolutions entières sur Z_17^(m+1), avec masses et
budget int64 contrôlés avant calcul. Jusqu'à 83521 états d'observation et
dénominateur 2^54. Scores vectorisés par phases, décisions certifiées avec
les tables préservées de run-013, DFT directe et covariance CBD généralisée
au vecteur (y,x,r). Partage des banques seulement par données exactes.

**Contrôles de développement.** Quatre tests nouveaux : calibration LLL 3
vers l'ancien module et certificat 5 avec altération, lois CBD(1/2/3) contre
petits états complets et poids littéraux de bits, budget int64, score complet
dimension 5/CBD(3). Les empreintes de tableaux explicitent forme, type et
ordre d'octets. Les 192 configurations de contrôle CBD(1)/dimension 3
retrouvent exactement les probabilités H07. Aucun changement des tables,
seuils ou profils antérieurs.

**Exécution et conservation.** 16 matrices, 1152 panneaux, 155 banques
distinctes et 96 lois exactes. Données de développement copiées octet
pour octet dans run-015 après contrôle des empreintes. Python 3.13.7 et
NumPy 2.3.5 du runtime local existant, sans installation globale. Les
quatorze instantanés antérieurs restent préservés.

**Résultats.** En dimension 5, les préfixes LLL+boîte de 4/8/12 vecteurs
égalent la référence dans les huit cas pour chaque taille ; la boîte
conserve pourtant seulement 1179..1307 représentants sur 2456. Au code
pondéré/N=12, CBD(2) et CBD(3) donnent chacun zéro gain, trois pertes et
cinq égalités du critère CBD, avec moyenne du vrai score accrue dans les
pertes. Moyennes de succès strict : 13,2684 %/13,2067 % et 8,2826 %/8,2560 %
pour euclidien/CBD. Pas d'ordre uniforme de l'euclidien : le contrôle répété
donne quatre gains et quatre pertes pour η=2 et η=3. Le témoin uniforme
en dimension 5/N=12, indépendant d'η, donne une queue moyenne 3,1447 %
contre 0,7153 % pour la normale de variance 1/24. Aucun transfert quantitatif
aux paramètres réels.

**Contre-vérification exécutée.** Programme sans import de l'arithmétique
du projet : réductions/listes et choix de codes, lois par permutations
de couches Bernoulli, phases par une autre construction, décisions et
moments. Il retrouve 96 lois, 5 949 643 scores de banques distinctes et
tous les événements. 3072 couches de bits au total, jusqu'à 54 par loi,
sans prétendre parcourir littéralement 2^54 configurations. Écart maximal
observé des moments ≈2,43×10^-15.

**Suite.** Relier ces contrôles exacts aux hypothèses de score et de
génération de listes du scénario q=7681, avec ressources explicites.
Aucun nouveau coût global, profil, seuil C05 ou clôture J2. Rapport :
CBD_ET_DIMENSIONS_SUPERIEURES.md.

**Validation finale.** `scripts/dev.ps1 check` passe : sources, rustfmt,
Clippy, 13 tests Rust, 65 tests Python dans le runtime local verrouillé,
profil et quinze instantanés. Les 145 cas ACVP et 32 échanges à clés
fraîches du témoin passent. Les deux nouveaux vérificateurs rejouent les
96 lois, 155 banques et 192 calibrations exactes ; les événements et
empreintes concordent. Les 425 empreintes des instantanés et références
correspondent aux octets indexés dans Git. Les quatorze études antérieures
et les deux erreurs BKW historiques restent conservées.

## 25 octobre 2026 — H09, conditions de transfert à q=7681

**Demande.** Poursuivre le lien entre les contrôles CBD exacts et les
hypothèses de score/listes du scénario réel. Protocole préenregistré dans
PROTOCOLE_H09.md au commit a0b9fab avant les nouveaux calculs.

**Travail.** Audit à points fixes des quatre minima run-009, sans nouvelle
optimisation. Séparation des facteurs réseau/code idéal, reproduction du
budget normal, sensibilités de variance, covariance moyenne admissible,
borne de moments unilatérale et stockage selon deux représentations.
Reconstruction des huit panneaux et 2048 résidus run-011. Résultats
conservés dans run-016 ; les quinze instantanés antérieurs sont préservés.

**Résultats.** Au point MLWE/q=7681, facteur idéal de code 2^-24,925654
contre moyenne CBD pondérée observée 2^-33,380947, rapport 350,99 ; pas
de certificat de population. À liste et seuil fixes, hausse maximale de
variance 0,173146 % au budget normal 0,05. Sous diagonale moyenne 1/2,
covariance moyenne correspondante environ 2^-258,159. Cantelli+union,
même avec les moments supposés, donne la borne 1. Une taille suffisante
2^601,087 à seuil fixé pour ce seul certificat n'est ni nécessaire ni un
coût d'attaque. Liste dense empaquetée : 2^260,016 octets, représentation
explicitée sans borne universelle ni nouveau budget adopté.

**Contre-vérification.** Sans import arithmétique du projet, Decimal à
90 chiffres, autre série d'intégrale, queues normales via Mills/Taylor,
cosinus en série. 192 champs numériques et 2048 résidus retrouvés ; écart
maximal 9,30×10^-12. Les évaluations ne sont pas des certificats par
intervalles. Trois tests nouveaux des bornes et erreurs d'usage.

**Décision.** Aucun transfert de coût avant des listes (y,x,r,c) effectives
au module réel et une loi/queue justifiée. Suite : construire une liste
réalisable à q=7681, contrôler les phases et les moments complets, avec
ressources enregistrées. Aucun coût global, profil ou seuil C05 modifié ;
J2 reste ouvert. Détails : TRANSFERT_SCORE_Q7681.md.

**Validation finale.** `scripts/dev.ps1 check` passe : sources, rustfmt,
Clippy, 13 tests Rust, 68 tests Python, profil et seize instantanés. Les
145 cas ACVP et 32 échanges frais du témoin passent. Les deux vérificateurs
H09 reproduisent les calculs et leur couverture ; les quinze études
antérieures sont rejouées, sans changement de résultats. Les 444
empreintes d'entrées/sorties et références correspondent aux octets
indexés dans Git. Aucun dépôt distant ni publication.

## 25 octobre 2026 — H10, listes et scores complets à q=7681

**Demande.** Réaliser le contrat H09 : listes duales de taille réalisable,
coefficients (y,x,r,c), identités de phase et moments vrais/faux au module
réel, avec ressources mesurées. Protocole figé avant calcul au commit
6827a5a, quatre matrices et aucune sélection après observation des scores.

**Construction.** q=7681/η=3, trois observations, deux coordonnées secrètes
dans le réseau et 140 dans le code, 21 symboles. Réduction LLL rationnelle
en dimension 5 puis boîte [-2,2]^5 : 1562 représentants par matrice,
préfixes 32/64/128. Huit banques, codes répété/pondéré et décodeurs
euclidiens exacts. Aucun réseau de dimension 2576 ni prétention que la
boîte énumère tous les plus courts vecteurs du quotient.

**Résultats.** 4 194 304 identités de phase, 648 moments analytiques,
16 384 états synthétiques CBD de 145 variables ; pas de loi exacte sur
2^870 configurations. Variances numériquement proches de 1/(2N) sur ces
listes. À N=128, log2 du biais pondéré complet de −33,3617 à −31,8142
selon la matrice ; échantillonnage trop faible pour mesurer ces moyennes.
Témoin uniforme : 296/16 384 dépassements de trois écarts types, soit
1,8066 % contre 0,1350 % pour la normale. Les observations LWE sont
différentes ; aucun facteur de queue transféré. Les deux familles ont
le même témoin uniforme à candidat zéro, sans répétition indépendante.
Aucun événement ambigu dans la marge numérique 10^-12 ; pas de certificat
de rang par intervalles. Vingt-six faux candidats choisis, pas q^21−1.

**Ressources et contrôle indépendant.** Étapes primaires instrumentées
≈8,81 s sur le poste, sans extrapolation en rop. Plus grand tableau recensé
4 751 360 octets ; somme recensée 18 388 992 octets par banque, sans RSS
ou pic global. Vérificateur sans import arithmétique du projet : certificats,
listes, 1 101 148 160 termes de distances, tous les échantillons/phases,
moments et événements. Caractères Decimal à 80 chiffres et 64 contrôles
prédéfinis ; écart numérique maximal ≈8,99×10^-12. Données dans run-017,
avec étiquettes et empreintes reconstructibles ; seize études préservées.

**Décision.** Étudier les dépendances d'ordre supérieur et la génération
des listes pour justifier les queues ; ne pas extrapoler ces banques au
grand réseau ni les fréquences finies aux probabilités cryptographiques.
Aucun nouveau coût global, profil, seuil C05 ou clôture J2. Voir
LISTES_DUALES_Q7681.md.

**Validation finale.** `scripts/dev.ps1 check` passe : sources, rustfmt,
Clippy, 13 tests Rust, 71 tests Python, profil et dix-sept instantanés.
Le témoin conserve ses 145 cas ACVP et 32 échanges frais réussis. Les
deux vérificateurs H10 rejouent les huit banques, 648 moments et tous les
événements/empreintes ; les seize études antérieures restent inchangées.
Les 470 empreintes des instantanés et références correspondent aux octets
indexés dans Git. Aucun dépôt distant ni publication.

## 25 octobre 2026 — H11, relations additives et sélection publique

**Demande.** Relier les queues aux dépendances d'ordre supérieur et à la
génération des listes. Protocole préenregistré avant calcul au commit
cfc924c : mêmes 128 candidats H10, ordres norme/hachage/glouton, tailles
32/64/128, sans accès aux scores pour sélectionner.

**Calcul exact.** Convolution des fréquences ±y et orthogonalité : moments
uniformes jusqu'à quatre sous forme rationnelle, spectre et comptes de
relations. 36 panneaux, 28 ensembles distincts ; partage à N=128. Kurtosis
moyenne à N=128 : 44,8121, dissymétrie 4,9351. À N=32, glouton 4,3110
contre 12,1641 pour norme, dans les quatre matrices. Ces moments exacts
ne sont pas une loi complète de queue sur q^3 observations.

**Mesures nouvelles et compromis.** 32 768 observations uniformes : au
seuil trois écarts types/N=32, 806 dépassements pour norme, 260 pour
hachage, 209 pour glouton. 16 384 états CBD nouveaux et 4 194 304 identités
de phase distinctes, réutilisées entre sélections sans triple comptage.
56 panneaux LWE et 224 moments de moyenne/covariance, trois faux candidats
choisis ; moments LWE d'ordre trois/quatre uniquement empiriques. Norme
réseau au carré moyenne +89 % à N=32 avec le glouton, moyenne des log2 du
biais vrai pondéré −1,198 bit. Une matrice gagne en biais, trois perdent.
Aucune conclusion de gain d'attaque ; tous résultats conservés dans run-018.

**Vérification et coût.** Quatre tests nouveaux, dont tore exhaustif et
minimum glouton recalculé intégralement. Contre-vérification sans import
arithmétique du projet : spectres vectorisés complets, autre formule
d'incrément et 33 024 coûts/choix reproduits, bits CBD extraits séparément,
phases/moments et tous événements. Écart absolu maximal ≈5,69×10^-14 ;
erreur des petites moyennes rapportée au biais positif ≤2,85×10^-14.
12 témoins uniformes et 96 moments CBD retrouvent H10. Étapes primaires
instrumentées ≈16,16 s, dont construction des ordres ≈3,05..3,15 s par
matrice ; budget de candidats identique, temps de sélection différent.

**Décision.** Les relations additives expliquent exactement l'excès de
moments du témoin, sans donner sa queue complète ni celle des faux LWE.
La suite doit calculer le quatrième moment CBD complet sur des listes
réduites, avec phases de vrais/faux candidats, avant de juger la sélection
sur le score d'attaque. Aucun nouveau coût global, profil, seuil C05 ou
clôture J2. Détails : SELECTION_ET_MOMENTS_SUPERIEURS.md.

**Validation finale.** `scripts/dev.ps1 check` passe : sources, rustfmt,
Clippy, 13 tests Rust, 75 tests Python, profil et dix-huit instantanés.
Les 145 cas ACVP et 32 échanges frais du témoin passent. Les deux
vérificateurs H11 retrouvent tous les choix, moments, événements et
empreintes ; les dix-sept études antérieures restent inchangées.
Les 507 empreintes des instantanés et références correspondent aux octets
indexés dans Git. Aucun dépôt distant ni publication.

## 25 octobre 2026 — H12, quatrième moment du score CBD complet

**Demande.** Poursuivre H11 par les moments de population du score LWE
complet, avec phases vrais/faux. Protocole préenregistré au commit
8354d10 : quatre matrices, deux codes 140/21, trois ordres publics figés,
préfixes 4/8/16 et quatre décalages choisis avant calcul.

**Calcul.** 36 panneaux, 32 géométries, 64 banques et 1024 moments 1..4.
Développement des 2N fréquences signées, multiplicités entières et termes
équilibrés séparés exactement ; caractères CBD numériques, corrections
signées et logarithmiques conservées. Aucune annulation supplémentaire
des coefficients complets jusqu'à quatre. Les relations sur y seules
ne forcent pas l'annulation de (y,x,r), contrairement au témoin uniforme.

**Résultat.** Kurtosis CBD voisine de 2,625 / 2,8125 / 2,90625 à N=4/8/16,
références de cosinus indépendants. Écart calculé maximal ≈5,775×10^-16
sur les vrais et trois faux candidats. À N=16/norme, le témoin uniforme
donne au contraire une kurtosis moyenne 6,351563. L'amélioration uniforme
du glouton ne fournit pas d'avantage comparable sur le quatrième moment
CBD complet de ces listes. Ce n'est ni une preuve d'indépendance, ni une
queue normale, ni une loi complète sur 2^870 configurations. Les petites
corrections restent numériques, sans certificat par intervalles.

**Vérification et ressources.** Autre développement par indices de cosinus
puis signes, sans import arithmétique du projet : 1 824 768 évaluations,
1024 moments retrouvés, erreur normalisée par masse absolue ≤2,37×10^-13.
256 calibrations moyenne/variance ; 4 194 304 identités de phase rejouées.
Les 16 384 états CBD H11 sont réutilisés et explicitement identifiés.
Quatre tests nouveaux incluent une loi CBD littérale, une relation non
triviale et une correction 2^-1200. Temps primaire d'expansion ≈19,53 s,
dont 17,40 s à N=16 ; lots de 512×145 coefficients, sans mesure RSS globale.
Les 95 818 termes pondérés perdus par exponentiation directe sont signalés
et les corrections agrégées sont conservées dans le domaine logarithmique.

**Décision.** Étendre à N=32 avec encadrement explicite des contributions,
du coût combinatoire et de l'erreur numérique. Conserver les trois
sélections. Aucun coût global, profil choisi, changement C05 ou clôture
J2 ; résultats et limites dans QUATRIEME_MOMENT_CBD.md et run-019.

**Validation finale.** `scripts/dev.ps1 check` passe : sources, rustfmt,
Clippy, 13 tests Rust, 79 tests Python, profil et dix-neuf instantanés.
Le témoin conserve ses 145 cas ACVP et 32 échanges frais réussis. Les
deux vérificateurs H12 retrouvent les 64 banques, 1024 moments et tous
les événements/empreintes ; les dix-huit études antérieures sont
inchangées. Les 545 empreintes des instantanés et références correspondent
aux octets indexés dans Git. Aucun dépôt distant ni publication.

## 25 octobre 2026 — H13, bornes N=32 et première brique moteur

**Demande.** L'utilisateur accepte N=32 et rappelle que le but central
est le développement du moteur cryptographique. Protocole préenregistré
au commit 5fc45d1 : étude bornée, sans extension automatique à 64/128,
accompagnée d'une arithmétique polynomiale de référence et d'une feuille
de route reliant la recherche au passage J2 → J3.

**Calcul.** Quatre matrices, deux codes 140/21 et trois ordres H11 figés,
24 banques q=7681/η=3 à N=32. Majoration des caractères CBD par
2^(-42*norme²/q²), constante justifiée rationnellement. Histogrammes
entiers des atténuations plafonnées à 128, avec masse couverte et termes
équilibrés exacts. Propagation des corrections brutes jusqu'à la kurtosis
par fractions, sans arrondi transcendant dans le certificat. Les bornes
sont uniformes en décalage ; elles ne décrivent pas une récupération
simultanée parmi q^21 candidats ni une queue rare.

**Résultat.** Kurtosis encadrée autour de 2,953125, écart strictement
inférieur à 3×10^-13 dans les 24 banques. Au code pondéré, maxima des
bornes norme/hachage/glouton ≈1,211×10^-13 / 2,982×10^-13 / 6,758×10^-14.
Au code répété, borne ≈1,313×10^-35. Il s'agit de majorations, pas des
écarts réels ni d'un classement de succès d'attaque. Aucune annulation
complète supplémentaire jusqu'à quatre dans ces banques.

**Contrôles et ressources.** Voie indépendante par indices de cosinus
puis signes, toutes coordonnées calculées : histogrammes et fractions
identiques sur les 24 banques et 64 calibrations H12, 23 132 160
évaluations indice/signes. Les 1024 corrections numériques H12 sont
contenues dans les bornes ; aucun nouvel échantillon. Cinq tests nouveaux,
dont loi CBD(3) pondérée et oracle ordonné. Primaire N=32 : 19 545 216
multisets, 13 757 076 arrêts anticipés, 1 924 428 844 coordonnées et
≈65,09 s de calcul instrumenté. Pas de mesure du RSS global.

**Développement moteur.** Ajout de reference_ring.rs : polynômes
canoniques de degré inférieur à 256, addition, soustraction et produit
dans Z_q[X]/(X^256+1). Trois tests Rust confrontent la convolution à
une construction ordinaire indépendante, les lois de l'anneau et le
signe X^255*X=−1, aux modulos 3329/7681 et avec contrôle large 65535.
Aucune dépendance ajoutée. Référence algébrique sans temps constant ni
effacement mémoire établis ; le KEM de rang 6 n'est pas implémenté.

**Décision.** Le volet d'extension des moments s'arrête ici. Prochaine
étape principale : bilan C01–C06 pour le passage J2 → J3, critères et
obstacles explicites ; les primitives indépendantes des paramètres finaux
peuvent avancer. Pas de nouveau coût global, profil, modification de C05
ou clôture J2. Voir BORNES_N32_ET_MOTEUR.md et FEUILLE_DE_ROUTE_MOTEUR.md.

**Validation finale.** `scripts/dev.ps1 check` passe : sources, rustfmt,
Clippy, 16 tests Rust, 84 tests Python, profil et vingt instantanés.
Les 145 cas ACVP et 32 échanges frais du témoin passent. Les deux voies
H13 retrouvent exactement les histogrammes et bornes des 24 banques
N=32 et 64 calibrations H12. Les dix-neuf instantanés précédents restent
inchangés. Les 572 empreintes des instantanés et références correspondent
aux octets indexés dans Git. Code, rapport et feuille de route enregistrés
localement, sans dépôt distant ni publication.

## 25 octobre 2026 — M01, développement autonome du moteur R1

**Demande et décision.** L'utilisateur demande de développer le moteur
autant que possible sans attendre sa validation, avec rapport tenu à jour.
Le bilan et la spécification sont enregistrés avant les vecteurs au
commit e325f50. Le codage expérimental avance en parallèle de J2, sans
clôture présumée de la faisabilité ni sélection finale du candidat.

**Première réalisation.** Rust, profil d'essai KEM1536-DEV-Q7681-R1,
q=7681/η=3/u exact/dv5 : cœur PKE, KeyGen/Encaps/Decaps, aléa système,
encodages canoniques, domaines SHA3/SHAKE, réencapsulation et rejet
implicite sans drapeau de rejet applicatif. Les premiers échanges frais
et déterministes, formats et remplacement sur chiffré non canonique
passent. Une référence Python indépendante est écrite ; la confrontation
sur corpus et les contrôles longs sont en cours. Les objets secrets
possédés sont effacés au drop autant que possible ; l'effacement intégral
des temporaires et les propriétés temporelles restent non audités.

**Confrontation complète.** 1000 vecteurs publics synthétiques concordent
sur douze champs, avec clés, chiffré, secrets et rho/sigma/A00. Une campagne
Rust réussit 10000 échanges frais et 10000 contrôles de rejet ; environ
111,85 s au total, sans journalisation de secrets. La référence Python
établit le rejet de 10000 chiffrés à u non canonique et calcule leurs
remplacements. Un deuxième corpus fait traiter les mêmes 10000 chiffrés
par Rust : tous les secrets de remplacement sont identiques, empreinte
cumulative 43b202c5974c37186c1c4650ae1cd6782fe44772c8cdaee190938186e2e20fc0.
Les vecteurs et contrôles appariés sont conservés dans results/engine,
avec sources copiées pour permettre l'évolution du moteur courant.

**Provenance des exécutables.** Le build applicatif et le build de
recherche produisent des exécutables différents. Leurs empreintes sont
enregistrées séparément ; l'empreinte du build de recherche a été relevée
sur l'artefact de compilation conservé, le chemin release principal ayant
été réutilisé par la campagne applicative. La correction de cette
métadonnée est effectuée avant gel, sans changement de vecteur ou calcul.

**Interfaces et suite.** Auto-test sans sortie de secret, API typée et
source système par défaut ; interfaces déterministes uniquement sous
fonctionnalité explicite research-vectors. Tests des longueurs proches
±1..32, canonicité en fin de vecteur, rejet d'un chiffré canonique nul
établi par réencapsulation et empreinte du cas 0. T02/T03 atteignent
leurs nombres de cas sur R1, T04 comporte 10000 échanges et T06 un corpus
apparié de 10000 rejets dans la famille définie. Cela ne valide pas tout
J3 : mémoire, temps, fuzzing, portabilité et dossier cryptographique restent
ouverts. Le guide MOTEUR_KEM_R1.md et la feuille de route sont actualisés.

**Validation finale.** `scripts/dev.ps1 check` passe : intégrité des
sources, rustfmt, Clippy avec toutes les fonctionnalités, 25 tests Rust
dans la configuration par défaut et 25 avec recherche (26 tests distincts),
87 tests Python, vingt instantanés J2 et contrôles du moteur. Les 145
cas ACVP et 32 échanges frais du témoin restent réussis. Le contrôle
ordinaire vérifie toutes les empreintes des corpus puis rejoue 16 vecteurs
et 16 rejets appariés ; il effectue aussi 16 échanges et rejets frais R1.
Les campagnes intégrales de 1000 vecteurs, 10000 échanges frais et 10000
rejets appariés ont été exécutées séparément et leurs bilans conservés.
Les 603 empreintes des instantanés, sources archivées et références
correspondent aux octets indexés dans Git. Aucun dépôt distant, déploiement
ou publication. L'autorisation de poursuivre sans nouvelle validation
de routine est conservée pour les étapes suivantes du moteur.

## 25 octobre 2026 — M02, mémoire et durcissement du moteur

**Demande et protocole.** L'utilisateur demande de durcir le moteur et
de faire tout ce qui est possible dessus. Protocole 63fd895 avant nouvelles
campagnes : mémoire, 20000 entrées de formats, 10000 décapsulations
malveillantes dans cinq classes, confrontation aux corpus M01 et diagnostic
temporel de 2000 mesures par classe après 100 échauffements, seuil |t|≥4,5.

**Corrections initiales.** La clé privée ne passe plus par un Vec secret
qui s'agrandit ; un propriétaire fixe efface ses octets avant libération.
Les vecteurs de polynômes, sorties de bruit et réencapsulation emploient
des tailles fixes, les accumulateurs sont effacés et les copies temporaires
évitables sont retirées. La validation d'import examine tout le vecteur ;
le calcul interne emploie ensuite les invariants des objets validés.
L'arithmétique R1 spécialisée est séparée de l'oracle générique et utilise
des réciproques entières exactes, sans division dépendant d'un secret au
niveau source. Tests de bornes et comparaison d'oracle réussis.

**Chaîne Linux.** Rust 1.91.0 installé localement sous .tools, installateur
vérifié par SHA256, sans modification des outils globaux. Premier passage
des tests Linux réussi sous Ubuntu 22.04/WSL2 ; le passage final, les
corpus interplateformes, les contrôles mémoire et temporels suivent.

**Version effective et infrastructure.** Le bootstrap a demandé 1.91.0,
mais rust-toolchain.toml a ensuite sélectionné et installé **1.91.1** :
c'est la version effectivement enregistrée et utilisée pour tous les
tests, builds, sondes et corpus Linux, comme sous Windows (LLVM 21.1.2).
Le premier build assembleur Windows a échoué sur dlltool ; l'ordre des
outils natifs dans engine.ps1 a été aligné sur dev.ps1, puis le build
a réussi. Les deux journaux sont préservés ; cet échec d'outillage ne
constitue pas un résultat cryptographique.

**Régressions et robustesse complètes.** Sur chaque cible Windows/Linux,
1000 vecteurs complets et 10000 remplacements retrouvent exactement M01.
Les 20000 imports comportent 17010 longueurs incorrectes, correctement
rejetées, et 2990 entrées de longueur exacte ; les 993 imports acceptés
sont des chiffrés de bonne longueur, sans attestation d'encapsulation
honnête. Aucun panic observé. Les cinq classes de 2000 mutations produisent
les mêmes sorties sur les deux cibles ; Python déchiffre, réencapsule et
retrouve les 10000 rejets et remplacements. Il s'agit de **5351 chiffrés
distincts**, les répétitions étant conservées. Empreinte cumulative :
512c32699c9933e45f170df59b9bf0140e316562fa8429c5e7cbbb85450ae1c7.

**Instrumentation mémoire.** Tests Linux avec/sans recherche : 28 tests
par configuration (29 distincts). Les 28 tests avec recherche passent
aussi sous AddressSanitizer avec détection de fuites. Le binaire release
instrumenté traite ensuite les 20000 formats et les 10000 mutations :
sorties identiques aux corpus vérifiés, codes de sortie 0/0, stderr vide.
La bibliothèque standard précompilée n'est pas réinstrumentée et les
copies du compilateur ou de registres ne sont pas toutes garanties
effacées. Les rapports, empreintes et journaux sont archivés dans M02.

**Diagnostic temporel et assembleur.** Après les autres calculs lourds,
100 échauffements puis 6000 mesures, soit 2000 par classe fixée avant
mesure. Les trois t de Welch sont 2,715636 / 3,026806 / 0,370974 : aucun
dépassement du seuil |t|≥4,5, sans preuve générale de temps constant.
Une clé et trois entrées fixes sur un hôte Windows non isolé limitent
le diagnostic ; les durées brutes sont conservées sans seconde campagne
sélectionnée a posteriori. Les sondes scalaires réduction/quotient n'ont
ni division ni branche conditionnelle sous Windows et Linux, sans
inspection complète du binaire. Les témoins analytique et négatif du
vérificateur passent. Voir DURCISSEMENT_MOTEUR_M02.md.

**Suite du moteur.** Les nouveaux résultats sont regroupés dans
results/engine/hardening-001 avec sources archivées ; les instantanés
M01 et les vingt J2 sont inchangés. Fuzzing long à couverture guidée,
analyse temporelle et mémoire plus large, revue des dépendances,
benchmarks P01, million de parcours avant gel et revue externe restent
ouverts. Aucun nouveau niveau de sécurité ni clôture J2/J3/J4.

**Validation finale M02.** `scripts/dev.ps1 check` réussit : sources,
rustfmt, Clippy toutes fonctionnalités, 28 tests Rust par configuration
avec/sans recherche (29 distincts), 89 tests Python, vingt instantanés J2
et leurs reconstructions indépendantes. Le contrôle ordinaire rejoue
16 vecteurs M01, 16 rejets M01 et 16 mutations M02, vérifie toutes les
empreintes et recalcule les statistiques des 6000 observations. Les
16 échanges et 16 rejets frais R1 passent ; le témoin conserve ses 145
cas ACVP et 32 échanges frais. Les campagnes complètes restent distinctes
de ce rejeu réduit. Les journaux du contrôle final et des tests Linux/ASan
sont archivés. Un second contrôle du manifeste enrichi réussit après
ajout de ces preuves, sans nouvelle mesure temporelle. Aucun dépôt
distant, déploiement ou publication.

**Livrable applicatif M02.** Le binaire release final est reconstruit sans
research-vectors ; les cinq commandes de recherche sont indisponibles,
sans sortie de données. Son auto-test réussit 16 échanges et 16 rejets
frais supplémentaires, sans afficher de secret. Son empreinte est
dc15ba07d79dbf9d9fe89d7b2413677d80987a5f80ab1d2be38e60ae4379f870,
distincte des builds de recherche utilisés dans les campagnes. Les preuves
sont conservées dans evidence/application.json et les deux journaux.

**Intégrité avant enregistrement.** Les 650 empreintes des instantanés,
sources archivées et références correspondent aux octets indexés dans
Git. Le contrôle des différences indexées ne signale pas d'erreur de
format ; les journaux bruts sont conservés sans normalisation. Aucun
changement des anciens instantanés J2 ou M01 n'est indexé.

## 25 octobre 2026 — M03, préparation des campagnes longues et de P01

**Instruction et préenregistrement.** L'utilisateur demande le fuzzing
prolongé à couverture élargie, l'analyse des binaires et les benchmarks.
Le protocole initial est enregistré au commit 9a226ae avant les campagnes.
Le budget est précisé avant lancement : quatre travailleurs de six heures
CPU effectivement mesurées, par segments d'au plus dix minutes murales.
Les durées CPU et murales sont distinguées ; T07 reste ouvert.

**Harnais et outils construits.** cargo-fuzz 0.13.1 installé localement,
libfuzzer-sys 0.4.13 verrouillé, Rust 1.91.1, llvm-tools et sources Rust
locaux. Quatre cibles : import public, import privé, décapsulation et
séquences structurées d'API. Corpus initial : seize clés synthétiques
publiques M01, formats valides, longueurs proches, chiffrés nuls et
coefficients non canoniques. Aucun secret d'application utilisé.
La bibliothèque standard Rust est recompilée avec l'instrumentation ASan.
Le test court et les 24 heures CPU cumulées ne sont pas encore exécutés.

**Inventaire initial des binaires.** Désassemblages complets et exécutables
compressés conservés sous artifacts/generated/m03-inspect-*. L'inventaire
repère 26 fonctions R1 sous Windows et 16 sous Linux : aucune division
entière dans ces fonctions. La résolution des appels Linux via les
relocalisations étend la fermeture à 125 fonctions repérées, contre 32
avant résolution. Les corps des bibliothèques système et les cibles
dynamiques non résolues restent hors de ce constat. La revue des
branchements est encore en cours ; aucune preuve de temps constant.

**P01 prêt à mesurer.** Nouvel exécutable de benchmark compilé sous Windows
et Linux, R1 et témoin RustCrypto ML-KEM-1024 sur le même hôte. Cinq séries
de 1000 observations par fonction et moteur, échauffement, validation des
échanges hors mesure, sorties consommées et destruction hors mesure.
La convolution directe de R1 et la NTT du témoin seront distinguées.
Les pics mémoire seront ceux des processus, pas une mémoire algorithmique
isolée. Aucun benchmark final n'est encore enregistré à ce stade.

**P01 exécuté.** 30000 observations par système, Windows puis Linux/WSL,
sur Ryzen 7 2700, Rust 1.91.1 en release, sans ASan/couverture. Les médianes
R1 KeyGen/Encaps/Decaps sont 1,987300 / 2,167600 / 2,543700 ms sous Windows,
2,033402 / 2,401786 / 2,772427 ms sous Linux. Le témoin ML-KEM-1024 est
plus rapide ; la comparaison distingue les profils et la NTT du témoin
face à la convolution directe de R1. Toutes les séries et valeurs brutes
sont conservées, sans suppression de valeur. Les pics processus Windows
sont 5496832 octets pour les deux moteurs et les pics RSS Linux 2048 Kio
pour les deux ; il ne s'agit pas de mémoire algorithmique isolée.

**Revue du compilé.** Les cinq divisions de la fermeture large Windows
repérée proviennent d'Instant et du compteur de performance, pas des
coefficients du KEM. Les six branchements de la multiplication examinée
dépendent des compteurs et de i+j. La comparaison du chiffré de Decaps
examinée parcourt les 332 mots et la sélection finale utilise des cmov
sur registres. Les limites d'appels indirects restent publiées.

**M03-A01 ouvert.** L'assembleur de multiply Windows montre une zone
résultat de 512 octets à rsp+0x20, copiée vers la destination, tandis que
la boucle finale efface les accumulateurs à partir de rsp+0x220. La zone
résultat temporaire n'est pas explicitement effacée dans cet épilogue.
Cela précise la limite connue des copies de déplacement, sans démonstration
de fuite de protocole ni lecture de mémoire libérée. Aucune disparition
générale des copies ni clôture T08 n'est revendiquée. Constat et compromis
à qualifier dans le dossier M03 ; le moteur n'est pas changé pendant
les mesures pour masquer ce résultat.

**Contrôle court.** Les quatre premiers travailleurs ont terminé sans
erreur signalée : 84,23 secondes CPU cumulées. Un second passage sur les
harnais finaux contrôle aussi le post-traitement automatique : couverture
des sources, corpus et oracle Python. La durée longue reste à atteindre.


## Actualisation automatique M03 — 2026-10-25T14:59:22.748948+00:00

Temps CPU de fuzzing cumulé mesuré : 85.01 s. Budgets atteints : True. Post-traitements : {"coverage_exported": true, "independent_corpus_replayed": true}. Preuves dans results/engine/m03-smoke-001. La revue finale reste requise ; T07 et la validation globale ne sont pas déclarés acquis automatiquement.

## 25 octobre 2026 — M03, livraison des mesures et lancement prolongé

**Campagne prolongée lancée.** À 16 h 01, heure de Paris, le contrôleur
est lancé en arrière-plan sous WSL depuis les sources 8ef4ceb, avec quatre
objectifs de 21600 s CPU mesurées. Les quatre cibles sont observées actives,
et les premiers segments de dix minutes se terminent avec code 0 puis
reprennent en conservant le corpus. Le suivi vivant est dans
artifacts/generated/m03-long-001/progress.json. Les sources et exécutables
ont été copiés au lancement ; les changements ultérieurs du dépôt ne
remplacent pas silencieusement ce moteur testé. Le contrôleur prévoit
l'archive nouvelle m03-fuzz-001 et un ajout au rapport/journal après la
fin. Aucune clôture T07 anticipée.

**Contrôle court final et couverture.** 85,01 secondes CPU, aucune erreur
signalée, corpus conservé dans m03-smoke-001. Les 511 requêtes déterministes
du corpus retenu concordent entre le Rust Windows et l'oracle Python M01,
à partir des entrées des harnais Linux. La cible de séquences exerce
276/311 lignes de dev_kem.rs, 53/53 d'engine_poly.rs et 15/15 de secret_box.rs
dans l'export LLVM du test court, avec 44/46 fonctions de dev_kem.rs.
Ces métriques de lignes ne sont pas les compteurs cov/ft du fuzzer et
ne sont pas une couverture exhaustive du projet ou une preuve de sécurité.

**Validation finale.** Le check complet avec le nouveau vérificateur
intégré réussit : rustfmt, Clippy, 28 tests Rust par configuration
(29 distincts), 91 tests Python et vingt instantanés J2. Les 60000 durées
sont recalculées depuis les données brutes ; les deux inventaires sont
reconstruits depuis les désassemblages et les sources du contrôle court
sont liées à leur archive par empreintes. Après ajout du journal final,
le manifeste enrichi est vérifié séparément. Les 730 empreintes des
instantanés et références sont contrôlées contre les octets indexés ;
les anciens instantanés sont inchangés. Les fichiers d'en-têtes bruts
gardent leurs espaces et octets d'origine.

**État à la livraison.** P01 mesuré et archivé dans m03-001 ; revue
statique tracée avec M03-A01 et cibles indirectes non résolues encore
ouvertes ; campagne longue en exécution, à revoir après sa fin. La
construction, J2/J3/J4, le temps constant général et l'effacement de toutes
les copies ne sont pas validés par cette livraison. Aucun déploiement ou
publication distante.

## 25 octobre 2026 — Préparation de majax_mlkem1536

L'auteur précise que le démonstrateur majax-mlkem1024-demo lui appartient
et demande un projet parallèle pour rendre visible le développement du
moteur 1536. Nom choisi : MajidNIMAR/majax_mlkem1536. Le projet local reste
dans NIST. Le README public explique la construction R1, les commandes,
les preuves et les limites. Le contexte détaillé antérieur est conservé
séparément, et les notices RustCrypto/NIST sont maintenues.

Préparation d'un export des seuls fichiers d'un commit, sans historique
Git privé, caches ou campagne vivante. Le manifeste de publication lie
les fichiers au commit local. Les identifiants historiques des protocoles
restent explicitement locaux. Les trois extraits coded-dual sans licence
établie sont exclus de l'export ; le setup les télécharge à leurs URLs
immuables et vérifie les empreintes. Les instantanés locaux sont préservés.
Licence Apache-2.0 cohérente avec le projet compagnon. La CI ajoute la
préparation Python 3.13/NumPy 2.3.5 et des références avant dev check.
La validation de la copie propre et la création publique restent à constater.


## 25 octobre 2026 — Copie de publication contrôlée et dépôt créé

Le dépôt public MajidNIMAR/majax_mlkem1536 est créé ; le signalement privé
des vulnérabilités est activé. La copie exportée du commit e2e9bc9 compile
dans une cible neuve. L'auto-test retrouve 16 échanges et 16 rejets, puis
le contrôle complet termine avec code 0 : tests Rust, 91 tests Python,
vingt études J2 et preuves moteur. Les trois copies externes omises de
l'export ont été récupérées et vérifiées par empreintes. Les journaux et
le manifeste testé sont conservés dans results/publication/initial-001.
Les outils et caches locaux ont été réutilisés par une jonction ignorée ;
ce contrôle ne démontre pas une installation à neuf ou des binaires
identiques. La copie finale précise seulement les documents et ajoute ces
preuves ; moteur, scripts, profils et CI restent identiques à l'export
qui a passé les contrôles. Le statut distant se lit sur GitHub Actions.
La campagne longue M03 continue séparément et n'est pas déclarée terminée.
