# Études mathématiques

Ce répertoire contient les calculs de bruit, les probabilités d’échec et la première comparaison d’attaques. Le [rapport](../docs/RAPPORT_RECHERCHE.md) explique les hypothèses et limites ; le [journal](../docs/JOURNAL_RECHERCHE.md) conserve les étapes. Les résultats figés sont dans `results/j2/run-001/`.

La comparaison moderne est conservée séparément dans `results/j2/run-002/`. Elle utilise `run_modern.py`, `modern_worker.py` comme cœur d'estimation inchangé et `modern_worker_json.py` pour l'export robuste des grands coûts. `modern-tools-manifest.json` fige les archives des estimateurs ; les fichiers `sage-*` verrouillent le runtime. `prepare_sage_archives.py` vérifie les SHA-256 des 158 paquets conservés localement.

`check_profile.py` utilise Python 3.11 ou ultérieur, sans dépendance supplémentaire. Il recalcule les dimensions et les tailles du profil TOML. Il n’effectue aucune validation cryptographique.

`verify_sources.py` vérifie les empreintes des sources, l’identité du paquet de référence et le décompte des vecteurs ML-KEM-1024. Il identifie indépendamment les sorties de rejet implicite avec `hashlib.shake_256`, à partir des graines publiques des tests.

```powershell
python research/check_profile.py
```

`noise_exact.py` calcule les lois sans troncature avec des entiers. `noise_crosscheck.py` vérifie la queue historique par une autre construction numérique à convolutions positives. `attack_models.py` utilise le modèle primal/dual historique des auteurs de Kyber, vérifié par empreintes, avec contrôle de son accélération. `run_j2.py` produit les résultats et leur provenance. `verify_results.py` contrôle l’instantané actif et les empreintes du code correspondant.

```powershell
.\scripts\research-setup.ps1
.\scripts\dev.ps1 analysis
python -m unittest discover -s research -p test_*.py
python research/verify_results.py
```

Les outils amont se téléchargent dans `.tools/upstream/`, par URLs de commit et SHA-256 de `tools-manifest.json`. Ils ne sont pas inclus dans la distribution des sources du projet. Le calcul exact et les six tests n’exigent pas NumPy ; la contre-vérification complète l’utilise dans l’environnement local dédié.

Les exécutions ordinaires écrivent dans `artifacts/generated/j2`. L’option `--snapshot --output results/j2/run-NNN` de `run_j2.py` exige un nouveau dossier. Après une évolution du code, conserver sa version Git, créer un nouvel instantané et actualiser explicitement le pointeur `RUN` du vérificateur avant de figer ce nouvel état. Ne pas écraser `run-001`.

Les estimations historiques ne couvrent pas les hybrides modernes ni l’ensemble de la sécurité du KEM. Les graines synthétiques et résultats reproductibles peuvent être publiés ; aucun secret d’application ne doit être utilisé.

La nouvelle matrice couvre les familles documentées dans la revue, sur deux budgets d'échantillons. Les huit appels de rotations sur CBD denses sont exploratoires. Les deux erreurs BKW sont conservées, ainsi que les huit premières tentatives d'export reprises. `verify_modern_results.py` vérifie le nouvel instantané sans Sage. Les dix tests Python incluent maintenant la dépendance de coefficients de bruit et l'export des coûts hors du domaine des flottants usuels.

```powershell
.\scripts\bootstrap-modern.ps1
.\scripts\dev.ps1 modern
python research/verify_modern_results.py
```

Ne pas écrire de nouvelles sorties dans `run-001` ou `run-002`. Le lanceur moderne refuse d'écraser un dossier existant sous `results/`. Une revue bibliographique ciblée, des sorties d'outils et une preuve de sécurité restent des éléments distincts.

Le diagnostic prioritaire de décapsulation est conservé dans `results/j2/run-003/` et expliqué dans `docs/DIAGNOSTIC_DECAPSULATION_P0.md`. `decapsulation_diagnostic.py` décompose la variance et compte des bornes modulaires permettant à l'arrondi final v de dépendre arbitrairement du bruit, sous une borne déterministe. L'hypothèse de distribution de u reste présente. `run_decapsulation.py` compare six scénarios sans sélectionner de nouveau profil ; il n'écrase aucun fichier. `verify_decapsulation_results.py` vérifie les empreintes et les accords exacts avec quatre scénarios antérieurs. Quatre tests supplémentaires portent le total Python à quatorze.

```powershell
python research/run_decapsulation.py --output artifacts/generated/diagnostic-nouveau
python research/verify_decapsulation_results.py
```

`run-004` poursuit l'étude avec `u_dependency.py` : lois d'idéaux/classes affines vérifiées exhaustivement sur un petit anneau et témoins de correction avec u exact. `witness_chernoff.py` ajoute un certificat rationnel par une seconde méthode, sans récurrence de distribution. Les deux fichiers initiaux du run sont conservés ; le certificat a sa propre provenance. Les sept nouveaux tests vérifient l'algèbre par CRT, la dépendance effective, le seuil entier, les MGF par énumération des bits, les zones sûres et une majoration de petite somme. Total courant : 21 tests Python.

```powershell
python research/run_u_dependency.py --output artifacts/generated/u-dependency-nouveau
python research/verify_u_dependency_results.py
python research/verify_witness_certificate.py
```

Le générateur `witness_chernoff.py` est lié à l'instantané existant et refuse de remplacer son certificat ; utiliser son vérificateur pour rejouer le calcul. Ne pas modifier les fichiers de `run-004` ni leurs entrées après gel sans conserver explicitement une nouvelle version scientifique.

`run-005` conserve H01 avec `mixed_precision.py` : 224 répartitions par blocs et 16 frontières/pas suivants entre coefficients, tous recalculés en rationnels après présélection. La borne majore les arrondis par leur support, sans indépendance de ceux-ci. `winner-certificate.json` conserve les MGF et la fraction du meilleur point trouvé ; `screening.json` contient seulement les propositions numériques. `verify_mixed_certificate_bits.py` reconstruit indépendamment la fraction depuis les bits CBD3, sans importer le moteur. Quatre tests supplémentaires portent le total Python à 25.

```powershell
python research/run_mixed_precision.py --output artifacts/generated/mixed-precision-nouveau
python research/verify_mixed_precision_results.py
python research/verify_mixed_certificate_bits.py
```

La reproduction complète de la matrice peut prendre plusieurs minutes en arithmétique rationnelle ; le contrôle courant rejoue seulement les certificats nécessaires. Les scores de recherche ne sont pas des preuves, les cas non certifiés ne sont pas des preuves d'échec, et le meilleur point trouvé ne revendique pas l'optimalité globale. Voir `docs/PRECISION_MIXTE.md`.

`run-006` conserve H02 dans `group_quantization.py` : cinq tores exhaustifs, le certificat de couverture au module réel et les 16 bornes de quantification par paires. Le décalage de lignes permet le support joint L1≤1 à q=7681,b=12. `verify_group_certificate_bits.py` reconstruit la couverture et les MGF sans importer l'arithmétique du projet. Quatre nouveaux tests portent le total Python à 29.

```powershell
python research/run_group_quantization.py --output artifacts/generated/group-quantization-nouveau
python research/verify_group_quantization_results.py
python research/verify_group_certificate_bits.py
```

La meilleure moyenne sur un petit tore ne garantit pas la couverture : le cas q=17,b=3 est conservé. Le critère MGF local n'améliore pas les cinq histogrammes euclidiens. La borne globale conserve le support joint et ne suppose pas l'indépendance des arrondis. Aucun KEM de rang 6 n'est implémenté par ces outils mathématiques.

`compare_compression.py` conserve run-007 : propositions sur la grille existante et validation rationnelle de neuf points à trois exigences de correction communes, plus rattachement explicite aux trente évaluations LWE identiques de run-002. Les valeurs de compression n'entrent pas dans ces estimateurs ; aucun nouveau coût ni garantie CCA. Rejeu : `python research/compare_compression.py --verify`. Nouvelle étude : préciser un `--output` inexistant sous `artifacts/generated/`. Deux tests contrôlent les décisions exactes aux frontières et la conservation des hypothèses d'attaque.

`coded_dual_model.py` et `run_coded_dual.py` adaptent le modèle des auteurs au rang 6 : sources et archive e2104 verrouillées, six calibrations avant toute estimation nouvelle, grille et recherche locale bornées, rejet explicite des plafonds inadmissibles. `scripts/coded-dual.sh --output <nouveau-dossier>` utilise le runtime Sage local. `verify_coded_dual_numeric.py` contre-vérifie les quatre points retenus avec les fonctions des auteurs et une autre voie numérique. Le contrôle Python standard `verify_coded_dual_results.py` valide les empreintes et cohérences conservées, sans relancer Sage. Quatre tests supplémentaires couvrent petits cas probabilistes exacts, limites et identités d'intégration. Les coûts GV/score normal sont conditionnels et ne valident pas un niveau global de sécurité ; voir `docs/DUAL_CODES_ROTATIONS.md`.

`refine_coded_dual.py` poursuit run-008 dans un module séparé : reprise de ses points, descente à quatre échelles puis vérification des 32 voisins unitaires d'un ou deux axes. Le plafond de sécurité et les diagnostics non résolus empêchent une déclaration de stabilité. `scripts/coded-dual-refine.sh --output <nouveau-dossier>` utilise le runtime Sage ; `verify_coded_dual_numeric.py` contre-vérifie les points finaux sans modifier le modèle. Contrôle standard de run-009 : `python research/verify_coded_dual_refinement.py`. Quatre tests supplémentaires portent le total Python à 39. Les 1187 nouvelles évaluations et 44 trajectoires sont conservées ; aucune optimalité globale n'est revendiquée.

`block_decoder.py` implémente des codes directs par blocs répétés/pondérés, un décodeur exact par intervalles pour les blocs répétés et un oracle entier exhaustif. `block_decoder_numpy.py` accélère l'énumération exacte des blocs pondérés. `scripts/block-decoder.sh --output <nouveau-dossier>` exécute les huit expériences sous le runtime local verrouillé ; il n'implémente pas Decaps du KEM. `verify_block_decoder_results.py` reconstruit les données et distances sans NumPy ; `verify_block_decoder_independent.py` rejoue les livres complets des petits codes et 64 blocs réels sans import de l'arithmétique du projet. Cinq tests supplémentaires portent le total Python à 44. Voir `docs/DECODEUR_CONCRET.md` et run-010 pour les mesures, le repère GV et les limites de toute transposition aux coûts d'attaque.

## Contribution CBD des résidus — run-011

`decoder_score.py` calcule le biais cosinus CBD idéal, une majoration
gaussienne, des moments entiers empiriques et des covariances à secret
partagé. `run_decoder_score.py --output <nouveau-dossier>` reconstruit les
2048 résidus de run-010 et produit les contrôles exhaustifs et à norme égale.
`verify_decoder_score_results.py` rejoue les calculs et contrôle les trois
provenances ; `verify_decoder_score_independent.py` retrouve les lois des
petits modèles sans importer l'arithmétique du projet. Ces deux programmes
sont inclus dans `check` et utilisent la bibliothèque standard.

`verify_decoder_score_numeric.py --run <nouvelle-étude>` exige mpmath et crée
une contre-vérification à 160 décimales sans écrasement. Les 114 contrôles
de run-011 ont déjà été exécutés sous le runtime local verrouillé. Ces calculs
concernent la contribution du code sous CBD idéal, pas un score d'attaque
complet ni une probabilité de succès. Voir [la méthode](../docs/SCORES_DECODEUR.md).

## H05 — Comparaison de critères du décodeur, run-012

`cbd_decoder.py` contient l'oracle scalaire, la garantie uniforme fondée sur
les poids entiers et les certificats de minimum réel. `cbd_decoder_numpy.py`
énumère les mêmes q symboles par bloc pour les deux critères.
`run_cbd_decoder.py --output <nouveau-dossier>` exige Sage pour les poids
encadrés et NumPy pour la comparaison aux modules réels ; il peut être
exécuté via le runtime local micromamba déjà utilisé par block-decoder.sh,
en remplaçant son programme cible par ce runner. Le dossier doit être neuf.

`verify_cbd_decoder_results.py` et `verify_cbd_decoder_independent.py` sont
inclus dans `check` et utilisent la bibliothèque standard. Le second vérifie
les livres de codes complets et 64 blocs réels, sans importer l'arithmétique
du projet. `verify_cbd_decoder_intervals.py --run <nouvelle-étude>` vérifie
chaque poids avec mpmath.iv à 160 décimales et crée sa provenance sans
écrasement. Le protocole préenregistré et les manifestes du runtime sont
des entrées figées. Voir [l'étude](../docs/DECODEUR_CRITERE_CBD.md).

## H06 — Score LWE dual complet réduit, run-013

`full_dual_toy.py` construit les représentants duaux, lois LWE, scores de
tous les candidats, événements certifiés et moments avec covariances.
`run_full_dual_toy.py --output <nouveau-dossier>` exécute le protocole H06
préenregistré ; seul le calcul des tables encadrées exige le runtime Sage
local. Il refuse tout écrasement. Le calcul ne met en œuvre ni BKZ ni FFT
optimisée ; une DFT directe est comparée à chaque histogramme de score.

`verify_full_dual_toy_results.py` rejoue les 32 panneaux en Python standard.
`verify_full_dual_toy_independent.py` reconstruit les listes et scores et
énumère littéralement les bits CBD, sans importer l'arithmétique du projet.
Ils sont intégrés à `check`. Le contrôle par intervalles déjà exécuté est
conservé ; `verify_full_dual_toy_intervals.py --run <nouvelle-étude>` le
reproduit avec mpmath.iv à 160 décimales, sans écrasement des sorties.
Voir [la méthode](../docs/SCORE_DUAL_COMPLET_REDUIT.md).

## H07 — Famille élargie et réduction LLL, run-014

`exact_lll.py` réduit une base entière 3×3 avec Gram-Schmidt rationnel,
certificat unimodulaire et trace, puis énumère une boîte bornée dans le
quotient. `dual_expansion.py --output <nouveau-dossier>` exécute le protocole
préenregistré, sans Sage ou NumPy. Il partage les scores uniquement quand
toutes les données exactes coïncident. Chaque loi, table de scores et
distribution exacte est reconstructible et contrôlée par SHA-256.

`verify_dual_expansion_results.py` rejoue les 768 panneaux et 224 banques.
`verify_dual_expansion_independent.py` emploie une autre vérification de Gram,
reconstitue les candidats et énumère les bits CBD sans importer l'arithmétique
du projet. Les deux sont intégrés à `check`. Les tables transcendantes sont
reprises avec leur provenance de run-013, sans nouvel arrondi. Voir
[l'étude et les limites](../docs/LLL_ET_FAMILLE_ELARGIE.md).

## H08 — Dimensions 3/5 et CBD(2)/CBD(3), run-015

`lll_dimensions.py` généralise LLL rationnel dans un nouveau module.
`higher_cbd.py` construit les lois jointes exactes et tous les scores avec
NumPy 2.3.5. `run_higher_cbd.py --output <nouveau-dossier>` exécute le
protocole ; les lois ne reposent ni sur une simulation ni sur une énumération
littérale des 2^54 configurations de bits. Les masses entières sont contrôlées
pour rester dans le domaine int64. Les 192 calibrations de contrôle sont
comparées aux probabilités exactes de H07.

Utiliser `.tools/research-venv/Scripts/python.exe` sous Windows et
`.tools/research-venv/bin/python` sous Linux. Le verrouillage dédié est
`requirements-cbd-dimensions.txt` ; le setup local existant fournit déjà
la même version de NumPy. `check` utilise maintenant ce Python pour les
tests de recherche et les deux nouveaux vérificateurs, avec un message
de setup si le runtime manque.

`verify_higher_cbd_results.py` rejoue toutes les lois et banques.
`verify_higher_cbd_independent.py` ne charge aucune arithmétique du projet :
il retrouve les lois par couches de bits et tous les scores par une
construction différente. Les tableaux sont liés par empreinte avec forme,
type et ordre d'octets explicites, et restent reconstructibles. Voir
[l'étude](../docs/CBD_ET_DIMENSIONS_SUPERIEURES.md).
