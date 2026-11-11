# M08 — Imports de clés et validation élargie

11 novembre 2026. **Moteur, mesures, revue ciblée, campagne prolongée, couverture LLVM, oracle et deux paquets de livraison vérifiés. L'archive complète et le contrôle local Windows passent ; la publication avec CI neuve est en préparation.**

Le profil reste `KEM1536-DEV-Q7681-R1`. Le cœur mesuré a pour SHA-256 `b39c2fdfcdd7c22634162a2c451213a6c4309b27524a82069f37903653e12334`. Le [protocole](PROTOCOLE_M08_IMPORTS.md), les seuils et le plan ont été committés au `7ad5698` avant référence et candidat.

## Modification du moteur

Le validateur ne construit plus de polynôme et ne réduit plus les valeurs. Chaque groupe de 13 octets contient huit coefficients sur 13 bits. Si `X` est le groupe lu en petit-boutiste, le coefficient j est `(X >> (13*j)) & 8191`. Les huit assemblages explicites utilisent des champs disjoints, puis accumulent leur masque de non-canonicalité. Pour une valeur dans 0..8191, la soustraction u32 avec enroulement suivie du bit de signe distingue exactement `v < 7681`. Le vecteur complet contient 192 groupes, soit 1536 coefficients. La décision source vient après le balayage.

Les paramètres, domaines, formats, déchiffrement et comptes NTT 48/55/68 sont inchangés. Le lien certificat/programme reconnaît 36 ancrages M08 et conserve les réalisations historiques, sans vérification formelle complète du compilateur.

## Compatibilité et mesures

Le test Rust examine les 8192 valeurs du prédicat et 6144 sondes de frontière réparties sur toutes les positions. Les quatre consommateurs référence/candidat Windows/Linux réussissent chacun 88576 sondes mono-coefficient, avec fixtures structurelles identiques. Cela n'énumère pas l'espace de tous les vecteurs. Les smokes distincts utilisent de vraies clés fraîches importées, un échange et un rejet.

Les deux binaires de recherche candidats retrouvent intégralement les 1000 vecteurs, 10000 rejets, 10000 mutations et 20000 formats par hôte. Les sorties étaient antérieurement confrontées indépendamment ; ce rejeu n'est pas une nouvelle simulation d'échec rare.

Le panneau mémoire contient 2880 observations : 18 cas × deux motifs ×20 répétitions ×deux versions ×deux hôtes. Le panneau de temps contient 300000 observations : 80000 KEM et 220000 imports, cinq séries alternées, 1000 observations par opération/version/série/hôte, 100 échauffements hors panel, CPU10. Validation/drop hors chronomètre ; aucune observation extrême supprimée.

Les 210 contrôles des budgets passent. Le tableau rapporte les médianes d'import, en microsecondes ; les facteurs sont descriptifs de ces binaires et de cet hôte.

| Hôte | Import | M07, µs | M08, µs | M07/M08 |
|---|---|---:|---:|---:|
| windows | Public valide | 18.900 | 1.400 | 13.50 |
| windows | Privé valide | 46.200 | 11.200 | 4.12 |
| windows | Secret invalide premier | 18.500 | 1.100 | 16.82 |
| windows | Secret invalide dernier | 18.500 | 1.100 | 16.82 |
| linux | Public valide | 19.119 | 1.240 | 15.42 |
| linux | Privé valide | 47.122 | 10.936 | 4.31 |
| linux | Secret invalide premier | 18.922 | 1.040 | 18.19 |
| linux | Secret invalide dernier | 18.920 | 1.040 | 18.19 |

Les médianes des quatre opérations principales restent proches de la référence : rapports M08/M07 Windows 1,0012/1,0041/0,9973/1,0110 et Linux 0,9944/0,9977/0,9970/1,0038 (KeyGen/Encaps/Decaps valide/rejetée). Les résultats défavorables sont conservés, sans affirmation de significativité.

Les maxima de pile touchée Encaps/Decaps restent 7672/13064 octets sous Windows et 7400/12696 sous Linux. Les imports privés valides restent dominés par d'autres appels (1144/952 octets). Pour les erreurs secrètes, zéro signifie aucune modification détectée dans la zone peinte ; les 512 octets supérieurs ne sont pas peints et les motifs peuvent coïncider avec les écritures. Ce zéro ne prouve ni absence de pile ni effacement. Les demandes de tas n'augmentent pas.

Deux flux conservent un avertissement du lanceur WSL concernant la session systemd de l'utilisateur : candidate/linux/memory.stderr et paired-latency/linux/baseline-0.stderr. Sortie0, grilles complètes et hashes validés ; le vérificateur classe ce texte exact comme diagnostic d'infrastructure, sans supprimer ses octets. Tout diagnostic inconnu/panic reste rejeté.

Une amélioration du contrôleur, avant les acquisitions appariées, conserve désormais chaque tentative (commande, horodatages, code et hashes) avant analyse et vérifie les statuts d'import. Les captures gardent ses deux versions. Les entrées Rust/instruments sont identiques entre versions, sauf dev_kem.rs ; les seuils/plans/protocole restent identiques. Le helper d'affinité inchangé est lié au blob Git préenregistré ; cela ne constitue pas une attestation d'affinité par l'OS.

Le diagnostic temporel distinct contient 32000 observations, huit clés/cinq classes, sans exclusion. Aucun contraste ne dépasse |t|=4,5 : max 1,843 Windows et 1,602 Linux. Il ne démontre pas le temps constant.

## Revue machine ciblée et suites

La collecte des quatre consommateurs conserve les symboles par adresse, les références et les retours d'erreur. La revue scellée qualifie une boucle SIMD fixe de 12 tours, 208 octets par tour, avec décision après balayage. Aucune écriture dérivée des coefficients n'est observée dans la nouvelle boucle Linux ; les sauvegardes des XMM entrants Windows précèdent la première lecture d'entrée. La revue conserve 51 membres vérifiés et 124 témoins adressés. Les appelants gardent longueur → secret → public intégré → hash ; l'erreur secrète construit son tag/code puis retourne sans appel supplémentaire. Les copies ciblées de bits décodés ne sont plus produites en pile dans ces consommateurs. Les registres, la pile préexistante et les zones ABI du demandeur ne sont pas assimilés à un effacement universel.

Les CLI de recherche et de livraison candidats ont de nouveaux listings complets, un inventaire historique indexé par noms et un index physique conservant les noms dupliqués. Ces inventaires ne sont pas une nouvelle preuve d'effacement PKE et ne reprennent pas tacitement les conclusions par empreinte M07.

## Campagne principale : budgets atteints, posttraitements en cours

La campagne longue est lancée après acceptation explicite : 1800 secondes CPU
nouvelles par harnais, quatre workers. LONG_CAMPAIGN_ACCEPTED.json lie le
manifeste, le plan, le marqueur quantitatif et la revue scellée, avant la
configuration de campagne ; le wrapper du contrôleur racine vérifie ce
raccord. Le script fuzzer impose lui-même le marqueur quantitatif, pas ce
contrôle de lancement supplémentaire.

Les quatre harnais atteignent leurs budgets, avec sorties normales et aucun
défaut observé. Le reçu principal conserve 7256,67 secondes CPU nouvelles
et 30 segments ASan avec std reconstruite ; aucune durée historique n'est
créditée. Les compteurs après INITED sont recalculés depuis les logs :

| Harnais | CPU nouvelles, s | Segments | Exécutions après INITED | Corpus récolté, entrées distinctes dans ce harnais |
|---|---:|---:|---:|---:|
| import_public | 1801,59 | 10 | 29470724 | 771 |
| import_private | 1802,90 | 7 | 1930870 | 723 |
| decapsulate | 1809,01 | 7 | 353097 | 660 |
| api_sequence | 1843,17 | 6 | 24371 | 864 |

Les 31779062 exécutions après initialisation incluent des répétitions et ne
sont pas un nombre de nouvelles entrées uniques. Les quatre corpus récoltés
sont dédupliqués séparément ; leur taille ne mesure pas la couverture source.
La demande libFuzzer `max_total_time=600` ne constitue pas un plafond strict
de durée murale : le maximum conservé est de 603,72 secondes par segment.
Les mesures de ressources réellement enregistrées restent les données de référence.

Le reçu de la campagne principale conserve `source_line_coverage_measured=false`
et `independent_oracle_replayed=false` : ces opérations sont des étapes distinctes.
Les exports LLVM acquis sont décrits ci-dessous. La comparaison indépendante
du corpus, la livraison et la clôture du jalon M08 ne sont pas déduites des
seuls budgets de la campagne principale.

## Couverture LLVM sur quatre objets distincts

Les quatre objets de couverture et leurs exports complets sont conservés dans
`m08-fuzz-001/postprocessing`. L'union provient d'une fusion LLVM des quatre
profils et d'un export multiobjet. Les comptes des panneaux qui se chevauchent
ne sont pas additionnés. La source statique reste liée à la configuration
figée de campagne ; les fichiers générés par l'instrumentation sont recensés
séparément dans `coverage-worktree.json`.

Ces objets sont distincts des binaires de la campagne principale ASan/std
reconstruite. La couverture utilise la std distribuée, non reconstruite :
cargo-fuzz 0.13.1 refuse la combinaison couverture et `--build-std`.
Les fractions ci-dessous comptent les éléments couverts parmi les éléments
instrumentés selon LLVM, sur les cinq fichiers retenus, y compris ceux à zéro.

| Fichier | Lignes | Fonctions | Régions | Branches LLVM |
|---|---:|---:|---:|---:|
| dev_kem.rs | 333/362 | 45/46 | 656/706 | 13/18 |
| engine_poly.rs | 90/120 | 14/17 | 154/189 | 4/4 |
| lib.rs | 0/61 | 0/7 | 0/78 | 0/14 |
| reference_ring.rs | 0/46 | 0/10 | 0/68 | 0/0 |
| secret_box.rs | 15/15 | 5/5 | 17/17 | 0/0 |
| **Union des cinq fichiers** | **438/604** | **64/85** | **827/1058** | **17/36** |

Un compte 0/0 signifie qu'aucune branche n'est instrumentée dans cette
catégorie, sans pourcentage de réussite à en déduire. Les 101 mappings de
fonctions LLVM, dont 25 de compte nul, distinguent notamment des instanciations
génériques ; ils ne sont pas le dénominateur des 85 fonctions du résumé.
Les listes complètes de fonctions et régions/branches non parcourues restent
dans `coverage-summary.json` et les exports complets conservés. Quelques
angles morts représentatifs sont explicités :

- Les fonctions de profil dans `lib.rs` et l'anneau de référence générique
  restent à zéro dans ces objets. Le cœur KEM n'appelle pas ces interfaces
  pendant ce parcours ; leurs zéros sont conservés dans le total.
- `public_power`, `public_powers` et `stage_roots` construisent les tables
  NTT constantes à la compilation ; leurs compteurs d'exécution sont nuls.
  `run_diagnostics` n'est pas appelé par ces harnais.
- Les chemins d'échec de l'aléa OS et leur propagation ne sont pas forcés.
  La branche d'erreur de longueur du validateur interne n'est pas exercée
  ici : ses appelants lui fournissent déjà un vecteur de longueur fixe.
- Quatre mappings spécialisés `SecretBox::wipe`/`Drop` restent à zéro,
  malgré les 5/5 fonctions agrégées de `secret_box.rs`. Une fonction agrégée
  couverte ne garantit pas que toutes ses instanciations le soient.

Cette couverture mesure les passages enregistrés pour ces objets et ce corpus.
Elle ne prouve ni tous les chemins possibles, ni le temps constant ou
l'effacement global. Les compteurs d'arêtes libFuzzer de la campagne principale
restent une métrique distincte de cette couverture source LLVM.

## Rejeu indépendant et reprise après interruption

Le passage complet compare 3156 requêtes déterministes distinctes : toutes
les sorties Rust/Python concordent. Ce nombre compte les requêtes décodées
du corpus, pas des fichiers uniques globaux ni les exécutions du fuzzer.
Le reçu conserve 433 requêtes d'import privé acceptées accompagnées d'une
sonde indépendante de décapsulation, ainsi que 16 acceptations de
réencapsulation par l'oracle. Les 1022 opérations à aléa frais encodées dans
le corpus ne sont pas recréées par l'oracle Python ; elles restent distinctes
des comparaisons déterministes ci-dessus. Le rejeu emploie le binaire Rust
Linux déjà construit et l'oracle Python figé, exécuté sous Windows.

Une interruption d'environnement est consignée pendant la première tentative
de comparaison. La session outil disparaît, l'heure UTC passe approximativement
de 04:30 à 10:18 et un redémarrage WSL est constaté, sans processus original
d'oracle ou de contrôleur restant. Le code de sortie de ce premier processus
est inconnu. Ces observations ne déterminent pas la cause de l'interruption.
Les trois traces incomplètes sont conservées avec leurs empreintes sous
`postprocessing/interrupted-oracle-001` : transcript compressé, journal et stderr.

L'adaptateur de reprise maintenu au commit `99ce3a5` conserve sa requête,
son code et ses empreintes. Il relance uniquement la partie oracle au moyen
du contrôleur original figé et du binaire existant ; aucune compilation,
campagne fuzz ou couverture LLVM n'est relancée. Le passage complet termine
normalement, code 0. `recovery.json` lie sa requête, l'adaptateur, le journal
et le reçu oracle. La vérification du posttraitement original et celle de
l'adaptateur passent ; `postprocess.json` rattache le résultat à la reprise,
aux exports et à la source de campagne conservée.

Cette concordance de sorties et ces sondes finies ne prouvent pas la sécurité
globale des clés adverses, le temps constant ou l'effacement de toutes les
copies. La distribution et le gel complet restent des étapes séparées.

## Volet C01 borné

Le [résultat conditionnel sur information latérale classique](REJET_ET_INFORMATION_LATERALE_M08.md) est figé dans `results/security/m08-rejection-001` : dix panneaux rationnels, cas D=0 et contrôles finis. Pour p majorant la probabilité de deviner Z après E, les bornes sont min(1,qp) en ROM et min(1,2q√p) en QROM lorsque D>0 ; elles valent zéro lorsque D=0. D compte les accès classiques à la fonction indexée, même en QROM ; q compte les portes de requête publiques pouvant viser J. La vue idéale doit être indépendante de Z conditionnellement à E, et E reste classique. Le cas p=2^-256 retrouve M06 sans resserrer sa borne quantique. Ce résultat ne certifie ni l'entropie des clés importées, ni SHAKE concret ou le KEM global. C01 reste ouvert.

## Pièces acquises du bilan intermédiaire

Les reçus locaux permettent de vérifier les faits ci-dessus avant le gel
complet du moteur. Les quatre inventaires CLI et les quatre images de
consommateurs sont distincts. Leurs vérificateurs relisent les pièces
conservées sans nouveau désassemblage. Le volet C01 est déjà un instantané
figé indépendant ; les autres pièces restent dans l'atelier `artifacts/generated`.

| Pièce | Reçu | SHA-256 du reçu |
|---|---|---|
| 210 budgets satisfaits, panneau quantitatif valide | `m08-001/measurements-evaluation.json` | `a4465d88e43457cab980cc73b6818c36f328f3104eda9eb7d0a235fdfb305141` |
| Revue ciblée scellée, 51 membres et quatre consommateurs | `m08-import-review-001/provenance.json` | `2ea7181d49927316bba117a29fb5a6a0af0b04a8d550155606c84292944f1dad` |
| Quatre inventaires CLI candidats | `m08-cli-inventory-001/provenance.json` | `eca24e5694d61caa4d47222d755407e744c3d28a25645729e1be3ea050d180f6` |
| Campagne principale, quatre budgets atteints | `m08-fuzz-001/fuzz-summary.json` | `b51f270f1069e2f8de0e7c844cdda233c5804148a369b32f81d475b39c53e568` |
| Vérification principale et corpus récolté par harnais | `m08-fuzz-001/verification.json` | `03a62a6eb8ef75e6888936d46cdfe47fddf3f59709c2ab92962ea93e5b1bef91` |
| Quatre exports LLVM et union des cinq fichiers | `m08-fuzz-001/postprocessing/coverage-summary.json` | `f18694723af58e0946833fb94891b014d08431702d3217bf4b679bccb8d15d9b` |
| Rejeu indépendant complet, toutes sorties déterministes égales | `m08-fuzz-001/oracle-replay.json` | `73fa8e6331581486b3d697063ca877a06051ecf8816e73f4e59613a820f913a4` |
| Reprise oracle terminée normalement, traces initiales conservées | `m08-fuzz-001/postprocessing/recovery.json` | `608484137ab343693708ac3761273bfdef9c3a451269c1b940c2850eede5b7c5` |
| Rejet idéal avec E classique, sept membres et provenance | `results/security/m08-rejection-001/provenance.json` | `229ac35d96164f082612859eb98e1d0f475f28fb1ba90f1cce642ff3843c21c1` |

## Distribution acquise

Le contrôleur de livraison termine avec code 0 et vérifie deux paquets. Deux
constructions CLI nouvelles, une par hôte, utilisent les mêmes sources
capturées, recettes et caches d'outils ; cela ne constitue pas une reproduction
par un tiers. Linux retrouve les octets bruts de l'original. Windows diffère
seulement dans le timestamp COFF et la somme de contrôle PE, masqués dans des
copies de comparaison. Aucun original n'est réécrit ; les paquets livrent les
premières images inventoriées, accompagnées des sources et licences.

| Paquet | SHA-256 |
|---|---|
| `majax-r6-m08-x86_64-pc-windows-gnu.zip` | `6df750dc709ac42aa429add50e863bac17e84f747e03f134316e24f4ee54d994` |
| `majax-r6-m08-x86_64-unknown-linux-gnu.tar.gz` | `420fe8f480e1ee29cc7b0c01ffbbc4da2acce3697787490582e0f8b1ebfeaf4e` |

Les originaux et répétitions réussissent chacun 16 échanges frais, 16 rejets
et les cinq refus normaux de commandes de recherche (code 1). Le résultat
de livraison `m08-delivery-001/result.json` a pour empreinte
`5c1014e7401947af8860bc88007a9b6b28a1e0c21b1fa2806e92ec78d4637fc4`.
Le paquet source conserve l'étude à l'acquisition, avant ces résultats de
livraison (SHA `eb17ae8d31d2bdf8cbecf4fa463bbe404600801c89478fcad15a1a40ea38625d`).
La présente version du dépôt porte le bilan ultérieur ; aucun paquet déjà
qualifié n'est modifié pour lui ajouter sa propre conclusion.

Les neuf images diagnostiques ont une collecte de notices distincte : 123
textes, graphes fuzz/coverage et rejeu séparés, 55 packages dans leur union
dont 52 tiers. Ce sont des graphes résolus avec fonctionnalités, pas une
attribution de symboles liés. Aucun ancien bundle ni nouvelle compilation
n'est utilisé pour cette collecte. Son reçu a pour empreinte
`ab1279f89e3ab60eb13052143ab7ff66226e9a754b02fddf52106bc5a9af0698`.

## Conservation complète

L'[archive M08](../results/engine/m08-001/) est figée et son rejeu complet
depuis extraction termine avec code 0, sans diagnostic stderr. Ses 17 fichiers
physiques conservent 7520 fichiers et 428 répertoires des six étapes et des
32 contrôles Python. Le plus gros fichier comprimé mesure 86730786 octets,
en dessous du seuil de découpage de 90 Mio. Aucune entrée brute n'est omise.

Le manifeste `provenance.json` a pour SHA-256
`02cc3515cfe6740ccc66e6f8c36f8183ec922607f156cc12a131fb3bc6c79385` ; le
résumé rejoué `summary.json` vaut
`5b533fcde1d103323d00ed53af312d66a2d3e129d5612006bdaec1aa3d3bed8f`.
Le contrôle `python -B research/archive_m08.py verify --output results/engine/m08-001`
relit les données et transcripts, sans relancer Git, compilation, binaire,
désassemblage, benchmark, fuzzer ou oracle. Les trois traces interrompues,
les reçus de reprise et leurs contrôles sont conservés.

## Intégration locale Windows

Le [reçu local](../results/engine/m08-verification-001/) conserve le check
complet `scripts/dev.ps1 check`, terminé avec code 0 : tests Rust, fmt,
Clippy strict, 352 tests Python suivis de OK et tous les rejeux requis.
Les 2008 fichiers maintenus présentent les mêmes empreintes avant/après,
de même que les outils. Ces deux observations ne sont pas une attestation
continue de l'hôte. Le check dure 904,33 secondes ; ses journaux intégraux et
le rejeu séparé de ses reçus sont conservés.

Le smoke natif de l'archive exécute l'original CLI et le consommateur API
par défaut sous Windows : 16 échanges et 16 rejets CLI, cinq commandes de
recherche refusées normalement, un échange frais avec clés importées, un
rejet et 88576 sondes du consommateur. Il ne recompile ni ne mesure de
nouvelles performances. L'exécutable habituel `target/release/kem1536.exe`
est ensuite remplacé atomiquement par l'original M08, SHA
`d3fb7537face2cd4b7e295ec829b6a282a711d005f4535ff99dddce90a98dde1`,
puis vérifié par 16 nouveaux échanges et 16 rejets sans afficher de clé.
Les 22 fichiers du reçu local conservent ces étapes et les journaux de gel.

La CI sur hôtes neufs reste une étape distincte. La durée principale ne
devient ni couverture exhaustive ni preuve globale.
