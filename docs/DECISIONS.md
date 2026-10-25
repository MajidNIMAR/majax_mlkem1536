# Décisions de mise en place

## Emplacement du projet

Le dossier `Codex\NIST` est la racine unique du projet. Le cahier des charges initial reste à cet emplacement. Git est initialisé localement ; aucune publication ni connexion à un dépôt distant n’a été effectuée.

## Langage et outils

Le socle utilise Rust 1.91.1, avec rustfmt et Clippy, et un espace de travail Cargo. Sous Windows, la chaîne GNU est installée sous `.tools/` pour disposer des outils de liaison sans installation globale de Visual Studio. Les scripts utilisent leurs propres emplacements Cargo et Rustup et ne modifient pas le PATH enregistré dans Windows.

Les dépendances de `kem1536` servent à la lecture du profil TOML. Le composant séparé `kem1024-reference` utilise RustCrypto pour le témoin standardisé ; aucune primitive cryptographique du candidat de rang 6 n’est encore implémentée.

Python, déjà présent sur la machine, est utilisé sans paquet additionnel pour une vérification indépendante des calculs de dimensions et de tailles.

## Identité du profil

`KEM1536-EXP-P0`, version 0.1, identifie exactement les paramètres inscrits dans le cahier des charges. Le programme refuse un changement silencieux de rang, de bruit, de compression ou de tailles sous cette identité.

La commande `self-check` vérifie uniquement la configuration publique. La commande `status` indique séparément l’absence des trois opérations du KEM. Une commande cryptographique non disponible doit échouer.

## Validation des environnements

La préparation est exécutée et vérifiée sur le PC Windows local. Les scripts Linux et le workflow Windows/Ubuntu sont préparés pour une validation ultérieure. Ils ne constituent pas encore une preuve d’exécution sous Ubuntu ou sur GitHub.

## Références figées et témoin 1024

J0 conserve le PDF FIPS 203 du 13 août 2024 et le fichier d’errata examiné avec leurs empreintes SHA-256. Les deux corrections recensées clarifient des commentaires et l’indexation ; leur traitement est enregistré dans `ERRATA_FIPS203.md`. Le contrat initial du candidat est décrit dans `CONTRAT_ALGORITHMIQUE.md`.

J1 retient RustCrypto `ml-kem 0.3.3`, checksum du paquet vérifié contre le manifeste et `Cargo.lock`. Le backend est utilisé sans modification, avec effacement des secrets activé. Le format développé, déprécié dans cette version de la bibliothèque, est réservé au harnais afin de comparer les clés des vecteurs FIPS 203. Les fonctions déterministes sont confinées aux données publiques de test.

Les jeux ACVP sont copiés au commit `975de31eb83d87039ec88934fdc47d8c312b892d`. Le témoin sélectionne tous les cas ML-KEM-1024 des trois jeux importés, sans supprimer les autres paramètres des fichiers originaux. Les deux révisions encapDecap restent distinguées dans les rapports ; leurs comptes ne représentent pas deux implémentations indépendantes.

Les contrôles comprennent les sorties de génération, les chiffrés et secrets d’encapsulation, les secrets de décapsulation, le rejet implicite et l’import des clés. Un calcul Python indépendant identifie les sorties de remplacement. Les sources sont contrôlées avant les vérifications ordinaires et leurs fins de ligne sont préservées par Git.

L’intégration de l’aléa Windows a nécessité l’outil d’import LLVM fourni par la chaîne locale. Le démarrage et les scripts incluent maintenant cette préparation de façon reproductible.

Le fait que le témoin passe les vecteurs retenus ne fournit aucune évaluation de sécurité du candidat 1536.

## J2 — Correction et premier modèle d’attaque

Le 24 octobre 2026, les calculs conservés dans `results/j2/run-001/` donnent une borne d’union d’échec d’environ 2^-118,44 pour P0 sous le modèle indépendant documenté. Même l’événement sur un seul coefficient dépasse le seuil C05. Le profil est conservé sans changement comme résultat négatif et n’est pas gelé pour implémentation.

Les scénarios de compression à q=3329 ne résolvent pas le problème étudié. Une piste q=7681 avec η1=η2=3 donne environ 2^-227,53 et une première comparaison historique primal/dual favorable face au témoin. Cette piste n’est pas un nouveau profil sélectionné. Les encodages à 13 bits, l’échantillonnage et la NTT demandent une nouvelle spécification.

L’arithmétique des probabilités est exacte dans un modèle dont les hypothèses restent explicites. Les coûts d’attaque sont heuristiques et limités au Core-SVP historique. Les modèles modernes, hybrides et attaques exploitant les échecs restent nécessaires avant la clôture de J2.

Le rapport courant et le journal conservent les méthodes, les limites et les décisions pour le futur article. Les instantanés ne sont pas écrasés par les exécutions ordinaires. Le cache des outils externes n’est pas redistribué faute de licence explicite repérée ; ses fichiers sont récupérés au commit et aux empreintes du manifeste de recherche.

## J2 — Actualisation des attaques au 24 octobre 2026

Le panneau moderne sous Sage est exécuté et conservé dans `run-002` : 120 évaluations, 118 coûts retournés, deux erreurs BKW de P0 explicites. Les huit exports repris conservent leur première tentative. Les modèles classique MATZOV et de sensibilité BCSS23 sont séparés. Les diagnostics de rotations sur CBD denses ne sont pas intégrés aux minima du panneau communautaire.

La revue signale les résultats récents sur les codes, rotations, corrélations du bruit, scores duaux et oracles d'échec. Un outil à jour ne couvre pas automatiquement tous ces travaux. Le choix q=7681/η=3 reste une piste ; la première version de Kyber utilisant déjà q=7681 est citée comme antécédent. Aucun niveau global ni nouveau profil n'est validé par ce jalon intermédiaire.

L'environnement Sage dédié utilise un stockage temporaire Linux sous `.tools/`, avec archives persistantes et versions verrouillées. Le Python système reste inchangé. Les vérificateurs ordinaires contrôlent les résultats sans télécharger Sage. La procédure Rust complète sur Linux et le workflow GitHub restent à exécuter.

## J2 — Priorité au diagnostic de décapsulation

À la demande de l'utilisateur, terminer la faisabilité avant le choix final des paramètres. `run-003` approfondit le rejet de P0 sans modifier son profil : suppression séparée des erreurs u/v, variance intrinsèque et bornes d'échec sans indépendance de l'arrondi final v. Le rejet subsiste sous les hypothèses restantes CBD/δu. Ce diagnostic ne constitue ni une sélection de q=7681 ni une clôture de J2. Les lois de bruit des scénarios de réparation et leur résistance aux attaques restent à justifier ensemble. Voir `DIAGNOSTIC_DECAPSULATION_P0.md`.

## J2 — Témoin de correction sans arrondi u

`run-004` établit, dans le modèle CBD indépendant, un témoin de correction à q=7681,η1=η2=3,u exact,dv=5. Le calcul de queues et le certificat Chernoff rationnel satisfont C05 sans indépendance des arrondis ni uniformité de A pour cette correction. Le coût de format est un chiffré théorique de 2656 octets. Le scénario compact précédent n'est pas abandonné ni remplacé silencieusement. Aucun profil n'est choisi : compléter les attaques et les critères de faisabilité avant la sélection finale. Les limites concernant SHAKE fixé, les clés conditionnelles et les oracles restent explicites dans `DEPENDANCES_ARRONDI_U.md`.

## J2 — Hypothèses et précision mixte

Créer un registre des hypothèses et distinguer gains propres, contrôles et antécédents. H01 obtient un certificat exploratoire de 2581 octets dans `run-005`, avec seulement 11 octets de gain dus à u au-delà du contrôle de v. Sa faible marge dans la borne exclut une sélection automatique comme profil. Les configurations non certifiées restent disponibles sans être déclarées défaillantes. Le schéma reste public et fixe ; poursuivre la recherche et les comparaisons de sécurité avant tout gel. Aucune primauté mondiale n'est établie.

## J2 — Quantificateur décalé de H02

`run-006` conserve un gain de 14 octets sur H01, avec une borne de correction 2^-175,665600 dans le modèle CBD et un support joint prouvé par couverture finie. Le point de 2567 octets reste exploratoire à faible marge. Préserver les cas négatifs et le non-gain du critère local MGF. La présence de précisions par blocs dans le README Minal est enregistrée comme antécédent de H01. La construction, la preuve et l'implémentation future doivent rester distinguées ; compléter les critères de sécurité de J2 avant tout choix final.

## J2 — Comparer l'utilité à seuil de correction commun

run-007 conserve H01/H02 et le contrôle u exact à trois seuils communs. H02 gagne seulement neuf octets (0,347 %) à une exigence de borne ≤2^-200. Garder la variante pour la recherche, sans la sélectionner pour le moteur. Les trente évaluations de clé publique identiques sont réutilisées avec leurs limites ; aucun gain de résistance ni nouvelle estimation. L'audit du code dual avec rotations reste une inspection documentaire, sans coût nouveau. Terminer les distributions du chiffré, attaques et CCA avant de clore J2. Voir UTILITE_COMPRESSION.md.

## J2 — Adaptateur dual avec codes calibré

run-008 apporte six calibrations publiées, 1043 évaluations de sensibilité GV et quatre contre-vérifications numériques à haute précision. La borne de recherche beta=1000 est supprimée au profit de la dimension du réseau ; l'ancienne limite est conservée comme diagnostic. Le point exploré à environ 2^380 opérations sous l'heuristique MLWE n'est pas une sécurité globale : code GV idéal, score normal, extrapolation beta>1024, mémoire exponentielle et recherche locale bornée restent explicites. Ne pas changer les paramètres ni implémenter le moteur sur ce seul chiffre. Compléter décodeur, score/covariance, convergence, mémoire et CCA. La version e2104 possède déjà l'intégrale cohérente ; aucune correction originale revendiquée sur l'ancien appel nfft. Voir DUAL_CODES_ROTATIONS.md.

## Liberté de conception et méthodes non standardisées

Le 24 octobre 2026, l'utilisateur autorise explicitement l'étude et le développement de méthodes sans approbation préalable du NIST ou d'un autre organisme. Les choix standardisés sont des références de comparaison ; les nouveaux candidats peuvent modifier la construction avec des algorithmes et formats explicitement définis. A01 est précisé pour limiter l'obligation de partir de FIPS 203 au point de départ P0, et A02 distingue optimisation d'un profil inchangé et nouvelle variante. Les exigences de correction, de sécurité visée et de reproductibilité restent les objectifs du projet. Une hypothèse non validée peut être expérimentée, en conservant son statut et ses limites ; une validation externe future ne doit pas être présumée acquise. Aucun paramètre, résultat figé ou seuil de sélection n'est modifié par cette décision. J2 reste la priorité avant le moteur de rang 6.

## J2 — Recherche duale stabilisée dans un voisinage explicite

run-009 poursuit le modèle inchangé de run-008 : 1187 évaluations nouvelles et quatre points contrôlés sur les 32 voisins unitaires d'un ou deux axes, avec quatre contre-vérifications numériques. Le meilleur coût exploré MLWE au rang 6 descend à log2(coût)=378,984845. Cette baisse précise le coût d'attaque estimé ; aucun changement de paramètres ni gain de sécurité du KEM. La stabilité est locale, dans le domaine déclaré et à 10^-10 près ; aucun optimum global. La priorité suivante est le décodeur concret à q=7681 et l'analyse des scores, avant clôture de J2. Conserver les neuf instantanés et les résultats négatifs antérieurs. Voir STABILISATION_DUAL.md.

## J2 — Décodeurs auxiliaires concrets par blocs

run-010 apporte deux constructions de codes et des décodeurs exacts, huit expériences aux quatre dimensions de run-009, 2048 cibles synthétiques, six petits modèles exhaustifs et une vérification indépendante de 64 blocs réels. Le code pondéré atteint une norme moyenne de 1,177973 fois le rayon de référence à q=7681,140/21, avec environ 6,752 ms de décodage exact dans le prototype local. Conserver ce résultat positif face au contrôle répété ainsi que l'écart persistant au modèle idéal. La moyenne des normes et la durée mesurée ne remplacent pas l'analyse de score et le coût rop. Aucun coût d'attaque, profil ou objectif C05 modifié. Il s'agit du décodeur de l'analyse duale, pas de Decaps du KEM. Étudier ensuite les erreurs structurées, les scores et le compromis coût/distance. Voir DECODEUR_CONCRET.md.

## 24 octobre 2026 — Contribution CBD et dépendances du décodeur

Conserver `run-011` comme étude auxiliaire distincte des coûts de run-009.
Utiliser la fonction caractéristique CBD pour le biais d'un résidu fixé et
conserver les covariances quand les termes partagent le secret. La norme
euclidienne reste un contrôle, sans supposer qu'elle détermine seule ce biais.
La factorisation par blocs est justifiée pour des cibles à blocs uniformes
indépendants ; celle par coordonnées n'est pas retenue. Les petites banques
et les moyennes des 256 observations ne valident pas les queues d'une attaque
exponentielle. Aucun coût, seuil C05 ou profil n'est modifié. Le prochain test
pourra comparer un choix de mot par biais CBD au choix euclidien, à code et
budget comparables, avant l'intégration au score complet. Voir
[SCORES_DECODEUR.md](SCORES_DECODEUR.md).

## 24 octobre 2026 — H05, critère CBD avec encadrement

Le protocole H05 est préenregistré au commit 17f30d3, avant les mesures.
Conserver run-012, ses tables et ses trois provenances. Le critère entier
garantit un écart uniforme au meilleur biais CBD auxiliaire et les certificats
observés résolvent tous les minima des blocs testés. Le gain de biais moyen
sur les codes pondérés est limité, de 0,185 % à 0,667 % sur les cibles fixes.
Au point 140/21 : +0,428 % pour environ +24,85 % de temps local, certification
comprise. Conserver le critère CBD comme témoin et le contrôle euclidien ;
ne pas prioriser une optimisation supplémentaire de ce prototype sur la
seule base de ce gain. Passer au lien entre décodeur, vecteurs duaux et score
complet dans un modèle réduit vérifiable. Aucun paramètre du KEM, seuil C05
ou coût d'attaque modifié. Voir [l'analyse](DECODEUR_CRITERE_CBD.md).

## 24 octobre 2026 — H06, score complet et événements exacts

Conserver run-013 comme modèle LWE réduit, avec son protocole préenregistré,
ses histogrammes et ses trois provenances. Le score inclut bruit des
échantillons, partie du secret liée au réseau et résidu du code. Les rangs
et seuils sont certifiés ; les moments restent évalués numériquement et
confrontés à l'énumération. Séparer les faux candidats corrélés au vrai u
du témoin public uniforme, et la probabilité de classement du franchissement
d'un seuil fixe. Une meilleure moyenne du bon score ne garantit pas un
meilleur succès. Une bonne variance ne garantit pas une queue normale.

La suite porte sur la stabilité de ces constats dans une famille réduite
plus large, puis sur des vecteurs issus d'une réduction de réseau. Ne pas
appliquer un facteur correctif universel aux coûts de run-009 depuis ces
petits cas. Aucun profil, seuil C05, coût réel ou clôture J2 modifié.
Voir [SCORE_DUAL_COMPLET_REDUIT.md](SCORE_DUAL_COMPLET_REDUIT.md).

## 24 octobre 2026 — H07, LLL et famille étendue

Conserver run-014, ses certificats LLL exacts, les témoins de combinaisons
et toutes les configurations du protocole préenregistré. Les lois et tables
de scores reconstructibles sont liées par empreintes, sans dupliquer les
banques identiques. Les 768 panneaux ne sont pas des répétitions indépendantes.

La boîte [-2,2]^3 après LLL n'est pas un échantillonneur ni une énumération
exhaustive : elle manque certains préfixes à q=17, davantage à N=12. Le
critère CBD ne domine pas le critère euclidien sur le classement ; une
meilleure moyenne ne suffit pas. Garder l'euclidien comme contrôle et les
deux critères pour les études suivantes, sans sélectionner un profil.
La variance uniforme exacte ne justifie pas une queue normale, y compris
sur cette famille plus large. Poursuivre vers des dimensions de réseau et
des distributions CBD(2)/CBD(3) plus proches des scénarios réels, avec une
analyse propre de la génération de liste. Aucun coût antérieur, seuil C05,
paramètre du KEM ou clôture J2 modifié. Voir LLL_ET_FAMILLE_ELARGIE.md.

## 25 octobre 2026 — H08, lois entières et distributions η=2/3

Conserver run-015 et ses deux provenances. La récurrence sur le groupe
des observations remplace l'énumération littérale devenue impossible :
elle calcule exactement les lois entières jusqu'à 2^54, avec contrôle de
masse et de budget int64. Une seconde méthode procède par couches Bernoulli.
Les probabilités restent exactes ; les moments et DFT sont numériques.

Les tests et vérificateurs de recherche utilisent maintenant le runtime
local NumPy 2.3.5 déjà installé, verrouillé par un fichier dédié, sans
installation globale. Les scripts Windows/Linux signalent le setup local
nécessaire si ce runtime est absent.

Le critère CBD ne domine pas l'euclidien sur le classement, y compris avec
CBD(2)/CBD(3). L'accord des listes après LLL en dimension 5 ne démontre
pas une génération de vecteurs équivalente aux grandes listes de l'estimateur.
Priorité suivante : préciser le transfert des contrôles de score vers
q=7681 et les hypothèses encore nécessaires, avant révision de coûts.
Aucun seuil C05, paramètre du KEM, niveau global ou clôture J2 modifié.
Voir CBD_ET_DIMENSIONS_SUPERIEURES.md.
