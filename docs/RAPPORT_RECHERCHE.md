# Rapport de recherche — MLKEM-1536 Core, KEM à six blocs de 256 coefficients

**20 novembre 2026 — premier cycle du programme de fermeture C01 en cinq
blocs.** Quatre dossiers d'analyse distincts et une porte d'intégration
ont été constitués et scellés localement :
`c01-next-challenge-001`, `c01-next-decaps-001`,
`c01-next-correction-001`, `c01-next-quant-001` et
`c01-next-integration-001` sous `artifacts/retained/`. Le lecteur final
rejoue onze commandes de vérification et de scellement, contrôle leur
source R1 commune et enregistre `C01_CONCRETE_OPEN`. Les contre-lectures
internes sont limitées aux énoncés examinés ; aucune revue extérieure
n'est acquise. Ces dossiers restent hors du dépôt public.

| Bloc | Résultat de ce cycle | Porte restant à franchir |
|---|---|---|
| Clé du défi passive | Décomposition exacte du jeu R1 fixé ; les seules marginales de ses sorties ne justifient pas les termes de corrélation. | Borner ces termes pour la construction réelle, avec des hypothèses indépendantes, ou revoir la construction. |
| Décapsulation adaptative | Une route précise d'extraction externe à partir de la vue publique est écartée dans sa portée. | Établir une autre simulation ou réduction efficace, aux ressources et erreurs entièrement comptées. |
| Correction du programme fixé | Le transfert par proximité statistique globale avec le bruit indépendant est écarté ; les marginales seules ne contrôlent pas l'événement étudié. | Prouver une propriété jointe ciblée sur la correction réelle, ou adapter la construction. |
| Résistance quantitative | Calcul rationnel exact des exigences de deux avantages Module-LWE dans le théorème classique idéal antérieur ; archives de coûts recontrôlées. | Acquérir une analyse native aux ressources après réduction et justifier les hypothèses d'avantage ; traiter séparément fonctions fixées et quantum. |
| Composition C01 | Les quatre entrées sont rejouées et les obligations ouvertes consignées. | Fournir une chaîne non circulaire complète, la contre-lecture indépendante et la qualification du programme exact. |

Le calcul quantitatif utilise des plafonds **illustratifs**. Pour huit
plafonds `2^32`, l'expression résiduelle conservatrice du modèle classique
idéal est proche de `2^-189,642`. Cette **majoration choisie** ne peut pas
certifier une cible illustrative `2^-192`, même avec des avantages
Module-LWE nuls ; elle ne constitue ni une attaque, ni une borne inférieure
sur la sécurité réelle. Le cahier C01 initial ne fixe pas cette cible,
et le point de contrôle RC1/QROM relève d'un autre modèle. Les anciennes
estimations d'attaques ne donnent pas de borne supérieure sur les deux
avantages natifs au budget composé. Aucune nouvelle campagne native
d'attaques n'est créditée dans ce cycle.

**Décision :** les cinq blocs ne sont pas fermés. Trois raccourcis de
preuve sélectionnés ont été écartés avec une portée explicite ; les
nouveaux lemmes et calculs orientent la prochaine acquisition, mais ne
chiffrent pas l'avantage IND-CCA du R1 à SHA3/SHAKE fixés. Le chemin
prioritaire consiste à définir une propriété jointe propre au programme,
une autre route Decaps et une preuve de correction ciblée, puis à chiffrer
les ressources et hypothèses du théorème composé. Une construction
distincte reste une option si ce chemin n'aboutit pas. Le cœur Rust,
les paramètres, les formats et l'API sont inchangés. **R1 reste
expérimental ; C01 concret reste ouvert.**

**Point d'état du 20 novembre 2026 — lecture des jalons.** Les numéros `M`
désignent des chantiers, pas des versions du moteur ni des niveaux de sécurité.
M10 reste la référence du moteur Rust livré. M15 est le lot historique de
preuves arithmétiques rendu reproductible publiquement : son job CI relit
un commit source figé, d'où sa présence dans les vérifications actuelles.
M23 est le dernier chantier numéroté de qualification du moteur ; M28 est le
dernier chantier numéroté de recherche C01. Les blocs post-M28 et les
études C01 du 20 novembre sont plus récents, sans nouveau numéro `M`.
L'état scientifique reste : R1 fonctionnel et expérimental, argument
conditionnel dans ses modèles déclarés, **C01 concret ouvert**. Le dernier
[run CI vérifié avant ce point d'état](https://github.com/MajidNIMAR/mlkem-1536-core/actions/runs/44660698822)
a réussi les contrôles moteur Windows/Ubuntu et le rejeu M15 figé. Cela
n'attribue aucun niveau de sécurité au moteur.

**20 novembre 2026 — raccord structurel au R1 à fonctions fixées.** Pour
une clé honnête dont la génération s'est terminée, la source Rust réalise
exactement la règle « déchiffrer, dériver G, réencapsuler, comparer le
chiffré entier, puis choisir la clé ou le rejet ». Il en résulte qu'une
requête Decaps postérieure au défi, distincte du chiffré défi, ne peut
être acceptée avec le message de ce défi. Si `q_pre` requêtes ont précédé
le tirage uniforme du message défi, la rencontre d'un message décodé
est au plus `q_pre/2^256`. La coïncidence avec l'un des chiffrés déjà
soumis est au plus `q_pre/2^256 + epsilon_corr_fixed`, où
`epsilon_corr_fixed` est l'erreur de correction moyenne du **programme
fixé** ; aucune borne numérique de ce terme n'est établie ici.
La génération terminée a parcouru les 36 flots de matrice déterministes
réutilisés par le chiffrement, ce qui évite de conditionner après coup
sur la terminaison de requêtes choisies adaptativement. Le risque de
non-terminaison de la génération elle-même reste séparé.

Une seconde capsule compose le couplage conditionnel de Decaps déjà
étudié avec un jeu passif `CPA-F` du **R1 exact** : pour un extracteur
en ligne exécutable `E`, l'avantage CCA est au plus l'avantage CPA-F du
simulateur, plus une erreur `delta_0 + delta_1` facturée séparément dans
les deux mondes du défi. Chaque `delta` réunit un événement de correction
adaptative et un événement de chiffré accepté sans témoin vérifié ; les
coûts de `E`, des fonctions publiques et de la mémoire sont comptés
symboliquement, sans plafond concret acquis.
Cette formule n'est **pas** une borne de sécurité : ni l'avantage CPA-F,
ni l'existence d'un extracteur efficace avec petites erreurs, ni la
correction adaptative sous SHA3/SHAKE fixés ne sont établis. Elle précise
les trois travaux mathématiques à mener, sans emprunter un transfert
générique des oracles idéaux. Les dossiers locaux scellés sont
`artifacts/retained/c01-fixed-structural-001/` et
`c01-fixed-cca-decomposition-001/`. Leurs vérificateurs et deux
contre-lectures internes passent dans la portée source et classique
déclarée. L'équivalence de toutes les images binaires avec cette règle
source reste à qualifier. **C01 concret reste ouvert ; R1 demeure expérimental.**
Le moteur, ses paramètres et ses formats sont inchangés.

**20 novembre 2026 — saut de clé dans le jeu complet classique idéal et
fonctions fixées.** Une nouvelle réduction traite ensemble le défi et la
décapsulation adaptative du R1 exact dans un jeu à six oracles aléatoires
indépendants, typés et consultés classiquement. Elle simule les réponses
Decaps à partir des consultations publiques de G, avec une erreur
explicitement bornée par la correction, la rencontre de graines déjà
touchées et la distribution exacte des 1 536 coefficients non comprimés de
la partie `u`. Une seconde réduction rattache le terme restant à deux
problèmes décisionnels Module-LWE aux dimensions `(6,6)` et `(7,6)`, avec
les coûts de préparation, de programmation des rôles et de requêtes
comptés. Les contre-lectures internes n'ont pas relevé d'objection
bloquante **dans ce modèle déclaré**. Les avantages Module-LWE au budget
composé ne disposent pas de borne supérieure démontrée par ce travail ;
le résidu arithmétique seul ne donne aucun niveau de sécurité du KEM.
Une composition séparée vérifie, sous huit plafonds illustratifs de
`2^32` requêtes ou graines chacun, un résidu **hors** avantages
Module-LWE `<2^-189`. Ce nombre ne borne pas l'avantage total. Un
corollaire à permutation aléatoire partagée est seulement conditionnel
à l'absence d'accès direct à la permutation et à un plafond global
supplémentaire sur les appels ; il ne concerne pas Keccak-f fixé.

Le passage à SHA3/SHAKE et Keccak-f **fixés** reste une obligation
distincte. Les six rôles et le lien entre la queue de G et les coins
d'encapsulation ont été contrôlés sur huit vecteurs synthétiques. Un banc
séparé a exécuté 464 parties du jeu à fonctions fixées, avec adversaire
dans un processus distinct, budgets et rejeu, ainsi qu'un contrôle sur
16 vecteurs Rust historiques. Ces contrôles confirment l'interface et
les traces dans leur périmètre fini ; ils ne bornent pas le meilleur
adversaire. Une substitution générale des fonctions publiques fixées par
des oracles aléatoires n'a pas de petit coût de distinction : une preuve
pour R1 fixé devra être propre à la construction ou changer de cadre.
Les dossiers détaillés et contre-lectures restent locaux sous
`artifacts/retained/c01-full-game-extract-002/`,
`c01-pke-ow-mlwe-001/`, `c01-fixed-function-scope-001/` et
`c01-fixed-game-harness-001/`, avec composition dans
`c01-classical-composition-001/`. **C01 concret demeure ouvert ; R1 reste
expérimental.** Le cœur, ses paramètres et ses formats n'ont pas changé.

**19 novembre 2026 — raccord multidébit classique, avec interfaces
distinctes.** Les [théorèmes 9 et 10 de Bertoni et al.](https://keccak.team/files/CSF-0.1.pdf)
permettent de comparer les six domaines idéalisés de R1 à une permutation
aléatoire partagée lorsque tous les appels pertinents ont un plafond
déterministe. Le méta-jeu peut exécuter lui-même KeyGen et Decaps avec la
clé secrète. En revanche, avec accès direct à la permutation et à son
inverse, le simulateur du monde idéal peut consulter une entrée de G
pertinente pour le défi. Le saut de tête exige alors un événement de
rencontre élargi ; sa probabilité après défi reste ouverte. Le coût de
comparaison de deux mondes est au plus `2Δ_IP(N)`, mais l'ajouter au
seul événement de consultation G adverse serait injustifié.

Un second raccord concerne **un jeu restreint sans accès direct à la
permutation**, avec une clé honnête, uniquement les encapsulations sous
cette clé effectivement surveillées et un plafond chemin par chemin
`N≤2^32` sur tous les appels. Le moniteur vérifie la correction des
chiffrés qu'il a réellement évalués, sans nouvelles consultations pour
des graines seulement latentes. La borne idéale `<2^-195` reçoit ici une
seule pénalité multidébit `Δ_IP(2^32)≤2^-193+2^-225` : le résultat est
**strictement inférieur à `2^-192`** pour l'événement de correction et de
cap retenu. Ce nombre n'est ni un niveau de résistance du KEM ni une
borne pour Keccak-f fixé. Les sorties XOF et les appels du moteur doivent
tous être comptés ; une exécution non plafonnée exigerait son propre
terme de dépassement. L'interface complète, le QROM et C01 concret
restent ouverts. Les capsules locales `c01-head-ip-transfer-001` et
`c01-sponge-correction-restricted-001` sont scellées et rejouées ; une
contre-lecture séparée a examiné le second raccord. Les modèles finis
et contrôles de portée vérifient les équations et les hypothèses de
transfert annoncées, pas la sécurité du moteur à fonctions fixées.
Le lecteur scellé `c01-ip-integration-001` rejoue ces résultats et le
reçu historique du pont multidébit sans modifier ses archives.

**19 novembre 2026 — correction adaptative dans un jeu idéal, portée de la
preuve A.** Une route d'extraction statistique sélectionnée a été confrontée
aux tailles exactes du message et de la clé du défi. Sa condition suffisante
d'entropie ne peut pas être satisfaite par le R1 inchangé ; cette conclusion
ne vaut que pour cette route et ne constitue ni attaque ni impossibilité
générale. La condition utilisée vient du
[lemme 2.3 de Peikert–Waters](https://sites.cc.gatech.edu/fac/cpeikert/pubs/lossy_tdf.pdf).
Une revue de sources primaires ne fournit pas non plus de théorème
transférable directement aux fonctions fixées du moteur. Les preuves,
lecteurs finis et contre-exemples de portée sont conservés localement.

Un saut A plus étroit a ensuite été établi et contre-lu dans le jeu
classique à oracles idéaux typés. Le remplacement de la tête du défi par
une valeur indépendante coûte la probabilité d'une évaluation adverse de
l'entrée G cible, plus au plus `q_pre_dec/2^256` si Decaps était accessible
avant le défi. Les requêtes Decaps postérieures au défi sont traitées
séparément ; les chiffrés de défi y sont interdits. Le contrôle fini
vérifie la nécessité du terme pré-défi et l'égalité des réponses dans les
cas post-défi autorisés. **La probabilité d'évaluation cible après le
défi n'est pas bornée** : le saut n'est donc ni une réduction IND-CCA
complète ni une preuve pour SHA3/SHAKE fixés.

Pour la branche B, un nouveau lemme traite les mêmes adresses de bruit
partagées par génération et chiffrement, puis la loi CBD indépendante quand
les graines sont distinctes. Dans le jeu déclaré à rôles aléatoires typés,
avec une clé honnête, le certificat J2 borne par moins de `2^-54` la
probabilité qu'au moins un message du domaine entier échoue à la correction
dans la version à matrice capée. La somme sur `2^256` messages est large et
ne démontre pas l'objectif C05. Le résultat retire un terme de décodage du
couplage Decaps adaptatif conditionnel, **pas** le besoin d'un extracteur
efficace. La contre-lecture interne n'a pas trouvé d'objection bloquante
dans ce jeu. Un test Rust supplémentaire vérifie le cas de graines
coïncidentes ; le cœur de production, les paramètres et les formats sont
inchangés. Aucun transfert à Keccak fixé, au modèle quantique ou à une borne
IND-CCA complète n'est acquis. **C01 concret reste ouvert.**

Une analyse complémentaire traite l'adaptativité avec un budget explicite
de graines de bruit distinctes réellement touchées. Elle utilise une borne
de norme pour la clé, une fonction génératrice du CBD(3), puis une union
sur les nouvelles graines, sans supposer que les décisions de l'adversaire
sont indépendantes. Pour une seule clé et au plus `2^32` graines autres
que celle de génération, deux lecteurs en arithmétique exacte vérifient
une borne d'événement de correction inférieure à `2^-195` dans le même
jeu idéal classique. Le budget doit comprendre les appels directs,
ceux du moteur et les vérifications de tout simulateur des deux mondes.
La borne ne s'applique pas aux chiffrés forgés en général et ne donne ni
extraction, ni transfert automatique au modèle de permutation partagée,
ni sécurité des fonctions SHA3/SHAKE fixées. C01 reste ouvert.

Un lecteur d'intégration `c01-cycle-integration-001` rejoue les sceaux
des cinq dossiers sélectionnés, la borne rationnelle et le contrôle fini,
puis vérifie que les termes de sécurité non établis restent marqués
ouverts. Il passe localement ; cette capsule reste hors Git et ne vaut
pas audit externe.

**19 novembre 2026 — raccords du défi, Decaps adaptative et modèle des
primitives.** Une nouvelle étude privée a repris le jeu R1 inchangé et
traité trois questions séparées. Pour la clé du défi, une commutation
exacte vers une loi auxiliaire de clé publique a été démontrée, avec son
coût de réduction ; l'avantage de ce jeu et la borne computationnelle
restante ne sont pas établis. Un lemme de collision conditionnel tient
compte du hachage public corrélé sans supposer son indépendance. Il
écarte une route de remplacement statistique **si** le terme auxiliaire
de collision est petit, condition qui n'est pas établie pour R1, sans
constituer une attaque ni une preuve de sécurité du R1.

Pour Decaps, un candidat avec trace classique a un lemme de couplage
adaptatif exact sous deux événements distincts : extraction d'un témoin
pour les chiffrés acceptés et accord avec le message effectivement
décodé. Le rejet fixe peut être calculé exactement avec une seule graine
indépendante dans cette simulation **si** ces conditions sont satisfaites.
Dans cette première étude, ni extracteur efficace pour tout adversaire du
jeu, ni borne de correction adaptative n'avaient été démontrés ; la classe
quantique n'était pas couverte. La nouvelle borne idéale et bornée en
graines figure dans la mise à jour en tête de ce rapport.

Un troisième dossier applique les [théorèmes 9 et 10 de Bertoni et al.](https://keccak.team/files/CSF-0.1.pdf)
aux débits du [FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf).
Il obtient, **en permutation aléatoire et avec accès classiques seulement**,
une enveloppe commune `N(N+1)/2^257` pour `N<2^256`, où `N` comprend
les appels pertinents à la permutation et à son inverse. Un prédicat
borné du tirage de matrice a un coût marginal explicite dans ce modèle.
Cette expression n'est pas une borne pour Keccak-f fixé. Le
[théorème quantique d'Alagic et al.](https://arxiv.org/html/2504.16887v2)
sur une éponge unique ne donne pas ici de transfert multidébit ni
d'avantage numérique pour le moteur concret.

Les trois capsules locales, `c01-lossy-key-001`, `c01-decaps-trace-001`
et `c01-sponge-multirate-001`, sont liées par une contre-lecture et un
lecteur d'intégration dans `c01-ab-integration-001`. Deux lecteurs
indépendants vérifient la première, deux modèles finis la deuxième ;
un lecteur et une mutation contrôlent la troisième. Les anciens lecteurs
de référence C01 ont été rejoués séparément. Ces tests vérifient les
identités et leurs limites, **pas** la résistance du R1 réel. Aucun
changement du moteur, de ses formats ou de ses paramètres ; aucune
nouvelle CI ou revue externe créditée. **C01 concret reste ouvert** :
il manque les bornes efficaces A et B et le transfert aux fonctions
fixées avant toute composition IND-CCA chiffrée.

**19 novembre 2026 — tentative de fermeture de C01 sur le R1 concret.**
Une nouvelle étude a confronté le même jeu à trois périmètres : preuve du
KEM inchangé, fonctions SHA3/SHAKE fixées et calculs de correction et de
résistance à la dimension réelle. Les capsules locales scellées apportent
trois résultats nouveaux et limités. Une preuve relie les collisions
d'encapsulation à la probabilité moyenne d'erreur PKE, sans supposer
l'injectivité globale. Un certificat arithmétique fixe à **1799** le rayon
entier qui garantit le décodage de tout bit malgré la compression. Un
raccord de jeux démontre alors une **borne conditionnelle de correction
honnête** : borne CBD idéale plus probabilité de dépassement du sampler
de matrice et quatre avantages des fonctions fixées. Ces cinq derniers
termes n'ont pas de borne numérique adoptée. L'audit des six rôles de
primitives les rattache aux octets du source, sans attribuer de propriété
cryptographique à leurs seuls domaines séparés.

La capsule quantitative démontre un **plafond générique** sur le coût de
recherche publique et vérifie les deux coefficients de son lemme par
énumération finie. Un plafond de coût n'est pas une minoration de toutes
les attaques ; les estimations Module-LWE antérieures gardent leur modèle
et ne deviennent pas un niveau de sécurité du KEM. Une recette matricielle
publiée a été écartée pour le scénario précis de dimension matricielle
1536 et objectif 256 ; ce filtrage ne porte ni sur une impossibilité
générale ni sur le module six par 256 du R1.

Une seconde route de preuve reproduit exactement la distribution des
réponses Decaps adaptatives pour un KeyGen **capé et conditionné à sa
terminaison**, mais son calcul énumère toutes les graines possibles et
son passage au source non capé dépend d'une probabilité inconnue. Il
établit l'existence d'une simulation abstraite, pas une réduction
efficace ou une borne de sécurité. Le raccord de clé défi reste ouvert.
Une candidate de découplage entre la tête et les coins de G a aussi été
formalisée : sous les auxiliaires nécessaires, son avantage est
équivalent au défi à une perte explicite ; elle ne constitue donc pas
une hypothèse indépendante plus faible. Ce diagnostic est vérifié par
des jeux finis dans `c01-joint-decoupling-001/` et ne conclut pas à
une impossibilité générale.

Les dossiers de preuve, rayon, primitives, calcul quantitatif et route
alternative sont conservés sous `artifacts/retained/c01-proof-next-001/`,
`c01-correction-bridge-001/`, `c01-primitives-next-001/`,
`c01-quant-next-001/`, `c01-alternative-route-001/`,
`c01-proof-route2-001/`, `c01-joint-decoupling-001/`,
`c01-fixed-route-search-001/` et `c01-r2-bil20-feasibility-001/`.
Leurs sceaux, lecteurs disponibles et
contre-lectures internes passent dans leurs portées. Le cœur
Rust inchangé repasse Clippy strict et **46 tests** avec toutes les
fonctionnalités via `scripts/engine.ps1 -Task check` sur le PC. Aucun
nouveau test fonctionnel ne démontre la sécurité IND-CCA.

**Décision actuelle : C01 concret reste ouvert.** La preuve manque
toujours d'un raccord indépendant pour la clé du défi corrélée à son
chiffré, d'un traitement efficace de Decaps adaptative, de bornes pour
les fonctions fixées et la PKE semée, puis d'une composition numérique
dans un budget adversaire commun. Une comparaison avec la preuve
machine vérifiée publiée pour ML-KEM
([Almeida et al., ePrint 2024/843](https://eprint.iacr.org/2024/843.pdf),
§5–6) rappelle la frontière de modèle : son argument FO est en oracle
aléatoire et certaines fonctions SHAKE sont traitées par des hypothèses
PRF distinctes. Il ne prouve pas le R1 aux SHA3/SHAKE fixés. Le moteur,
ses paramètres et ses formats restent inchangés ; R1 demeure
expérimental, sans gel cryptographique, sélection R2 ou qualification
de production.

La lecture intégrale de [Luck, Mao et O'Neill, ePrint
2026/2365](https://eprint.iacr.org/2026/2365) clarifie la route à
fonctions fixées : leur résultat négatif concerne une TDF construite
pour chaque fonction G, **pas** la PKE R1 ; leur résultat positif
concerne un chiffrement hybride, avec des hypothèses supplémentaires,
**pas** le KEM R1. Les auteurs laissent ouverte une instanciation
standard de la propriété d'extractabilité qu'ils emploient. Les autres
constructions primaires comparées changent également le schéma et ne
fournissent pas de preuve transférable au source inchangé. La lecture et
ses conditions sont conservées dans `c01-fixed-route-search-001/` ;
elle réduit les raccourcis de preuve admissibles, sans établir ni
attaque contre R1 ni impossibilité de toute preuve future.
Un amendement à l'écran R2 précédent confirme que le q=7681 de R1
ne satisfait pas, à dimension **matricielle** 1536, une condition de
raccord à LWE de la construction directe corrigée en 2025
([Nguyen, Duong et Pham](https://www.mdpi.com/2410-387X/9/4/79),
§2.4 et §3.1). Les tailles de cette route figuraient déjà dans le
dossier R2 antérieur et ne sont pas comptées comme résultat nouveau.
L'amendement ne prouve rien pour le module R1 et ne fixe aucun niveau
de résistance concret à 256 bits.

**19 novembre 2026 — bilan des blocs 2 à 4 du programme C01.** Trois
dossiers locaux ont traité la décision de paramètres R1, le choix d'une
construction R2 et la préparation du moteur à une revue indépendante.
Leurs résultats sont bornés par le bloc 1 : aucune preuve complète du R1
à fonctions fixes n'a été obtenue. **C01 concret reste ouvert ; R1 est
expérimental.**

Le **bloc 2** recalcule les tailles réelles, la borne de correction dans
son modèle et plusieurs coûts d'attaques dans les conventions de leurs
modèles, avec ML-KEM-1024 comme témoin de taille et de calcul. Les coûts
de modèles ne sont ni une borne IND-CCA du KEM exécuté, ni une comparaison
globale de résistance. Le verdict `BLOCK2_PARAMETER_FREEZE_HELD` maintient
le gel de sécurité des paramètres en attente. Le rapport, les reçus et les
lecteurs sont conservés dans `artifacts/retained/r1-c01-block2-001/`.

Le **bloc 3** examine quatre routes de construction distinctes et fixe
avant code les conditions de preuve, paramètres, formats et coût. Des
comptes de taille reproductibles d'une route matricielle montrent les
conséquences d'un encodage dense, sans constituer un jeu de paramètres
valide ni un transfert au module six par 256. Le verdict limité
`R2_SELECTED_CANDIDATES_NOT_VIABLE_YET` ne sélectionne aucun R2 « 1536 ».
Il ne signifie ni impossibilité générale ni faiblesse de R1. La fiche
M28 reste une réduction abstraite et non une spécification de moteur.
Le dossier est `artifacts/retained/r2-block3-001/`.

Le **bloc 4** contrôle à nouveau le moteur R1 actuel sur les octets de
ses images locales : suite Rust et Clippy strict, 64 comparaisons à la
référence Python indépendante, puis 256 échanges frais et 256 rejets.
Les reçus lient source, images et résultats ; un mandat de revue
cryptographique extérieure est préparé dans
`artifacts/retained/r1-c01-block4-001/`. Le statut
`BLOCK4_PREPARED_PARTIAL` signifie que ni moteur R2, ni qualification
binaire complète, ni avis extérieur reçu ne peuvent être crédités.
Un moteur final attend une construction sélectionnée et la revue effective.
Les trois dossiers ont été scellés, relus dans leurs portées et leurs
lecteurs rejoués. Ils restent locaux, hors du dépôt public ; aucune nouvelle
CI hébergée ou publication GitHub n'est revendiquée pour ce cycle.

**19 novembre 2026 — bloc 1 du nouveau programme C01, décision sur les
routes de preuve du R1 exact.** Le protocole a figé le jeu du KEM R1 à
fonctions publiques SHA3/SHAKE fixes, les deux raccords absents de M27 et
les critères de succès ou d'arrêt avant l'examen. Trois familles ont été
traitées : la justification indépendante de la clé défi, la simulation
adaptative de Decaps et le transfert de théorèmes primaires sélectionnés.
Le dossier privé `artifacts/retained/r1-c01-block1-001/` conserve
protocoles, amendements, preuves bornées, contrôles finis, lecteurs et
contre-lectures. Les identités et leurs limites ont été rejouées ; ce
travail ne constitue pas une revue cryptographique extérieure.

**Décision `R1_SELECTED_ROUTES_NO_GO` dans la portée examinée.** Les
propriétés séparées de la PKE et d'une primitive ordinaire ne suffisent
pas comme argument générique de la clé du défi lorsque la construction
exacte corrèle ses choix internes. Une famille de simulations externes
de Decaps est également contrainte. Les sources primaires étudiées
n'apportent pas les deux raccords au R1 inchangé. Ces résultats éliminent
des routes de preuve précises ; ils ne montrent pas de faille dans R1,
n'excluent pas une preuve spécifique future et ne donnent aucune borne
IND-CCA du programme exécuté. Les termes de défi, d'adaptation et de
primitives fixes restent `OPEN` ; **C01 concret reste ouvert**.

Le moteur, ses paramètres, formats, API et binaires canoniques sont
inchangés. Aucune CI hébergée, publication GitHub, qualification de
production ou certification n'est créditée. La prochaine décision
scientifique doit choisir entre une nouvelle preuve spécifique au R1
exact, avec hypothèses et coûts indépendants, et une construction
distincte entièrement spécifiée avant implémentation.

**19 novembre 2026 — M24 à M28, cinq blocs de recherche ciblés sur C01.**
Les protocoles et critères ont précédé les nouveaux calculs ; les capsules
locales `artifacts/retained/m24-concrete-game-001/` à
`m28-architecture-decision-001/` conservent les résultats sélectionnés,
premiers essais, lecteurs, contre-revues et sceaux. Les dossiers complets
restent hors du dépôt public. Le code, les paramètres, formats, API et images
canoniques R1 sont inchangés.

**M24 — `M24_CUT_CERTIFIED_SCOPED`.** Le jeu R1 aux fonctions publiques
fixes est formalisé et deux transitions indispensables sont isolées. Une
contre-lecture et des contrôles finis écartent les raccourcis circulaires.
Cela délimite une route de preuve sans établir une faiblesse du moteur.

**M25 — `M25_COMPLETE_SCOPED`.** Quatre coûts d'une famille d'estimation
ont été acquis sous budgets préfixés avec un témoin commun, puis recomposés
séparément. Un certificat de distribution vérifie le PKE semé exact dans
sa portée. Les premiers échecs d'outillage et la reprise sont conservés.
Les valeurs numériques reposent sur un modèle scalaire simplifié, avec
extrapolation pour R1 ; elles ne majorent pas l'avantage du PKE semé ni du
KEM complet. La veille de littérature n'a pas été convertie en revendication
de rupture ou de résistance.

**M26 — `M26_SCOPED_PRF_HOP_ESTABLISHED`.** Un saut de jeu conditionnel
pour la fonction de rejet est démontré avec son coût en requêtes, et les six
rôles SHA3/SHAKE sont liés à la source et à la spécification. La prémisse
quantitative correspondante n'a pas de borne adoptée. Le réducteur de ce
saut possède une capacité qui ne se transfère pas à la réduction adaptative
encore manquante.

**M27 — `M27_GAP_IDENTIFIED`.** Une composition rejouable relie les trois
capsules précédentes au même commit source. Son lecteur recalcule les
liaisons, l'algèbre et les contrôles négatifs. Les termes indispensables
pour le défi fixe et la décapsulation adaptative restent explicitement
ouverts ; aucune borne numérique IND-CCA du jeu exécuté ne résulte de cette
composition.

**M28 — `M28_ROUTE_SELECTED_SCOPED`, décision architecturale bornée.**
R1 est conservé comme moteur expérimental. Une fiche séparée définit un
candidat R2 fondé sur une PKE
matricielle CCA2 en modèle standard et une réduction abstraite classique
PKE→KEM, sous hypothèses. Les paramètres, coûts, formats, implémentation et
portée quantique de R2 restent à établir ; aucun théorème de cette fiche
ne prouve R1. La version publiée de la source primaire est conservée dans
la capsule locale, distincte de la version ePrint à comparer plus tard.

**Décision C01 : ouvert pour le R1 à fonctions fixes.** Le travail avance
en isolant les obligations mathématiques exactes et en éliminant des
conclusions non justifiées. Les prochaines dépenses de recherche doivent
porter sur une réduction indépendante du défi et une route adaptative sans
secret PKE, ou sur une architecture R2 réellement spécifiée et qualifiée.
Aucun audit extérieur, nouvelle CI hébergée, publication GitHub, certification
NIST ou qualification de production n'est crédité à M24–M28.

**19 novembre 2026 — M20 à M23, quatre qualifications bornées du moteur,
achevées dans leurs portées.** Les protocoles, critères et références ont été
fixés avant les acquisitions. Les dossiers locaux
`artifacts/retained/m20-source-root-repro-001/`,
`m21-path-coverage-001/`, `m22-image-link-001/` et
`m23-aarch64-port-001/` conservent les images, journaux, premiers essais,
reçus, contre-revues et manifestes scellés. Ces éléments détaillés ne font
pas partie du dépôt public.

**M20 — `M20_COMPLETE_SCOPED_DEFAULT`.** Deux extractions vérifiées d'une
même archive Git, sous des chemins source différents sur le même PC, et deux
cibles Cargo neuves produisent des exécutables Windows GNU CLI et banc
identiques octet à octet. Les images correspondent aussi aux images M19 du
même programme. Chaque CLI passe 16 échanges frais et 16 contrôles de rejet ;
le banc fournit 30 000 observations contrôlées structurellement. Cela vérifie
l'invariance au chemin source pour cette chaîne locale, sans démontrer une
reproductibilité entre machines.

**M21 — `M21_COMPLETE_SCOPED`.** Un pilote unique exécute 176 entrées
synthétiques de quatre familles dans une seule image Linux instrumentée.
Le profil et l'export LLVM retenus indiquent 18 issues exercées sur 24 issues
mappées dans les fichiers R1 actifs ; le code historique P0 est compté
séparément. Le premier essai, les amendements et les lectures écartées restent
tracés. Le dénominateur dépend de cette image et de cette toolchain : il ne
décrit ni tous les chemins sémantiques ni les exécutables release.

**M22 — `M22_COMPLETE_SCOPED`.** Les sources R1 concernées, les témoins
binaires antérieurs et les images PC exactes sont reliés par empreintes et
contrôles de lecture bornés. Le PE Windows et l'ELF Linux x86-64 donnent le
même profil R1 et passent chacun 16 échanges frais et 16 contrôles de rejet.
La contre-revue accepte la liaison dans ces deux images, sans équivalence
complète entre source et binaire, ni garantie générale de temps constant ou
d'effacement.

**M23 — `M23_COMPLETE_SCOPED`.** Une compilation croisée épinglée produit
une image release ELF64 Linux AArch64, inspectée et retenue hors cache. Sous
QEMU utilisateur, son profil correspond au témoin PC et elle passe 16 échanges
frais et 16 contrôles de rejet. Les premières tentatives d'outillage et de
lecture ont été conservées et corrigées par amendements avant les reprises ;
une contre-revue accepte l'image et les diagnostics exacts. Ce résultat vaut
pour Linux AArch64 émulé avec cette chaîne, sans qualification Android ni
sur un SoC réel.

Le cœur R1, ses paramètres, formats et API sont inchangés depuis M19.
**R1 reste expérimental et C01 concret ouvert.** Ces cycles ne démontrent ni
résistance cryptographique générale, ni temps constant, ni effacement global,
ni aptitude à la production. Aucune nouvelle CI hébergée, publication GitHub,
revue extérieure ou certification NIST n'est créditée.

**19 novembre 2026 — M19, reproductibilité Windows et branches LLVM dans une
portée PC définie, verdict `M19_COMPLETE_SCOPED`.** Le nouveau cycle local
`artifacts/retained/m19-engine-next-001/` a figé 28 entrées de source et de
preuve, les outils, les critères et le témoin négatif M18 avant les nouvelles
acquisitions. Un premier essai Windows a été interrompu par le harnais avant
toute image release ; il est conservé avec l'amendement préalable à la reprise.
Le changement de configuration Windows GNU, limité à une ligne de l'éditeur
de liens, est ensuite validé par deux constructions propres et indépendantes
du CLI et du banc. Les deux paires PE sont identiques octet à octet, avec
horodatage nul. Chaque CLI conserve le profil R1 et passe 16 échanges frais
et 16 contrôles de rejet ; le banc exécute 30 000 observations comme contrôle
fonctionnel. Formatage, Clippy strict et tests Rust du workspace passent
après le changement.

Quatre harnais Linux instrumentés ont des profils et exports LLVM de branches
authentiques, liés aux images, sources et corpus par empreinte. Le lecteur
indépendant retrouve les compteurs à partir des enregistrements de fonctions
et confronte les résumés LLVM. Le dénominateur est non nul pour chaque image,
avec une couverture partielle propre à chaque corpus. Il s'agit des issues
exposées par la toolchain dans ces images instrumentées, pas de tous les
chemins du moteur ni des binaires release. Les premières erreurs d'outillage
et de lecture sont enregistrées séparément. La contre-revue interne a
recompté les images Windows et les quatre exports Linux. Le cœur, les
paramètres, formats, API et binaire canonique R1 archivé sont préservés ; seul le
réglage de construction Windows GNU change. **R1 reste expérimental, C01
concret ouvert.** Ces résultats ne prouvent ni reproductibilité entre hôtes,
ni temps constant, effacement ou sécurité cryptographique générale. Aucune
nouvelle CI hébergée ni publication GitHub n'est créditée à M19.

**19 novembre 2026 — M18, six étapes de qualification PC exécutées, résultat
`M18_PARTIAL`.** Le dossier privé
`artifacts/retained/m18-engine-qualification-001/` fixe quatorze entrées de
référence, les cibles Windows et Ubuntu/WSL x86-64 et les critères avant les
acquisitions. Le nouveau contrôle fonctionnel passe avec huit paires de clés
fraîches, seize comparaisons Rust/référence Python et trente-deux décisions
de régression. Chaque image PC passe seize échanges frais et seize contrôles
de rejet agrégés. La chaîne source du KEM et les images PE/ELF ont été lues
dans une portée bornée, avec un addendum de liaison Linux contre-vérifié.

Le formatage, Clippy strict et les tests Rust du workspace passent sur les
deux systèmes. Chaque système a livré 30 000 observations organisées en
séries appariées avec le témoin ML-KEM-1024 ; R1 est environ cinq à six fois
plus lent pour les trois opérations dans ces mesures locales. Deux
compilations Ubuntu sont identiques octet à octet ; celles de Windows ne le
sont pas, la différence observée
étant limitée aux champs PE examinés. Quatre campagnes ASan nouvelles passent
un budget supérieur à 120 secondes CPU chacune. La couverture LLVM des lignes
est acquise par harnais ; celle des branches est `NOT_ACQUIRED`. Le diagnostic
temporel a 16 000 mesures par OS, sans signal au seuil fixé, mais ne prouve
pas le temps constant. Les deux essais préliminaires de couverture et les
limites des outils sont conservés séparément ; leurs métriques ne sont pas
créditées.

L'étape de correction conclut `NO_CORE_CHANGE_JUSTIFIED` pour les preuves
sélectionnées : aucun défaut nouveau du cœur n'a été établi et aucun
durcissement du code n'est revendiqué. La contre-revue interne accepte ces
résultats dans leurs portées et recommande `M18_PARTIAL`, car l'égalité brute
Windows a échoué, les branches LLVM ne sont pas acquises et les garanties
globales du programme restent ouvertes. Les images, corpus, profils,
instruments et reçus nécessaires sont retenus localement hors des caches.
**R1 reste expérimental, C01 concret ouvert ; aucune certification NIST,
revue cryptographique extérieure, qualification de production, nouvelle CI
ou publication GitHub n'est déduite.**

**19 novembre 2026 — Parties 3.2 à 3.5, quatre livrables traités dans leur
portée ; bloc 3 scientifique encore ouvert.** Le cycle privé
`artifacts/retained/r1-block3-completion-001/` fixe la construction R1
inchangée et distingue deux jeux : l'argument IND-CCA conditionnel du modèle
quantique déclaré et le KEM aux fonctions SHA3/SHAKE fixes. La chaîne du
premier est reconstruite et son calcul exact rejoué ; le second conserve
une obligation de sécurité non résolue. Les comptes du programme sont liés
aux sources. Le contrat précédent est revérifié et un diagnostic agrégé
supplémentaire sur le binaire canonique passe dans sa portée fonctionnelle.
Une contre-revue indépendante examine la sélection et ses limites.
Elle a conduit à sélectionner une révision du registre qui rattache
explicitement le calcul conditionnel au budget élargi correspondant ; les
premières versions sont conservées.

Les travaux 3.2–3.5 produisent des décisions et reçus vérifiables, sans
constituer une nouvelle preuve de sécurité pour les fonctions fixes.
**C01 concret et le but scientifique du bloc 3 restent ouverts ; R1 reste
expérimental.** Le moteur, ses paramètres et formats, le binaire, les
archives antérieures et le clone public sont préservés. Le dossier technique
demeure privé dans NIST ; aucune nouvelle CI, publication GitHub, certification
ou intégration de production n'est créditée.

**19 novembre 2026 — Bloc 3.1, décision de faisabilité de la preuve R1 à
fonctions fixes.** Un protocole préalable, les identités du moteur et des
archives, trois familles de parcours de preuve, une carte des ressources du
programme entier et des contrôles logiques indépendants sont conservés dans
`artifacts/retained/r1-fo-feasibility-001/`. Aucun des trois parcours examinés
n'a fourni une chaîne IND-CCA complète, indépendante et entièrement chiffrée
pour le R1 inchangé. Un lemme de simulation conditionnel est retenu comme
résultat structurel, avec ses conditions et coûts encore ouverts. La revue
des constructions publiées ne fournit aucun théorème directement applicable
aux fonctions et formats actuels ; elle ne démontre aucune impossibilité
générale.

Cette décision borne le prochain travail de recherche : choisir explicitement
le niveau de preuve visé avant de prolonger la calibration numérique, puis
construire et contrôler le parcours correspondant. Elle ne constate aucune
attaque contre le moteur. Le bloc 3 reste partiel, C01 concret ouvert et R1
expérimental. Le résultat conditionnel du bloc 2 conserve son propre modèle.
Le cœur, les paramètres, le binaire canonique, les capsules antérieures et
le clone public restent inchangés. Les détails et reçus demeurent privés
dans NIST ; aucune CI, publication ou intégration de production n'est créditée.

**19 novembre 2026 — Bloc 3, raccord ciblé au KEM concret livré.** Le dossier
privé `artifacts/retained/r1-concrete-link-001/` relie la chaîne entière du
programme R1 à ses sources, contrôles d'octets et imports. Il établit une
nouvelle borne **conditionnelle** de correction d'un échange honnête avec les
fonctions fixes, en séparant les hypothèses supplémentaires. Les traces
conservées ont été rejouées et une contre-revue interne a accepté ce résultat
dans sa portée après correction d'un quantificateur sur les clés honnêtes.

Le raccord ne constitue pas encore la preuve IND-CCA du KEM à fonctions
fixes : les écarts computationnels requis ne sont pas qualifiés numériquement
et la composition FO entière reste à établir. Le bloc 3 demeure partiel pour
cet objectif, C01 concret ouvert et R1 expérimental. Le bloc 2 conserve sa
clôture dans son modèle conditionnel déclaré. Le cœur, les paramètres, le
binaire canonique, les anciennes capsules et le dépôt public sont inchangés.
Le rapport détaillé et les reçus restent privés dans NIST.

**19 novembre 2026 — Livrable natif ciblé du bloc 1 achevé.** Les calculs
globaux de R1 et du témoin ont terminé, avec certificats exacts du réseau
initial complet et rejeux indépendants. La comparaison est exécutée et
rejouable selon les mêmes conventions. Les deux matrices conservées gardent
leur identité historique ; aucune nouvelle cohorte n'est créditée.

Les résultats renforcent le dossier expérimental et sa vérifiabilité. Les
intervalles de comparaison se recouvrent et ne démontrent ni gain strict
d'avantage ni supériorité globale. Les qualifications complémentaires et les
limites de mesure sont consignées séparément, avec les tentatives et reprises.
Ce lot ne ferme pas la recherche générale de résistance. R1 reste expérimental,
C01 concret ouvert. Les détails sont privés dans NIST ; le moteur, les
archives antérieures et la publication sont préservés.

**19 novembre 2026 — Bloc 2 formellement clos dans le modèle conditionnel
déclaré.** Le calcul de bout en bout du modèle élargi, les ressources
transmises à l'hypothèse de résistance et la borne finale sont constitués
et contrôlés. Le verdict reste celui déjà acquis : cible retenue satisfaite
sous les hypothèses explicitement déclarées. Cette décision formalise la
clôture du livrable de calcul ; elle ne constitue pas une nouvelle avancée
scientifique ou une nouvelle série de tests.

Les blocs 1, 3 et 4 restent partiellement réalisés au regard des livrables
généraux demandés. Le dossier privé lie la décision aux résultats sélectionnés
et aux revues postérieures, sans réécrire les archives. Les hypothèses de
résistance et le passage aux primitives fixes restent distincts du calcul
conditionnel. R1 reste expérimental et C01 concret ouvert. Aucune modification
du moteur ou nouvelle publication GitHub n'est effectuée par cette clôture.

**Quatre blocs de qualification mis en œuvre dans leurs portées.** Le cycle
privé fournit de nouveaux calculs natifs avec certificats et limites
conservés, une composition quantitative du modèle idéal élargi, une branche
conditionnelle pour la population PKE concrète et une qualification plus
large du cycle source/binaire. Les acquisitions et leurs rejeux indépendants
sont conservés ; les résultats négatifs ne sont pas effacés.

La sélection comporte 90 tests ciblés distincts pour les volets réduction,
population concrète et programme ; les témoins numériques et relectures
restent comptés séparément. Les hypothèses de résistance ne sont pas adoptées
sur la seule base des expériences. Les conclusions idéalisées, concrètes et
logicielles conservent leurs conditions respectives et ne sont pas fusionnées
en une garantie du KEM complet. Les limites de provenance sont consignées.

R1 reste expérimental et C01 concret ouvert. Les sources, paramètres,
formats et binaire canonique sont préservés ; aucun résultat ne justifie un
correctif de production dans ce cycle. Les rapports PC sont actualisés et
les détails restent privés. Le dépôt public reste au commit cc65426 ; aucun
nouveau push, résultat de CI hébergée ou déploiement n'est crédité.
Le dossier interne est scellé et son intégration indépendante acceptée.
Les archives précédentes et les entrées protégées ont été contrôlées ; les
diagnostics et leurs corrections d'instruments restent conservés.

**Publication de la synthèse ciblée vérifiée.** Le commit
[`cc65426`](https://github.com/MajidNIMAR/mlkem-1536-core/commit/cc65426a44e0fdbf9647d6a22dbe33baf72d47c0)
est publié sur main. La présentation et les synthèses documentaires ont été
relues ; les six documents publics sont accessibles anonymement et leurs
octets correspondent au commit. Le moteur, les archives et les réglages du
dépôt sont préservés. Les détails scientifiques restent privés. Cette
publication ne crédite aucune nouvelle CI ; R1 reste expérimental et sa
qualification concrète C01 ouverte.

**Présentation publique actualisée de l'étude ciblée.** Le README, SECURITY
et la note de portée présentent une synthèse des expériences exécutables,
du rejeu indépendant et des extensions du modèle idéal. Les 66 tests ciblés
de composants sont identifiés comme vérifications locales privées, distinctes
du lot public M15 et de la CI hébergée. Les données, programmes et résultats
détaillés restent privés. Cette présentation ne change ni le moteur, ni ses
paramètres, ni les budgets historiques, ni le statut expérimental de R1 ou
l'ouverture de sa qualification concrète C01. La publication documentaire
ne crédite aucune nouvelle exécution de tests hébergée.

**Cryptanalyse exécutable et extension du modèle idéal — cycle privé achevé
dans sa portée.** Une chaîne complète construit ses sondes depuis les seules
données publiques et décide sur les vecteurs effectivement calculés. Le
protocole, les coûts observés, les limites de budget et les contrôles
indépendants sont conservés ; le rejeu reconstruit intégralement les données.
Les calibrations réduites et témoins natifs restent distincts, sans déduction
de dureté générale à partir d'une absence de succès.

Le volet mathématique ajoute un transport cohérent d'interface et un
corollaire pour un prétraitement préclé dont toute la préparation est comptée.
Une autre comparaison, où l'oracle change réellement, conserve sa perte et
ses conditions propres. Les revues sont internes ; les budgets antérieurs
ne sont pas étendus gratuitement et aucune équivalence générale des fonctions
fixes avec des oracles idéaux n'est affirmée. Les résultats détaillés restent
privés dans NIST, conformément à la demande de confidentialité.

Aucun résultat retenu ne justifie de modifier le moteur ou ses paramètres.
R1 demeure expérimental et sa qualification concrète C01 reste ouverte.
Le cœur, le binaire, les archives précédentes et le clone public sont
préservés. Ce cycle local ne constitue ni une nouvelle CI ni une publication
GitHub. La feuille de route précise le prochain critère de décision.
Le dossier interne est scellé et vérifié. Les diagnostics de validation
restent conservés ; la sélection finale réussit ses contrôles ciblés.

**Publication M17/C01 vérifiée.** Le commit
[`4d3e1b5`](https://github.com/MajidNIMAR/mlkem-1536-core/commit/4d3e1b5b45d9be5b7b55c35b1dacb97d016c3ffe)
est publié sur main. Le README, SECURITY, la note de portée et les synthèses
du rapport présentent les résultats et leurs limites. La référence distante,
l'API et les octets de quatre documents accessibles anonymement sont contrôlés.
Le nom, le titre, la description courte et les autres réglages du dépôt sont
inchangés. Les archives privées et les entrées exécutables restent préservées.
Cette publication documentaire ne crédite aucune nouvelle CI ; le code reste
celui du53d501de testé dans le run44223949348. R1 demeure expérimental,
avec argument conditionnel établi dans son modèle et qualification concrète
encore ouverte.

**Présentation publique M17 et C01.** Le README, la [note de portée
actualisée](ETAT_RECHERCHE_C01.md) et SECURITY décrivent les nouveaux résultats
et distinguent l'argument conditionnel QROM/RC1 de la qualification concrète
encore ouverte. R1 reste expérimental. Cette mise à jour documentaire conserve
le moteur, ses paramètres, ses formats, les workflows et le lot reproductible
M15. Les programmes, acquisitions et revues détaillés M17/C01 restent privés.
Les comptes de validation locaux ne sont pas une nouvelle suite CI publique.
La référence du code testé demeure le commit53d501de et la CI44223949348.

**C01 — argument conditionnel IND-CCA consolidé et vérifié dans sa portée.**
Le travail ciblé réunit désormais l'énoncé exact de R1, les raccords de
réduction, la correction, les oracles et leurs ressources dans un dossier
unique. La relecture interne n'identifie pas de lemme supplémentaire manquant
pour le modèle quantique idéalisé précisément déclaré. Les deux hypothèses
natives peuvent se ramener à une seule hypothèse MLWE, dans un budget augmenté
dont le coût complet est payé. Le repère numérique conservé est satisfait
conditionnellement ; la condition suffisante est moins forte que le choix
historique. Ce repère ne revendique pas un niveau global en bits.

Le dossier explicatif demandé par le C01 original est constitué comme
argument sous hypothèses. La vérité numérique de l'hypothèse de dureté et la
qualification des fonctions SHA3/SHAKE fixes restent non établies. Le statut
plus fort de qualification entièrement concrète de R1 demeure donc ouvert.
Cette distinction est explicite ; les anciens états et archives ne sont pas
réécrits. Les garanties de programme, temps constant, effacement, audit et
production restent des sujets séparés.

La sélection finale réussit neuf contrôles ciblés et 42 tests distincts,
sans omission ; les reprises de revue ne gonflent pas ce compte. R1 reste
expérimental. Aucun changement du cœur, des paramètres ou du binaire n'est
retenu par ce travail ; les détails restent privés dans NIST, les rapports
PC sont à jour et la publication GitHub précédente est préservée.

**M17 — dix périmètres développés et relus dans leurs portées.** Le cycle
local ajoute des décisions avec matrice visible, des sondes adaptatives, des
filtres quantitatifs pour les deux jeux natifs, un traitement conjoint des
fonctions fixes et des populations, des cartes de ressources, une lecture
sémantique de fonctions Rust, des contrôles d'images PC et une composition
reproductible. La validation sélectionnée comporte **18 travaux réussis et
217 tests ciblés sans omission** ; les reprises de revue ne gonflent pas ce
compte. Les versions initiales et corrections d'instruments sont conservées.

Ces résultats restent propres aux classes, modèles et images déclarés. Ils
ne qualifient ni toute la classe adversariale du KEM concret, ni toutes les
fonctions compilées. Les hypothèses natives, le transfert de famille fixe et
les obligations générales de C01 restent ouverts ou conditionnels. R1 est
conservé pour la recherche, avec gel final différé. Aucun résultat retenu ne
justifie actuellement de modifier ses paramètres ou son moteur ; les sources,
le binaire canonique et les archives antérieures gardent leurs octets.

Le rapport, le journal et la feuille de route sont actualisés sur le PC.
Les détails M17 demeurent locaux et privés ; la publication M16 et le lot
reproductible public M15 sont préservés. Ces validations ne constituent ni
une nouvelle CI GitHub, ni un audit extérieur, ni une qualification NIST ou
une autorisation de production Messenger.


Version de travail du 18 novembre 2026. Ce document est la base évolutive du futur article. Le [journal](JOURNAL_RECHERCHE.md) conserve les étapes et décisions ; les [résultats figés de J2](../results/j2/run-001/) conservent les calculs et leur provenance. Une modification du rapport doit rester cohérente avec ces données.

**Présentation M16 publiée et vérifiée.** Le commit
[`cee88267`](https://github.com/MajidNIMAR/mlkem-1536-core/commit/cee8826724d0c3579b2b51700c9bce70c12f557d)
est publié sur main. Le README, la note de portée et le statut de sécurité
présentent M16 ; la description courte indique explicitement R1 expérimental,
C01 ouvert et l'absence de qualification de production. Les autres réglages
du dépôt sont inchangés. Les accès anonymes retrouvent la description exacte
et les octets commis des quatre documents examinés.

L'export contrôle 2 578 fichiers/blobs plus la provenance. Les inputs non
documentaires restent ceux du53d501de testé ; cette publication documentaire
ne revendique aucune nouvelle CI ou exécution des 113 tests M16 sur GitHub.
Les détails scientifiques restent privés et les archives, le moteur et son
binaire sont inchangés. Les reçus de publication sont conservés localement.

**Présentation publique M16.** La [synthèse de portée](ETAT_RECHERCHE_M16.md)
et le README présentent les cinq volets, leurs validations internes et leurs
limites. Le profil R1 reste explicitement expérimental et C01 ouvert. Cette
mise à jour documentaire conserve les sources, paramètres, formats et binaire
du moteur ainsi que les entrées du lot reproductible M15. Elle ne publie pas
les programmes, données ou revues détaillées M16 et ne transforme pas les
113 tests locaux en nouvelle CI publique. La référence de validation du code
reste le commit53d501de et son run44223949348, indiqués ci-dessous.

**M16 — cinq paliers de développement de sécurité, cycle local.**
Le nouveau cycle traite la résistance du PKE, les graines et fonctions fixes,
la conformité fonctionnelle, les images PC et la décision de candidat. Il
fournit une calibration mathématique exacte d'une famille restreinte, des
constructions quantifiées liées à la correction concrète, de nouveaux contrats
source-liés pour des composants du PKE/FO et une analyse de chemins compilés.
Un registre de composition conserve les conditions de chaque contribution.

Les résultats sélectionnés sont rejoués dans neuf travaux de validation,
avec 113 tests ciblés sans omission. Les revues internes croisées ont renforcé
les instruments et clarifié leurs conditions d'emploi ; les premiers essais
et diagnostics sont conservés dans le dossier local M16. Les propriétés de
programme et d'images gardent leurs bases de confiance et leurs limites.
Ce cycle ne constitue pas une nouvelle CI publique ou une revue extérieure.

La nouvelle calibration restreinte n'est pas une borne pour tout adversaire
du PKE ; les observations statistiques ne certifient pas une probabilité
cryptographique rare. Les transferts concrets, populations adversariales et
ressources complètes de la réduction restent à qualifier. C01 et le gel final
restent ouverts. La décision conserve R1 pour la recherche : aucun résultat
acquis ne justifie de modifier sa construction, ses formats ou son moteur.
Les sources, le binaire canonique, les archives antérieures et le lot public
M15 vérifié demeurent inchangés ; aucune production Messenger n'est autorisée.

**Publication M15 vérifiée le 18 novembre 2026.** Le premier lot
reproductible est publié sur la branche `main` au commit
[`53d501de`](https://github.com/MajidNIMAR/mlkem-1536-core/commit/53d501de898ec6ba024cc05a3f7373563c6a2ef4).
La [CI 44223949348](https://github.com/MajidNIMAR/mlkem-1536-core/actions/runs/44223949348) est terminée avec succès sur ses trois jobs :
514 tests Python sans omission par OS et contrôles natifs M10 sous Windows
et Ubuntu ; installation complète du solveur et deux rejeux M15 sous Windows,
avec 31 obligations SMT, 131 072 coefficients NTT, 21 tests scientifiques
et 18 tests d'outils. Les 34 fichiers de l'artefact de reçus/journaux sont
contrôlés, avec vérification du digest publié par l'API et des empreintes
de leurs composants. Les revues internes confirment la portée de ces résultats.

Les accès anonymes au dépôt, au README, au guide du lot, au manifeste et
au workflow correspondent aux octets commis. Les cartes d'export portent
sur 2 577 fichiers et leurs blobs, plus la provenance. Les titres, descriptions
et paramètres GitHub sont inchangés. Les archives scientifiques, les sources
et le binaire du moteur restent intacts. Les autres volets privés ne sont pas
crédités à cette CI ; C01 demeure ouvert. Les reçus détaillés de clôture sont
conservés localement dans le dossier de publication du lot.

**Reproductibilité M15 — premier lot distribué avec CI dédiée.** Le dépôt
livre désormais le lot Windows délimité : instruments, 31 requêtes SMT et
objets de preuve, certificat NTT, tests, manifeste et installation épinglée.
Le guide public fournit les commandes d'installation, de rejeu et de contrôle
hors ligne. Les 78 entrées scientifiques sélectionnées restent identiques ;
les adaptations de présentation et d'attributs Git préservent leurs octets.

Un job Windows indépendant installe réellement le solveur puis vérifie les
31 obligations arithmétiques, 131 072 coefficients NTT, 21 tests scientifiques
et 18 tests d'empaquetage ; il répète la configuration et le rejeu hors ligne.
Les reçus et journaux sont conservés dans les artefacts de la CI, sans wheel
ou bibliothèque native. Les contrôles habituels du moteur Windows/Ubuntu
restent séparés et inchangés. Le statut hébergé doit être lu pour le commit
examiné dans les exécutions GitHub Actions ; la seule présence du workflow
ne constitue pas un succès de CI.

Cette distribution ne publie pas les autres acquisitions détaillées M11–M15
ni leurs 82 tests internes complets. Elle rend une partie précise du travail
rejouable à partir des sources publiques. Le moteur et son binaire restent
inchangés. C01 demeure ouvert et les dépendances de confiance du lot sont
explicites. La publication suit la branche habituelle main, sans changement
de titre, description ou paramètres du dépôt.

**Reproductibilité M15 — étape 3 depuis une copie neuve.** Le lot figé
à l'étape 2 passe le rejeu dans un clone complet indépendant de la référence
publique, préparé avec un commit local sur `main` contenant les 88 fichiers
du paquet. Le paquet est relu depuis l'index Git identique au commit, puis
vérifié. Le contrôle indépendant préalable confirme l'absence de cache de
solveur, d'archives privées, de binaire de compilation et de liens partagés.

La première installation télécharge réellement le wheel officiel épinglé et
installe ses 34 membres Z3 dans le nouveau clone. Les 31 obligations SMT,
131 072 coefficients NTT et 21 tests scientifiques passent ; les 18 tests
d'empaquetage passent également. Une seconde configuration hors ligne et
un second rejeu réussissent sans modification des entrées suivies. L'arbre
complet de 2 578 fichiers est contrôlé ; les seules conversions de checkout
concernent sept scripts PowerShell suivant leurs règles Git CRLF déclarées.
Les 88 fichiers du lot et les deux sources Rust conservent strictement leurs
octets. Les reçus génériques bruts sont complétés par la provenance externe
de cette copie neuve, sans réécrire les archives historiques.

La revue indépendante finale accepte cette étape dans son périmètre, sans
correction restante. Le travail utilise le même PC, Windows et CPython 3.13.7 : il établit une
copie neuve autonome vis-à-vis des caches et archives privés, pas une machine
ou un système neuf. Le commit de préparation est uniquement local au clone
d'essai, sans dépôt distant configuré. La CI hébergée et la publication du
lot restent à faire à l'étape suivante. Les sources et le binaire du moteur
sont inchangés ; C01 reste ouvert.

**Reproductibilité M15 — premier lot, étape 2 locale.** Le paquet de
rejeu Windows est préparé sous
`research/reproducibility/m15/implementation/`, avec installation du solveur
épinglée par taille et SHA-256, manifeste des entrées et commande unique de
vérification hors ligne. Les 78 entrées scientifiques sélectionnées conservent
leurs octets ; le contexte de deux documents est adapté. Les deux sources
Rust liées et le binaire du moteur sont inchangés.

Le contrôle local valide les 34 fichiers du solveur, rejoue les 31 obligations
SMT, reconstruit les 131 072 coefficients du certificat NTT et réussit les
21 tests scientifiques sans omission. Les 18 tests distincts des outils
d'empaquetage passent également. Les reçus et journaux sont conservés, sans
modifier les archives historiques. Le cache existant a été vérifié et réutilisé ;
une nouvelle installation complète dans une copie neuve reste à effectuer.
Le rejeu depuis une copie neuve, la CI hébergée et la publication de ce lot
ne sont pas réalisés par cette étape. C01 conserve sa portée ouverte.

**M15 — cinq chantiers de sécurité approfondis.** Le cycle suivant fournit
de nouvelles acquisitions cryptanalytiques, des arguments sur les distributions
structurées, une construction calculable des primitives fixes dans les jeux
étudiés et des certificats conditionnels de correction par clé. Une comparaison
commune conserve les hypothèses propres à chaque famille. La conformité du code
est renforcée par des obligations sémantiques universelles sur des composants
délimités et un certificat algébrique du réseau NTT.

Les revues croisées ont demandé des durcissements des instruments privés et
une clarification de populations ; les versions initiales restent conservées.
Les versions retenues et le registre de composition sont vérifiés dans leurs
périmètres. Les coûts heuristiques ne deviennent pas des bornes universelles
d'avantage. Les théorèmes conditionnels n'établissent pas les écarts concrets
des fonctions fixes, et les preuves ciblées ne couvrent pas tout le KEM ni sa
compilation. Le dossier détaillé demeure local et privé.

C01 reste ouvert : la justification des hypothèses quantitatives, les
transferts et populations concrets ainsi que la comparaison CCA finale ne sont
pas entièrement acquis. Aucun résultat n'impose de modifier la construction
actuelle. Les paramètres, formats, sources et binaire de R1 sont inchangés.
La production Messenger reste interdite et la revue extérieure différée.

**M14 — avancée de l'argument conditionnel de sécurité.** Le cycle suivant
M13 fournit un lemme plus serré dans le modèle déclaré, une construction
de simulation moins coûteuse et leur intégration dans le cas candidat R1.
La comparaison de quatre variantes isole leurs effets sur 48 lignes
conditionnelles. Le repère étudié dispose désormais d'une marge suffisante
sous des hypothèses quantitatives explicites, là où l'ancienne borne ne
permettait pas de conclure. Les calculs exacts, reconstructions distinctes
et revues internes sont conservés dans le dossier privé M14.

Cette avancée ne repose pas sur l'adoption d'un facteur contrefactuel.
Sa portée reste conditionnelle : la crédibilité des hypothèses aux
ressources construites, le passage aux primitives exactes et la comparaison
au cahier des charges final restent à établir. Les contrôles finis ne
remplacent pas les preuves générales ; les revues internes ne constituent
pas l'audit extérieur différé. C01 demeure ouvert et la production
Messenger reste interdite. Le moteur, ses paramètres, son binaire et les
capsules historiques sont inchangés. Les détails ne sont pas exportés.

**M13 — hypothèses quantitatives pour orienter la recherche.** À la demande
de l'utilisateur, C01 est maintenu ouvert et une étude locale élargit les
hypothèses de travail. Elle comprend 270 cartes de ressources, 16 paires
d'avantages supposés et trois cibles, avec regroupement des cas
algébriquement équivalents. Des inversions, des scénarios d'amélioration
de preuve, des contrôles de cohérence et des frontières entières exactes
complètent la grille. La synthèse interne distingue les pistes qui changent
le registre numérique de celles qui modifient la force des hypothèses
requises aux ressources construites.

Les hypothèses ne sont pas adoptées comme vérités et les facteurs
contrefactuels ne constituent pas de nouveaux théorèmes ou paramètres.
Les verdicts restent conditionnels ; leurs fréquences ne mesurent aucune
probabilité de sécurité. Le rapport détaillé, les tableaux de décision,
les reprises et les vérificateurs restent dans le dossier interne M13.
R1, son binaire, le contrat RC1 et l'objectif comparatif final restent
inchangés. C01 demeure ouvert et la production Messenger reste interdite.

**M12 — contrat quantifié et composition de sécurité.** Le cycle local
du 17 novembre fixe un contrat de recherche borné, construit la carte de
ressources du mécanisme quantique extérieur et la relie aux hypothèses du
chiffrement interne. Les versions retenues comprennent des corrections
explicites d'instruments et de comptages, avec conservation des acquisitions
initiales. Les nouvelles analyses de structure combinent des contrôles à
taille réelle sur des données synthétiques et des populations réduites
exactes. Les propositions conditionnelles, exigences numériques et limites
sont consignées dans le dossier interne M12, hors export public.

La portée du contrat local reste distincte de l'objectif comparatif final.
Le cycle n'attribue aucun niveau global de sécurité à partir d'un coût
heuristique, d'un compteur de tests ou d'une hypothèse non évaluée. R1
reste la référence de recherche, avec sources et binaire inchangés. C01
reste ouvert et la production Messenger demeure interdite. Le rapport
historique et les capsules M10/M11 conservent leurs versions ; les
instruments repris dans M12 font autorité pour les nouveaux calculs.

**M11 — cycle interne de développement de sécurité.** Les quatre travaux
autorisés le 17 novembre sont engagés dans un dossier local distinct :
composition et ressources, recherche d'attaques sous contraintes, décision
de construction et liaison des obligations au programme. Ce premier cycle
comprend une carte réversible interne exécutable, une synthèse constructive
de son arithmétique de référence, huit travaux d'estimation avec 13 188
évaluations de candidats et des contrôles sémantiques sur des copies privées
du code. Les calculs, tests, contre-vérifications, incidents et limites sont
conservés avec leurs sources et empreintes. Les résultats détaillés demeurent
locaux conformément à l'instruction de confidentialité de l'utilisateur.

La décision M11 conserve R1 comme moteur de recherche ; aucune nouvelle
version cryptographique ni sélection finale des paramètres n'est déduite
automatiquement de ce cycle. C01 reste ouvert et bloque la production dans
Messenger. La revue croisée interne est distincte de la revue extérieure
différée. Le moteur livré, son binaire canonique et les capsules historiques
conservent leurs octets ; M11 n'ajoute aucun crédit aux campagnes M10.

Le [bilan courant M10](M10_MOTEUR_ET_QUALIFICATION.md) relie le durcissement
du cycle secret, les nouvelles analyses conditionnelles et les acquisitions
du candidat 003. Sa campagne longue a atteint les quatre budgets ; la
couverture LLVM, le rejeu indépendant, la distribution et le contrôle global
local sont acquis. La CI 43893183494 passe sur Windows/Ubuntu et l'original
Windows 003 est promu après vérification. M10 devient la référence livrée,
qualifiée dans le périmètre PC interne. Les reçus restent distincts ; cette
clôture d'ingénierie ne ferme pas C01 ni la sélection cryptographique finale.
Les gains antérieurs M06/M07/M08/M09 gardent leur portée historique ;
la sécurité cryptographique complète et le gel final des paramètres restent
ouverts.

La [revue des cibles et contrats M08](REVUE_CRITIQUE_M08_CIBLES_ET_CONTRATS.md)
confronte les cinq observations reçues au code et à la spécification :
qualification ARM/Android encore ouverte, C01 non fermé, domaines CBD déjà
spécifiés et test combinant secret non canonique/hash incohérent déjà présent.
Le test Rust et les 13 cas du consommateur Windows sont revérifiés avec
succès ; aucune propriété Android ni modification de R1 n'en découle.

**M09 livré et publié — contrats, cycle secret et NTT scalaire.** Les cinq
chantiers sont réalisés et leur [bilan](M09_MOTEUR_CONTRATS_ET_QUALIFICATION.md)
consigne les gains médians de 13,13 à 16,82 % contre M08 sur les deux OS,
les contrôles de correction et la revue ciblée des quatre images. La CI
43806407492 passe avec 439 tests Python exécutés par OS, sans test ignoré,
et les originaux CLI/API. Le rapport conserve ci-dessous les étapes, le
rejet du premier candidat et les limites C01/audit ; la clôture publique
est détaillée en fin de document.

**M08 livré et publié — import direct des clés et validation élargie.** Le
[protocole M08](PROTOCOLE_M08_IMPORTS.md) est fixé avant modification du
moteur : référence M07, contrôle direct des encodages, consommateur API
par défaut, revue des chemins compilés et nouvelle campagne de 1800 secondes
CPU par harnais, avec couverture source et oracle indépendant distincts.
Le [bilan M08](M08_IMPORTS_ET_VALIDATION.md) consigne maintenant le candidat :
300000 latences et 2880 observations mémoire passent les 210 budgets ;
88576 sondes d'import par version/hôte et les corpus complets concordent.
La revue ciblée est scellée (124 témoins adressés) et qualifie la suppression
des copies de bits visées dans les consommateurs. La campagne longue est
terminée dans son volet principal : les quatre budgets sont atteints,
7256,67 secondes CPU nouvelles en 30 segments, sans défaut observé ni crédit
historique. L'union LLVM distincte couvre 438/604 lignes et 17/36 branches
instrumentées du cœur, sans exclure les mappings nuls. Les 3156 requêtes
déterministes concordent avec Python, dont 433 sondes de décapsulation de
clés privées acceptées. La première tentative de rejeu a été interrompue lors
du redémarrage observé de l'environnement ; ses trois traces sont conservées et la
reprise utilise le contrôleur et l'image gelés, sans nouveau fuzzing ou build.
Les deux paquets de livraison passent leurs contrôles ; Linux est identique
brut à sa répétition et Windows diffère uniquement dans deux métadonnées PE.
Le gel complet et son rejeu passent : 7520 fichiers et 428 répertoires sont
conservés dans l'archive M08. Le check complet Windows passe, avec 352 tests
Python, Rust/fmt/Clippy/rejeux et 2008 fichiers identiques avant/après.
Les originaux CLI/consommateur passent le smoke natif local et la
[CI neuve Windows/Ubuntu](https://github.com/MajidNIMAR/majax_mlkem1536/actions/runs/43008567843),
avec 352 tests Python par OS. Le [reçu de publication M08](../results/publication/r6-m08-001/)
lie le commit public testé b0491eb à la source locale 33a1828 et aux 2024
blobs/fichiers exportés. Les exécutions natives d'origine passent 16/16 CLI,
cinq refus normaux et 88576 sondes d'import par OS ; ces intégrations ne
sont pas de nouvelles campagnes ou mesures de performance.
Les conclusions des consommateurs API ne sont pas transférées
aux CLI : leurs quatre inventaires propres identifient les autres images,
sans preuve d'effacement PKE. Le diagnostic distinct de 32000 observations
ne dépasse pas |t|=4,5, avec maxima Windows 1,843 et Linux 1,602 ; il ne
démontre pas le temps constant.

Le [volet théorique M08](REJET_ET_INFORMATION_LATERALE_M08.md) est figé dans
`results/security/m08-rejection-001`. Pour une information latérale classique
E et une borne p de la probabilité conditionnelle de deviner Z, le jeu idéal
donne min(1,qp) en ROM et min(1,2q√p) en QROM pour D>0, zéro pour D=0.
Ici D compte les accès classiques à la fonction indexée, même en QROM ;
q compte les portes de requête publiques pouvant viser J.
Les indépendances de la vue idéale sont des hypothèses explicites. Dix
panneaux rationnels retrouvent M06 lorsque p=2^-256 ; la borne quantique
uniforme n'est pas resserrée. Une clé importée valide ne certifie ni cette
entropie, ni sa génération honnête. Les primitives concrètes, l'information
quantique corrélée et la sécurité globale restent hors de ce résultat ;
C01 reste ouvert.

**M07 — mémoire, latence et livraison validées dans le périmètre mesuré.** Le moteur
traite désormais les polynômes en coefficients ligne par ligne, en
conservant les six opérandes NTT. Les 2240 observations mémoire et les
80000 observations comparatives de latence satisfont les 116 contrôles
des [budgets fixés avant candidat](DECISION_M07_BUDGETS.md). Le maximum
observé de pile touchée diminue de 39 à 49 % sur les opérations principales
selon l'hôte et l'opération ; cette métrique instrumentée n'est pas une
borne universelle de pile. L'import privé valide passe de deux allocations
à une. Les corpus intégraux concordent sur Windows/Linux. La médiane de
KeyGen Windows augmente de 1,8 %, résultat défavorable conservé. Le
[bilan détaillé M07](M07_MEMOIRE_ET_VALIDATION.md) décrit la méthode et
ses limites. La campagne ASan/std reconstruite propre à M07 a atteint
248,73 secondes CPU, avec activité après initialisation des quatre
harnais. La revue bornée des quatre binaires est scellée, les deux paquets
sont validés et l'[archive complète M07](../results/engine/m07-001/) se rejoue.
Le [contrôle complet Windows](../results/engine/m07-verification-001/) réussit
avec 227 tests Python, Rust/fmt/Clippy, rejeux et auto-tests. Les contrôles
GitHub neufs Windows/Ubuntu réussissent dans le
[run 42936652940](https://github.com/MajidNIMAR/majax_mlkem1536/actions/runs/42936652940),
pour le [commit public 97d776c](https://github.com/MajidNIMAR/majax_mlkem1536/commit/97d776c5a25f67c86a70fe83694c3e82425c0b33).
Chaque hôte passe 227 tests Python et le check complet, puis exécute l'original
de son paquet : 16 échanges, 16 rejets et cinq refus normaux de commandes de
recherche. L'[archive de publication M07](../results/publication/r6-m07-001/)
conserve huit membres et son manifeste, dont les journaux bruts et la
concordance des 1932 fichiers exportés/blobs canoniques. Ces essais natifs
sont frais ; les anciennes campagnes et mesures sont des données rejouées.
La clôture documentaire conserve le code, les contrôles et les preuves testés.

**Présentation du projet — MAJAX R6.** Le nom de présentation met en avant
le programme de recherche, l'ingénierie et l'architecture cryptographique.
R6 désigne le rang six ; le profil technique `KEM1536-DEV-Q7681-R1`, ses
formats, ses domaines et les résultats figés gardent leur identité. Le
README rassemble désormais le moteur exécutable, les résultats M06 et les
preuves selon leur portée. La synchronisation de publication préserve
l'historique public et ajoute une provenance de l'instantané source.
Les contrôles publics courants se lisent dans Actions ; les réussites
historiques restent liées à leur révision exacte.
La provenance distingue les octets exportés après attributs Git des
blobs canoniques : cette précision traite les fins de lignes PowerShell
sans changer les scripts ni les preuves. Douze tests ciblés couvrent
l'export et la conservation de l'historique public.

**Publication M06 contrôlée sur machines neuves.** Le
[passage public final](https://github.com/MajidNIMAR/majax_mlkem1536/actions/runs/42906288492)
réussit sous Windows et Ubuntu pour le commit public `feaeef2`, avec
166 tests Python par plateforme, tests Rust, formatage, Clippy strict,
rejeu des preuves et auto-tests. L'[archive de publication](../results/publication/r6-m06-001/)
conserve les deux passages réussis et leur portée, ainsi que la
concordance des 1 882 fichiers exportés et blobs Git canoniques. Ce
résultat complète les anciens reçus locaux ; les campagnes et benchmarks
archivés ne sont pas relancés par ce contrôle. Le prochain jalon
[M07](FEUILLE_DE_ROUTE_MOTEUR.md) mesure la mémoire du moteur,
réduit les espaces temporaires et renouvelle la livraison vérifiée.

**Historique — M06.** Le moteur accumule désormais les produits dans le
domaine NTT et réutilise les opérandes transformés. Les corpus intégraux
concordent sous Windows/Linux. Les 60 000 mesures comparatives donnent
des rapports de médianes de 1,79/1,87/1,76 pour KeyGen/Encaps/Decaps,
avec hausse de certaines frames statiques de pile explicitement conservée.
Le [volet J idéal](REJET_IMPLICITE_R1_M06.md) borne maintenant le rejet
secret dans le ROM/QROM ; sa borne quantique trop lâche ne certifie pas
l'allocation illustrative M05. La revue des binaires est acquise dans son
périmètre. La campagne instrumentée M06 est achevée : 850,99 secondes CPU,
quatre exports de couverture et leur union LLVM, 8638 requêtes de corpus
confrontées à Python. Les résultats
historiques ne sont ni écrasés ni crédités automatiquement à ce code.

**Historique — M05.** Les points 1 et 2 demandés après la recherche de
projets comparables sont exécutés : [majorants conditionnels ROM/QROM](SECURITE_CONCRETE_R1_M05.md)
et [108 estimations comparatives](COMPARAISON_EXPERIMENTALE_M05.md).
Le transfert de correction aux bruits expansés est maintenant établi
dans un modèle RO, en moyenne sur les oracles et les clés ; les avantages
du PKE à graines, de la PRF quantique de rejet et le passage aux primitives
concrètes restent ouverts. Aucun niveau global ni supériorité universelle
n'est acquis. Les résultats négatifs face au point académique de rang 6
à q=3329 sont conservés. Le moteur NTT et les formats R1 ne changent pas.
Les deux nouveaux instantanés sont sous `results/security/m05-cca-001`
et `results/security/m05-comparison-001` ; leurs rejeux sont intégrés à
`check`. La campagne longue M03 historique a atteint ses budgets ; son
reçu automatique conserve la nécessité d'une revue finale distincte.

**Historique — programme proposé avant la réalisation M04.** À la demande
de définir comment atteindre puis dépasser le niveau du démonstrateur
1024, le [programme M04](PROGRAMME_AMELIORATION_M04.md) ordonne les travaux
de moteur : traiter M03-A01 puis introduire une NTT scalaire compatible,
renforcer les contrôles et la distribution, comparer directement les deux
dépôts. Le contrat de sécurité, le lien certificat/programme et la
cryptanalyse commune restent un axe parallèle. Aucun gain ou niveau
supérieur n'est annoncé ; les critères de sortie sont définis avant
développement. La campagne M03 était encore active à cette étape ; sa
fin automatique est consignée plus bas, sans validation globale anticipée.

**Première publication GitHub du moteur 1536.** Le dépôt public
[MajidNIMAR/majax_mlkem1536](https://github.com/MajidNIMAR/majax_mlkem1536)
est créé, distinct du moteur ML-KEM compagnon du même auteur. L'export conserve
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
avant les contrôles Windows/Ubuntu ; les deux contrôles distants réussissent
désormais sur le commit public `75c26f6`, avec 95 tests Python par plateforme.
La campagne longue M03 continue séparément, sans résultat final anticipé.
Voir [la procédure de publication](PUBLICATION_GITHUB.md).

L'envoi public est confirmé au commit `08c8aa3` (672 fichiers), issu du
commit local `db22fc6`. Les deux jobs de [CI distante](https://github.com/MajidNIMAR/majax_mlkem1536/actions/runs/40210170341)
sont en cours au constat de publication.

**Premier retour de CI : liaison Windows.** Le job Windows initial échoue
pendant Clippy parce que la détection de MinGW n'emploie pas les objets et
bibliothèques livrés avec Rust. Les préparations Rust/Python réussissent.
Le correctif `.cargo/config.toml` impose `link-self-contained=yes` pour la
cible Windows GNU. L'auto-test release réussit ensuite : 16 échanges et
16 rejets. Le contrôle complet local et la CI Windows réussissent ensuite.
Aucun changement du moteur ou de ses formats.

**Portabilité numérique du contrôle H11.** La première CI Ubuntu passe
les tests et H10, puis relève une égalité stricte inadaptée sur des champs
flottants de calibration H11. Le diagnostic Linux isole notamment un
écart `erfc` de 3,47 × 10^-18. Un nouveau rejeu portable conserve le calcul,
les compteurs exacts et toutes les empreintes historiques, avec tolérance
relative 10^-13/absolue 10^-30 limitée aux champs flottants de calibration.
Les sources et résultats figés restent inchangés. Quatre nouveaux tests
et le rejeu complet H11 passent sous Windows ; la CI complète réussit
ensuite sur Windows et Ubuntu. Voir [le détail du correctif](PUBLICATION_GITHUB.md).

**Validation publique confirmée.** Le [run 40210986511](https://github.com/MajidNIMAR/majax_mlkem1536/actions/runs/40210986511)
termine avec succès pour les deux plateformes sur `75c26f6` : 95 tests
Python, les tests Rust, les vingt instantanés J2 et les contrôles moteur.
Les [journaux complets et leur provenance](../results/publication/portability-001/)
sont conservés. Cette validation depuis le dépôt public complète le
contrôle local avec caches réutilisés ; elle ne démontre pas des binaires
identiques, un niveau de sécurité ou la fin de la campagne longue M03.


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

Pour le dépôt de l'article, il restera à fixer le périmètre des revendications et des obligations ouvertes, faire relire l'analyse, préciser les auteurs et contributions, les licences et les commits exacts du texte et du logiciel, puis identifier les artefacts cités. Le logiciel et ses résultats sont déjà publics sur GitHub ; ce rapport demeure la base évolutive de l'article.


## Actualisation automatique M03 — 2026-10-25T14:59:22.748948+00:00

Temps CPU de fuzzing cumulé mesuré : 85.01 s. Budgets atteints : True. Post-traitements : {"coverage_exported": true, "independent_corpus_replayed": true}. Preuves dans results/engine/m03-smoke-001. La revue finale reste requise ; T07 et la validation globale ne sont pas déclarés acquis automatiquement.

## M04 — Trois travaux scientifiques avant les modifications du moteur

À la demande de l'utilisateur du 25 octobre 2026, les travaux 1–3 ont été
menés et revus avant l'optimisation du moteur. Les sources et sorties sont
conservées dans `results/security/m04-001` avec manifeste SHA-256.

- `docs/ARGUMENT_SECURITE_R1.md` définit le jeu mono-utilisateur, les deux
  hybrides CPA idéaux MLWE_(6,6) et MLWE_(7,6), la rigidité par réencapsulation
  et les obligations d'expansion/FO. Le résultat est conditionnel : aucune
  borne IND-CCA concrète complète ou QROM fermée n'est annoncée.
- `docs/LIEN_CERTIFICAT_PROGRAMME_R1.md` et un vérificateur indépendant
  standard Python retrouvent exactement la fraction run-004, la borne
  entière ≤2^-310, l'arrondi dans [-120,120] et le rayon commun 1799.
  Huit vecteurs répartis (2048 coefficients) sont reconstruits intégralement.
  La borne concerne l'espérance sur clés honnêtes du pire message avec
  bruits idéaux ; elle ne certifie ni chaque clé ni l'indépendance réelle de
  SHAKE. La collision de graines aux nonces alignés annule les deux produits
  croisés, elle n'impose pas une pénalité automatique de correction 2^-256.
- `docs/COMPARAISON_ATTAQUES_CADRE_COMMUN_R1.md` consolide 60 estimations en
  30 paires strictes et rattache quatre minima du dual aux ressources et aux
  queues. R1 retourne des coûts plus élevés dans ces modèles, sans niveau
  global déduit. La réussite de toutes les familles n'est pas 99 % ; les
  listes matérialisées et les extrapolations de réduction restent explicites.

Les sept tests du lien de correction et les cinq tests des contrats
comparatifs passent. Les vérificateurs historiques run-002/009/016 ont été
repassés sans nouvelle estimation Sage. Décision : conserver les paramètres
et octets R1, puis corriger M03-A01, optimiser la multiplication et contrôler
les réalisations livrées. Les graines et messages de 256 bits imposent des
plafonds génériques de recherche distincts des estimations de réseaux.
La campagne longue M03 reste active sur ses propres sources gelées.

## M04 — Moteur NTT livré, contrôles et comparaison exécutés

La séquence demandée a été exécutée : trois travaux scientifiques avant
modification du moteur, puis correction mémoire, NTT, contrôles des
binaires livrés, distribution et confrontation directe des dépôts.
Le détail est dans `docs/M04_MOTEUR_NTT_ET_CONTROLES.md` ; preuves nouvelles
immutables dans `results/security/m04-001` et `results/engine/m04-001`.

La réalisation scalaire NTT conserve les domaines, formats et octets R1.
Les sources de production sont celles de 78f5faf (dev_kem SHA4bc3f75c…,
engine_poly SHA 906e9e27…). Chacun des deux binaires de recherche retrouve
1000 vecteurs, 10000 rejets, 10000 mutations et 20000 décisions de formats.
Les nouveaux tests API et le consommateur KEM/HKDF/AES-GCM passent sur les
deux OS. Les contre-revues ont corrigé deux faiblesses des contrôles :
mutation de plusieurs octets à la fois et reconnaissance trop permissive
d'instructions intercalées dans les boucles d'effacement. Aucun défaut
supplémentaire de production n'a été identifié dans ce périmètre.

M03-A01 est corrigé dans les deux binaires effectivement empaquetés :
sortie polynomiale écrite directement dans la destination de l'appelant,
deux scratch de 512 octets effacés sur le retour normal. Windows SHA-256
ea80bc3a7f49ba287cf0958be1e7eceabe55cfc8882cdabc2517b6c58712ca65 ;
Linux e025ab71066ba63d3efccf6eb28f5e91a4050d151ea83f4fb1aab4320ced71c9.
Deux appels par registre Linux sont qualifiés comme memset ; 23 autres
sites restent ouverts. Ni l'effacement de toutes les copies ni un temps
constant général ne sont prouvés. Les anciens constats M03 restent intacts.

Le diagnostic temporel conserve 32000 observations et 64 contrastes, huit clés
et cinq classes par OS. Max |t|=1,578180 Windows et 1,981728 Linux, sous 4,5,
sans filtrage, sans preuve CT et sous charge. Le fuzzing ASan/std reconstruite
consomme 458,97 s CPU sur quatre harnais ; un complément API de 73,47 s CPU ajoute
510 exécutions après initialisation. Total 532,44 s CPU, aucun défaut observé.
La std instrumentée est contrôlée ; ni couverture de lignes nouvelle ni
oracle indépendant complet sur les mutants ne sont revendiqués.

La comparaison du vrai dépôt 1024 à 3dd7c91 avec R1 utilise Rust 1.93.0 commun
et 24000 observations ; les versions des 29 dépendances initiales sont conservées.
La révision NTT améliore les médianes R1 de ×2,25 à ×2,64 ; dans le panneau AVX2,
R1 donne 0,962/1,132/1,233 ms (KeyGen/Encaps/Decaps), le premier dépôt
0,099/0,083/0,090 ms. Le témoin inchangé varie jusqu'à 13,2 % entre processus ;
les gains restent des observations sous charge, pas un effet NTT isolé.
Le premier moteur reste plus rapide, sans conclusion globale de sécurité.

La distribution 003 a obtenu deux builds isolés identiques pour chaque
cible, sur le même hôte avec les caches existants. Les paquets 004 actualisent les
sources et réutilisent ces mêmes octets après égalité exacte des 30 entrées compilables ;
aucune nouvelle compilation n'est prétendue. Licences, inventaires,
prérequis et provenance sont inclus. Les paquets restent locaux sous
artifacts/generated/m04-distribution/release-004 ; la source locale et les
preuves sont versionnées. L'instantané source004 précède l'archive finale
M04 : le contrôle de recherche complet emploie également cette dernière.

La tâche complète check réussit deux fois ; 115 tests Python réussissent dans
la dernière campagne, plus les contrôles des workspaces autonomes. Le
vérificateur M04 contrôle 609 fichiers, 61 sources, quatre inventaires et 32000
observations, puis redésassemble réellement les quatre binaires et rattache
les deux paquets à leurs octets. Les conclusions C01/CCA concrètes et QROM
restent ouvertes ; le certificat de correction demeure dans son modèle
idéal documenté. Aucun dossier institutionnel, dépôt distant ou service
applicatif n'est créé ou modifié par cette passe.

La campagne longue M03 reste distincte sur 8ef4ceb. Au pointage du 25 octobre
2026 à 21:00:43 UTC, ses quatre travailleurs tournent encore, avec 77691,14 secondes
CPU cumulées sur 86400 (environ 89,9 %). Sa clôture et sa revue ne sont pas
annoncées ; aucun budget de cette campagne n'est crédité à la NTT.


## Actualisation automatique M03 — 2026-10-25T22:46:15.756612+00:00

Temps CPU de fuzzing cumulé mesuré : 86941.20 s. Budgets atteints : True. Post-traitements : {"coverage_exported": true, "independent_corpus_replayed": true}. Preuves dans results/engine/m03-fuzz-001. La revue finale reste requise ; T07 et la validation globale ne sont pas déclarés acquis automatiquement.

## 26 octobre 2026 — M05, sécurité et comparaison expérimentale

Le [protocole M05](PROTOCOLE_M05_SECURITE_ET_COMPARAISON.md) fixe le profil
R1 et demande une confrontation favorable ou défavorable aux sources.
La réalisation NTT de production n'est pas modifiée ; les paramètres,
formats et domaines de hachage restent identiques.

### Argument de sécurité et correction à graines

La [note de sécurité M05](SECURITE_CONCRETE_R1_M05.md) apporte le passage
du certificat rationnel aux bruits issus de graines dans le modèle RO.
Pour deux graines distinctes, les adresses du bruit sont disjointes ;
si rseed=σ, on obtient r=s et e1=e, donc B=e2 et aucun dépassement du
seuil majorant. Cela établit δ_RO≤(1−2^-256)δ_cert pour la moyenne sur
oracles/clés du pire message. Ce n'est pas une borne pour toute clé ou
tout oracle fixé, ni un résultat direct sur SHAKE concret.

Le calculateur conserve les deux coordonnées de G512 et les appels
implicites : Q_RO=2g+j+3D+2. Le majorant ROM laisse un avantage du PKE
à graines inconnu. Une incohérence locale de normalisation CPA/OW dans
les textes relus est conservée ; le coefficient 6 retenu est une marge
conservatrice de notre analyse, pas une constante imprimée attribuée à HHK.
Le contrôle formel final des constantes reste une obligation.

Le PDF complet de Ge–Yang–Yu–Yu 2025 a été récupéré et relu. Son théorème
22 concerne directement le FO implicite utilisé ici ; la simulation
cohérente des domaines est comptée. Le majorant conserve séparément
l'avantage OW du PKE et la sécurité de la PRF de rejet avec accès public
quantique. Aucun de ces termes n'est remplacé par zéro. Le travail de
Majenz–Sisinni 2025 est également relu : ses hypothèses asymptotiques et
sa compression omise ne fournissent pas de coût fini R1 à reprendre.

L'instantané `results/security/m05-cca-001` conserve six panneaux
rationnels, sept sources propres, les ancrages de lecture et empreintes
des PDF. Leurs octets externes restent dans les caches ignorés. Pour
g=j=D=2^64, les seuls termes connus ont pour logarithmes environ −242,386
(correction ROM), −187,830 (devinette ROM) et −174,916 (correction QROM).
Ces composantes ne donnent pas un niveau global. Les sept tests contrôlent
notamment les compteurs, les inversions exactes, les racines par entiers,
le partage CBD(3) et 729 tables pondérées d'un oracle scalaire réduit.

### Comparaison des problèmes et des proxys

Le [panneau M05](COMPARAISON_EXPERIMENTALE_M05.md) conserve les sources
primaires épinglées : Aigis-Enc mode 4 à secret CBD(3)/erreur CBD(8), Kyber
historique k=4 à q=7681, KINDI-512-3-2-1 à degré 512 et uniforme sur
{−2,−1,0,1}, plus R1, ML-KEM-1024 et le point d'article rang 6 à q=3329.
Les lois et équations des observations comprimées sont distinguées des
instances LWE abstraites. Une sensibilité gaussienne à l'arrondi marginal
indépendant supposé reste un proxy, pas une attaque validée du KEM publié.

Après un pilote de 15 travaux, le panneau complet termine ses 108 travaux
avec coûts finis en 690,37 s, quatre travailleurs et délai de 180 s par
travail. Les 229 fichiers figés dans `results/security/m05-comparison-001`
conservent entrées/sorties, sources du travailleur, paramètres et provenance.
Les 36 croisements avec run-002 retrouvent exactement les coûts historiques.
Les 23 554 résidus des quantificateurs sont énumérés en entiers ; les
contre-exemples conditionnels empêchent de créditer une indépendance fictive.

Les proxys R1 sont plus coûteux que ceux des comparateurs de rang quatre et
de KINDI dans les conventions exécutées. Le résultat défavorable est aussi
conservé : le point académique rang 6 à q=3329 coûte davantage que R1 dans
les six colonnes du panneau avant sérialisation. Le défaut de correction
historique de P0 reste distinct et empêche une substitution automatique.
Les 54 paires de budgets retournent ici les mêmes coûts, avec m=1536
effectivement choisi pour le dual R1 même lorsque 1792 est autorisé.

Les 24 extrapolations classiques au-delà de 1024, les quantités
exponentielles N, les succès heuristiques et l'absence de pic mémoire
calculé restent signalés. Les lectures récentes sont consignées dans
[l'applicabilité M05](APPLICABILITE_ATTAQUES_M05.md). L'attaque KINDI
rapportée par CryptanalysisBench cible le jeu 256-3-4-2 dans son benchmark,
pas le jeu 512 comparé ici ; aucune transposition automatique n'est faite.

### Contrôles et décision

Les deux livrables ont été contre-relus, leurs 13 nouveaux tests et leurs
rejeux sont réussis sous Windows et Linux. Leurs vérifications sont
intégrées à `check` sans relancer les estimations Sage à chaque contrôle.
Le contrôle complet Windows termine avec code 0 : formatage, Clippy,
tests Rust, 128 tests Python, vérifications des instantanés et auto-test
frais du moteur. Le contrôle Linux M05 porte sur les 13 nouveaux tests,
les six panneaux rationnels et les 108 sorties comparatives ; il n'est
pas présenté comme un nouveau `check` intégral Linux.
Les reçus d'intégration sont conservés dans
`results/security/m05-verification-001`.

R1 demeure la base du moteur expérimental. M05 termine le panneau et
l'instanciation conditionnelle annoncés ; C01 reste ouvert pour les
avantages du PKE à graines, la PRF quantique de rejet, les constantes
formelles finales et les primitives concrètes. Aucun niveau global,
audit extérieur ou supériorité universelle n'est annoncé. Les modifications
et preuves sont destinées à un commit local ; aucune publication distante
n'est comprise dans cette passe.

## 10 novembre 2026 — M06, développement du moteur et preuves associées

Le [bilan moteur M06](M06_MOTEUR_ACCUMULATION_NTT.md) part de `693c6a3`.
La réalisation réutilise les opérandes transformés et accumule les six
produits avant une seule inverse dans la destination détenue. Les types
coefficient et NTT sont distincts, les sommes restent canoniques après
chaque terme et aucun cache persistant n'est ajouté. Les lois CBD(3),
le module 7681, le rang six, les tailles et domaines R1 sont identiques.

| Opération | Transformations avant / après | Médiane avant / après, µs | Rapport des médianes |
|---|---:|---:|---:|
| KeyGen | 108 / 48 | 912,009 / 508,664 | 1,79 |
| Encaps | 126 / 55 | 1045,195 / 560,313 | 1,87 |
| Decaps | 144 / 68 | 1207,790 / 686,917 | 1,76 |

Les comptes sont testés dans le programme, y compris 68 pour un rejet
contrôlé ; les latences proviennent de 60000 observations dans cinq
séries alternées, sur la même machine et le même CPU logique. Les
extrêmes sont conservés. Les contrôleurs de la passe ont séparé les
mesures des builds lourds et du fuzzing ; l'hôte général et sa fréquence
ne sont pas isolés. Les résultats décrivent une exécution, sans facteur
universel de vitesse ni amélioration d'un niveau de sécurité.

La contrepartie mémoire est écrite : les frames LLVM statiques passent
de 7352 à 11464 octets pour KeyGen, de 11320 à 12872 pour PKE Encrypt,
de 7560 à 9096 pour Decaps. Les deux processus RSS séparés mesurent
2048 KiB chacun ; cette granularité ne mesure pas le cœur seul. Aucun
pic dynamique de pile n'est déduit de ces données.

### Conservation des octets et revue de réalisation

Les nouveaux exécutables de recherche retrouvent tous les cas figés
M01/M02 sous Windows et Linux : 1000 vecteurs complets, 10000 rejets,
10000 mutations et 20000 entrées de format par système. Les produits
scalaires sont aussi confrontés à la convolution générique indépendante.
La campagne de régression ne mesure pas de nouvelle fréquence d'échec
rare ; les références et leurs quantificateurs restent ceux des études.

Le premier check global a refusé les repères M04 devenus périmés.
Le pont certificat est adapté, puis renforcé après contre-revue d'une
ancre initialement satisfaite par un autre site intact. Les nouveaux
tests mutants ciblent séparément les deux inverses et additions, les
transpositions, resets, transformations et sorties. Le certificat exact
run-004 reste inchangé et sa sortie M06 est figée avec l'outil courant.

Quatre désassemblages complets sont conservés. La revue ciblée contrôle
les quatre helpers NTT sans division, la copie inverse de 512 octets
vers le propriétaire et huit emplacements des nouveaux buffers dans
leurs appelants. Le filtre lexical du cœur omet un nom LLVM manglé en
build de recherche ; la fermeture d'appels et la revue explicite le
traitent. Les emplacements reconnus ne prouvent ni tous les chemins,
ni l'effacement de toutes les copies, spills, registres ou sorties
exceptionnelles. Une contre-revue interne distincte n'est pas un audit
extérieur indépendant.

Deux cibles neuves par système sont construites. La première capture
avait omis les fichiers publics incorporés par include_str/include_bytes
du témoin ; une deuxième capture les inclut avant reconstruction. Les
sources communes concordent. Les trois Linux sont identiques en octets.
Les trois Windows ne diffèrent que dans l'horodatage COFF et le checksum
PE ; ces deux champs sont masqués dans une copie de comparaison, jamais
dans les binaires bruts conservés. Aucune identité brute Windows ou
reproduction par un autre hôte n'est revendiquée.

Le panneau temporel distinct conserve 32000 observations, maxima |t|
1,559/1,658 et aucun dépassement de 4,5. Tous les extrêmes restent inclus.
Sans contrôle de multiplicité ni garantie de puissance, il ne prouve
pas le temps constant. `results/engine/m06-001` conserve 114 membres
vérifiés et son manifeste de provenance, soit 115 fichiers ; son
vérificateur rejoue quatre inventaires depuis les textes
archivés et les revues ciblées, sans nouveau désassemblage. Les mesures
comparatives sont séparées dans `results/engine/m06-measurements-001`.

### Borne du rejet idéal et conséquence défavorable

L'[étude J M06](REJET_IMPLICITE_R1_M06.md) ferme la seule inconnue ciblée
du rejet préfixé dans le modèle idéal : ε_J≤min(1,q/2^256) en ROM,
ε_J≤min(1,2q/2^128) en QROM pour D>0, zéro exact pour D=0. z doit
être uniforme et indépendant des autres données ; les accès indexés
sont classiques et q compte les portes potentiellement J de la
réduction complète. La ligne entière est reprogrammée dès le départ,
ce qui évite un facteur D ajouté artificiellement.

La constante 2 du théorème O2H principal AHU est relue, ainsi que la
correction SXY d'août 2021 excluant l'ancienne constante sqrt(2). L'erreur
signalée de l'annexe FO d'AHU n'est pas utilisée. Les empreintes indiquent
les fichiers réellement récupérés ; les versions corrigées lues par
index n'ont pas d'empreinte inventée.

Sept panneaux rationnels et huit tests finis Windows/Linux sont figés
dans `results/security/m06-rejection-001`. À q=D=2^64, les majorants sont
2^-192 et 2^-63. La borne quantique ne certifie pas l'allocation M05
2^-130 dès une requête entière positive. Ce résultat défavorable est
une limite de la preuve suffisante, pas une attaque atteignable ou une
impossibilité de sécurité. C01 reste ouvert pour le PKE à graines, les
primitives concrètes, les constantes finales et une borne plus serrée
si nécessaire.

Le contrôle complet Windows réussit après la correction du pont,
avec 144 tests Python à son étape d'exécution, tests Rust, Clippy,
instantanés et auto-tests. Les tests Rust avec/sans recherche et les
24 nouveaux tests de recherche passent aussi sous Linux. Les ajouts
ultérieurs d'intégration sont rejoués séparément avant commit. Les
résultats et le budget de la campagne instrumentée M06 sont consignés
dans la note de mesures ; aucun temps historique n'est transféré à cette
version. Le bilan final est de 713,36 secondes CPU principales et 137,63
de complément API, soit 850,99 s. Les deux segments API initiaux n'avaient
aucune mutation et restent conservés ; le complément atteint 1740
exécutions après INITED. Les quatre exports et leur vraie union LLVM
couvrent 334/363 lignes instrumentées de dev_kem, 90/120 d'engine_poly,
15/15 de secret_box ; les zéros des fichiers de profil et d'anneau de
référence restent affichés. Les trois constructeurs constants des tables
NTT et run_diagnostics expliquent les noms non parcourus de ces modules,
sans preuve de toutes les branches ou d'effacement déduite. Les 8638
requêtes déterministes concordent intégralement avec Python, dont 1545
sondes sur clés privées importées. Les 2288 opérations à aléa frais restent
hors de ce rejeu déterministe, avec leurs invariants vérifiés par le
harnais. Le suivi délégué interrompu par un filtre automatique a été
repris par le contrôleur racine, sans doublon de campagne. Les reçus,
notices et sources sont conservés dans `results/engine/m06-fuzz-001`.

Les sept contrôles finaux d'intégration réussissent : quatre rejeux de
preuves M06 sous Windows, 154 tests Python Windows, rejeu de l'archive
instrumentée sous Linux et 25 tests M06 ciblés Linux. Formatage, Clippy
strict toutes fonctionnalités, tests Rust et auto-test du binaire habituel
ont leurs reçus. Le check global antérieur réussi comptait 144 tests ;
les ajouts ultérieurs sont couverts par ces contrôles finaux, sans
revendiquer un nouveau check intégral Linux. L'instantané
`results/engine/m06-verification-001` conserve 28 membres vérifiés et sa
provenance. Cette passe est livrée par un commit local, sans publication
distante implicite. Les anciens résultats et paquets restent intacts.

## 10 novembre 2026 — organisation et intégrité après nettoyage

Le rangement du projet, décrit dans les notes locales d'entretien, rassemble les
emplacements de référence dans NIST. L'inventaire de Documents et Codex
n'identifie aucun code ou rapport 1536 extérieur à rapatrier. Le clone
public propre est déplacé vers `publication/majax_mlkem1536`, séparé du
dépôt courant de recherche et conservé à sa révision publique ecb40ad.

Les compilations reconstructibles, exports redondants et anciens essais
d'installation sont supprimés après tri : 267 chemins de travail, environ
37 Go d'espace libre récupéré sur le volume. Treize produits historiques
uniques omis par les anciens paquets sont conservés une seule fois avec
index et empreintes ; les sources primaires sont dédupliquées dans leur
cache privé. Les résultats scientifiques figés et les historiques Git
restent en place.

Les empreintes des 1885 fichiers suivis sont contrôlées avant/après, avant
les mises à jour documentaires. Les 1549 fichiers de résultats conservent
leurs octets, ainsi que le moteur exécuté. L'auto-test frais passe
16 échanges et 16 rejets ; les données officielles, outils modernes,
158 archives Sage et Git public déplacé sont vérifiés. Le reçu
local `docs/maintenance/cleanup-001.json`, exclu de l'export public, distingue suppressions, déplacement,
produits uniques retenus et mesures d'espace. Ce rangement ne modifie
aucun paramètre ni argument de sécurité.

## 10 novembre 2026 — publication actuelle et identité MAJAX R6

La page GitHub, la notice et la description publique présentent le moteur
comme un programme de recherche et d'ingénierie cryptographique. Les
formats, les domaines et les octets du cœur R1 sont conservés. Les
évolutions M04–M06 sont publiées avec leurs preuves et l'historique public
reste intact. Les notes d'entretien du poste sont exclues de la publication.

Le premier passage de branche réussit à `1b4a1be` avec 164 tests Python
par système. La version consolidée réussit sur main à `feaeef2`, avec
166 tests par système et tous les contrôles ordinaires. Les
[reçus figés](../results/publication/r6-m06-001/) contiennent les journaux
bruts, révisions et empreintes. Ils distinguent le contrôle depuis des
exécutants neufs du rejeu des preuves historiques et des nouvelles
expériences, qui ne sont pas exécutées dans ce passage. La publication
des reçus ne modifie pas le code testé. M07 est planifié séparément,
avec mesure préalable des pics de pile et allocations avant optimisation.

## 10 novembre 2026 — identité du moteur ML-KEM compagnon

Le dépôt ML-KEM-1024 compagnon est renommé **MAJAX ML-KEM — Post-Quantum
Cryptographic Engine**, à l'adresse
[MajidNIMAR/majax-mlkem](https://github.com/MajidNIMAR/majax-mlkem).
Le changement conserve l'identité GitHub et l'historique du dépôt. Sa
présentation décrit maintenant la bibliothèque Rust et le CLI pour
ML-KEM-512/768/1024, le service HTTP ML-KEM-1024 avec HKDF-SHA-256 et
AES-256-GCM, les backends PQClean et les outils d'intégration et de
vérification. Le titre de l'interface web et les liens courants suivent
cette identité. Le commit public `ae903a6` porte cette refonte ; les
contrôles de syntaxe PowerShell, shell et JavaScript sont réussis. La
[CI publique 42917245769](https://github.com/MajidNIMAR/majax-mlkem/actions/runs/42917245769)
réussit sur ses cinq jobs : intégration, vérification complète, assurance
et performances x86-64/AArch64. Le moteur Rust, les
paramètres, les domaines et le binaire fourni sont inchangés. Les notes
historiques et comparaisons conservent leurs révisions et leur portée.
Cette actualisation de présentation ne modifie pas le profil R1 de MAJAX R6.


## 16 novembre 2026 — M09, cinq chantiers du moteur

Les cinq chantiers sont engagés suivant les protocoles
[de développement](PROTOCOLE_M09_MOTEUR.md) et
[de qualification](PROTOCOLE_M09_QUALIFICATION.md), préenregistrés dans Git.
Android et l'intégration applicative sont différés ; M08 reste la référence
immuable. Le code actif ajoute des vues de graines à rôle et taille fixes,
les tests d'échec partiel d'entropie au niveau des opérations et l'écriture
du message décapsulé dans son propriétaire final. Les nonces, domaines et
formats de R1 sont conservés. Le pont reconnaît la réalisation M09 et
conserve les contrats historiques jusqu'à M08.

Le chantier C01 produit un sous-lemme ROM classique de remplacement des
bruits expansés par des CBD frais avec perte rationnelle et matrice toujours
à graine publique : [argument M09](SECURITE_M09.md). Les 380 panneaux finis
et 512 transcripts adaptatifs vérifient le comptage ; ils ne prouvent pas
la sécurité globale du KEM. QROM, primitives concrètes et sécurité du PKE
à matrice semée restent ouverts.

L'optimisation des facteurs publics NTT a une comparaison isolée propre.
Les premiers gains KEM sont mesurés, mais le témoin multiply_add Linux
échoue au budget de médiane : cette variante n'est pas intégralement
acceptée. Le candidat complet, avec les nouveaux contrats, fait l'objet
d'une qualification distincte et de budgets mémoire fixés avant ses mesures.
Les preuves M08 ne deviennent pas des preuves ou du temps de fuzzing M09.
Le bilan définitif sera ajouté après les contrôles des images nouvelles.


### M09 — rejet de la première optimisation pour la livraison

La revue compilée a confirmé un nouveau résidu Windows dans le candidat
vectorisé `engine_poly.rs c22f53f5…` : e2+Encode(m) traverse XMM8 puis une
sauvegarde ABI de transform hors propriétaire effacé. Les images et
collections de `m09-final-001` restent figées. Les paquets préparés sont
marqués REJECTED_FOR_PROMOTION ; le binaire canonique demeure M08. Aucun
résidu ainsi observé ne démontre à lui seul une fuite du protocole.
Le gain de vitesse ne compense pas ce recul de durcissement. Une seconde
variante gardera les tables publiques en inhibant cette vectorisation,
avec nouveaux builds, revue et mesures. Les données001 ne sont pas réécrites.

Le premier check global a aussi détecté deux fixtures M08 qui copiaient
la source courante pour rejouer leur ancien modèle. Les fixtures lisent
maintenant la source de la capsule M08 elle-même ; ses données/contrôles
figés restent inchangés. Les douze tests ciblés passent. L'échec initial
et son reçu sont conservés sous m09-check-001 avant un nouveau check.


## M09 — candidat scalaire complet qualifié en interne

Le [bilan des cinq chantiers](M09_MOTEUR_CONTRATS_ET_QUALIFICATION.md) est
à jour. Les vues de graines, erreurs partielles d'entropie et propriétaires
secrets sont développés ; les formats et domaines restent R1. Le candidat
vectorisé001 est rejeté pour son résidu ABI Windows. Le scalaire002 supprime
le mécanisme ciblé dans quatre images propres, sans preuve globale d'effacement.

Le panneau final de 40 000 latences donne des réductions de médianes de
13,13 à 16,82 % selon opération/OS contre M08. Les budgets de latence/mémoire
passent, avec 216 observations de mémoire référence réutilisées et 216 nouvelles
pour le candidat. La frame transform augmente de 16 octets, alors que les
maxima KEM de pile peinte et les allocations demandées n'augmentent pas.
Le diagnostic temporel neuf de 32000 observations ne franchit pas 4,5
(maximum|t| 2,11069986 Windows / 1,11651668 Linux), sans preuve CT.

Chaque OS vérifie 1000 vecteurs, 10000 rejets, 10000 mutations et 20000 formats ;
les consommateurs par défaut passent 88576 sondes chacun. Le smoke ASan
à std reconstruite utilise les images M09 du build 002 dans la nouvelle
acquisition 003 : 194,64 s CPU, borne post-INIT 175,90 s, quatre budgets atteints,
1 046 348 exécutions après INITED répétitions comprises et aucun défaut observé.
Les incidents et reprises sont conservés, y compris le segment API limité
à l'initialisation et la correction de l'agrégation flottante. Aucun temps
antérieur n'est transféré, aucune couverture LLVM ou oracle du nouveau
corpus de fuzz n'est revendiqué.

Le sous-lemme ROM classique et la veille primaire de [SECURITE_M09](SECURITE_M09.md)
progressent sans fermer C01/QROM/Keccak concret. Deux paquets qualifiés en
interne et leurs répétitions sont disponibles ; les contrôles complets,
le gel principal et la CI neuve sont clos. Le dossier externe
est préparé ; aucun audit par un tiers ou déploiement Android/Messenger.


## Clôture locale M09 avant publication

La capsule moteur `results/engine/m09-001` est gelée et rejouée : 5618
membres, neuf groupes, provenance SHA-256
`0e785d177c8814d4cf0ae04696049dbe3d273620ed1d4a57c4bfb4819e064397`.
Le grand recueil des résultats rejetés est fractionné en deux parties ;
sa concaténation retrouve exactement l'archive originale et sa somme.
`m09-chunks-001` fige les adaptateurs de stockage, sans modifier les données
scientifiques, les images ou le manifeste moteur.

Le contrôle complet Windows réussit en 16 min 28 s : fmt, Clippy strict,
Rust par défaut/toutes fonctionnalités, 438 tests Python et tous les rejeux
requis. Les 279 entrées de sources/contrôles restent identiques avant/après.
`results/engine/m09-verification-001` conserve le reçu et le journal.
Un durcissement ultérieur du seul lecteur de stockage vérifie explicitement
les parties même si le tar complet est aussi présent ; quatre tests ciblés
et la suite entière de 439 tests Python passent. Ce suivi distinct est dans
`m09-reader-review-001`. Les 37 entrées compilables qualifiées sont inchangées.

Les deux paquets originaux sont qualifiés en interne, avec sources compactes
et licences. Le dossier externe est concret et prêt pour une remise, sans
contact tiers ni audit déclaré. La publication et la CI sont maintenant
closes dans leur périmètre d'intégration, détaillé ci-dessous.

## M09 — référence publiée et contrôle final

La [CI neuve 43806407492](https://github.com/MajidNIMAR/majax_mlkem1536/actions/runs/43806407492)
réussit sur Windows et Ubuntu au commit public `fdd323dcf840b0d12fd43a446acffbd0cce83d7b`,
exporté de la source locale `d616912fddd1e303c171678d0c6690286b570d38`.
Les **439 tests Python s'exécutent sur chaque OS, aucun n'est ignoré** ;
Rust par défaut/toutes fonctionnalités, fmt, Clippy strict, certificats et
rejeux requis passent. Chaque machine exécute les originaux M09 : 16
échanges/rejets et cinq refus normaux CLI ; 13 cas, un échange/rejet frais
et 88576 sondes pour le consommateur API par défaut.

Le reçu `results/publication/r6-m09-001` relie les journaux complets et
réponses API à 2138 blobs Git/fichiers exportés, aux 37 entrées compilables
du snapshot qualifié et aux empreintes originales. Le lecteur autonome
figé `r6-m09-controls-001` rejoue ce reçu hors ligne ; ses quatre tests
purs passent. La première CI verte `43804190038` conserve séparément un
test ignoré (`r6-m09-initial-001`) ; le collecteur strict l'avait refusée
pour une revendication de suite complète. La correction Python lit le
résultat négatif dans l'archive publique ; aucun code compilé, binaire ou
résultat scientifique ne change entre ces passages.

Après ce succès constaté, l'original Windows M09
`9eb95fb2cb9a8531a216012b4cff71d6b10d1a7951285d9d3c666f8186002255`
est copié vers `target/release/kem1536.exe`. Son empreinte reste exacte
avant/après le profil, 16 échanges/rejets frais et cinq refus normaux,
conservés dans `results/engine/m09-canonical-001`. Aucune reconstruction,
nouvelle mesure ou nouvelle campagne n'est attribuée à cette copie.

Les cinq chantiers M09 sont livrés dans le périmètre annoncé. Le moteur
R1 fonctionne et les améliorations sont mesurées ; **C01 complet, QROM,
primitives concrètes, temps constant/effacement universels et audit externe
restent ouverts**. Android et Messenger demeurent différés. Les futurs
commits de clôture documentaire conservent le code effectivement testé.

## M10 — quatre chantiers autorisés, résultats en cours

16 novembre2026. Le [protocole M10](PROTOCOLE_M10.md), commis1105e7f,
fixe avant modification les critères de l'argument exact, de la décision
des paramètres, du durcissement et de la qualification longue. La revue
extérieure reste différée. C01 et la sélection finale de R1 ne sont pas
déclarés clos par cette autorisation.

La capture de référence M09 conserve56 fichiers et le manifeste
`fea4458893be1e7f84e42d58da22c3740363a015103917fb0828603f902925ce` ;
ses douze builds nouveaux réussissent avec contrôles/source inchangés.
Les premières corrections concernent les dérivations et expansions
écrites dans leur propriétaire et la sélection finale du secret.
La revue étendue portera sur les nouvelles images, sans transférer
les conclusions ciblées des images historiques.

La [décision des paramètres](DECISION_PARAMETRES_M10.md) est préenregistrée
au commit c37e9f7 :40 jobs finis, modèle/coût/succès distingués, 300s par
job, sans réutiliser M05 comme calcul nouveau. Les témoins d'aplatissement
gardent la limite MLWE structuré/LWE indépendant et la RAM diagnostique
ne remplace pas une optimisation sous plafond non disponible.

La campagne longue ne commence qu'après validation et acceptation des
mesures/revues du candidat : quatre budgets nouveaux de1800s CPU après
INITED, sans crédit d'initialisation ou historique, avec couverture et
oracle indépendants du corpus récolté. Les observations et les limites
seront ajoutées au fil de leur acquisition.

### M10 — résultats acquis avant la clôture prolongée

La [revue du cycle secret](REVUE_CYCLE_SECRET_M10.md) conserve deux itérations
non promouvables : état SHAKE original laissé en pile (préexistant M09),
puis propriétaire local de sortie32 déplacé sans essuyage. La réalisation003
retire les deux mécanismes dans les quatre images examinées. Les corpus
complets Windows/Linux concordent ; le pont comporte78 ancrages, en plus
des branches historiques75/77 et antérieures. Ce n'est pas une preuve
universelle d'effacement ni de temps constant.

La comparaison M09→M10 comprend40000 latences et432 observations mémoire
nouvelles. Tous les budgets passent ; médianes−4,31 à+2,20%, maximum de pile
touchée Decaps−224 octets par OS et Encaps Windows+16 octets. Les allocations
demandées n'augmentent pas. Le diagnostic distinct de32000 observations a
max|t|1,74635/1,35509, zéro franchissement4,5. Les reconstructions CLI sont
Linux brut exact et Windows hors timestamp COFF/checksum PE, sur les mêmes
outils/hôte/caches ; aucune reproduction par tiers n'est revendiquée.

Le [volet sécurité M10](SECURITE_M10.md), scellé dans `results/security/m10-001`,
complète les simulations de matrice et de bruit, le raccord classique FO et
ses ressources ; il localise les obligations concrètes et quantiques encore
ouvertes. La [décision des paramètres](DECISION_PARAMETRES_M10.md) conserve
R1 pour le développement :40 calculs finis,20 paires favorables dans les
conventions précisées, sans niveau global ni optimum sous plafond RAM.
La sélection cryptographique finale et C01 restent ouverts.

Le candidat003 est accepté pour une nouvelle campagne longue par19preuves
liées au manifeste `67084be5ab1cde058661104b16e738138db7993dec001ac39625feb830b2810d`.
Les quatre harnais sont en cours, chacun devant atteindre1800 secondes CPU
conservatrices après INITED. Couverture, oracle du nouveau corpus, gel,
check complet et CI ne sont pas encore déclarés achevés à ce stade.
## M10 — couverture et oracle du corpus prolongé

Le post-traitement du 16 novembre 2026 conserve l'export LLVM complet,
les quatre objets et profils, puis leur union sans addition des panneaux
qui se recouvrent. L'union compte 492/669 lignes, 75/96 fonctions source,
907/1 155 régions et 18/38 branches couvertes dans les cinq fichiers du
cœur cartographiés. `dev_kem.rs` compte 384/417 lignes et 14/20 branches.
Les fonctions et côtés de branche à zéro restent présents. La couverture
utilise des objets ASan distincts et la bibliothèque standard distribuée ;
elle ne mesure pas les objets à std reconstruite de la campagne longue.

Les 3 968 fichiers des quatre corpus, dédupliqués séparément par harnais,
produisent 4 263 requêtes déterministes distinctes. Toutes les sorties du
binaire Rust Linux concordent avec l'oracle Python/NumPy 2.3.5 : 641 imports
de clés privées acceptées comprennent une sonde indépendante de
décapsulation, et 16 rechiffrements sont acceptés. Les 1 887 opérations à
aléa frais encodées dans ce corpus ne sont pas recréées par l'oracle.
Le transcript compressé et son empreinte sont conservés. Ces vérifications
ne démontrent ni temps constant, ni couverture complète, ni sécurité C01.

## M10 — contrôle local complet et scellement du reçu

Le 16 novembre 2026, le contrôle complet `scripts/dev.ps1 check` se termine
avec une sortie 0. Rust, formatage, Clippy, les 514 tests Python (aucun
ignoré), tous les rejouages et les essais natifs de fin passent. Les 313
entrées de source et de contrôle suivies sont identiques avant/après.
Le reçu [m10-verification-001](../results/engine/m10-verification-001/)
lie le journal complet, le contrôleur réutilisé et la provenance des
10 908 membres moteur. Le sceau vérifie également les 37 entrées compilables
de la capture retenue : 31 appartiennent au suivi avant/après, les six
fichiers des consommateurs/sondes autonomes sont contrôlés au scellement.
Ces deux portées restent distinctes. Aucun temps de fuzzing supplémentaire
n'est crédité par ce contrôle. La CI neuve et la promotion attendent leurs
propres résultats ; C01 et la sélection cryptographique finale restent ouverts.

## M10 — premier passage CI et portabilité des fixtures

La CI 43889980583 du commit public `b96b548` échoue sur Windows et Ubuntu :
les 514 tests sont collectés, avec deux erreurs. Deux fixtures supposaient
à tort la présence préalable du dossier ignoré `artifacts/generated`.
Le [recueil initial](../results/publication/r6-m10-initial-001/) conserve les
API, les journaux complets et l'analyse des deux erreurs. Aucun succès de
CI complète n'est attribué à ce passage.

La correction ajoute seulement la création du parent de travail dans les
deux tests concernés. Les contrôles d'appartenance restent identiques.
Le moteur, les onze contrôleurs d'acquisition, les 37 entrées compilables,
les images et les données scientifiques restent inchangés. Une vérification
sur deux racines temporaires sans ce parent, puis une nouvelle suite Python
et une nouvelle CI sont exigées. Le contrôle local complet antérieur est
conservé dans sa portée temporelle ; il n'est pas présenté comme une nouvelle
exécution des fixtures corrigées.

Le [suivi des fixtures](../results/engine/m10-ci-fixtures-001/) passe : les
deux cas réussissent dans deux racines isolées sans parent préalable, puis
les 514 tests Python passent sans ignoré. Les 313 entrées suivies restent
identiques avant/après ; le dossier réel et le recueil d'échec sont préservés.
Le prochain passage CI porte sur cette correction des tests, sans nouveau
build de qualification, nouvelle campagne ou modification du moteur.

## M10 — CI complète et binaire local promu

La [CI 43893183494](https://github.com/MajidNIMAR/majax_mlkem1536/actions/runs/43893183494)
du commit public `82c63441d1885c1e348884a2d9442ee48b6eaf03` passe sur
Windows et Ubuntu. Le [collecteur strict](../results/publication/r6-m10-001/)
vérifie 514 tests Python `OK` sans ignoré par OS, les contrôles complets et
les essais natifs des originaux M10. Les 37 entrées compilables sont égales
au source qualifié. Les doubles cartes contrôlent 2 360 fichiers exportés
et leurs blobs Git. Il s'agit d'une nouvelle CI, sans crédit de fuzzing ajouté.

Le [reçu canonique 002](../results/engine/m10-canonical-002/) constate la
copie de l'original Windows vers `target/release/kem1536.exe`, SHA-256
`2d6aa2e5859ea1df7774e5dd1cbb35827c8e9e1feddbe9f1f72a80c1661d5468`.
Profil exact, 16 échanges/rejets et cinq commandes de recherche refusées
passent après copie. Le binaire n'est pas recompilé pour cette promotion.

La [première tentative](../results/engine/m10-canonical-001/) avait été
annulée : son helper attendait deux objets JSON alors que `dev-profile`
en émet un. L'original M09 avait été restauré. Le nouveau helper accepte
exactement le profil réel et rejette trois cadres/affirmations erronés.
Ce correctif ne modifie pas le moteur. Un autre contrôle de clôture a refusé
la copie de contrôleurs locaux CRLF au lieu des blobs LF effectivement
testés ; le [constat](../results/publication/r6-m10-freeze-initial-001/)
reste conservé. Le gel du lecteur doit prendre les blobs publics exacts,
sans normalisation supposée équivalente.

Le [lecteur figé final](../results/publication/r6-m10-controls-001/) prend
effectivement ses 50 fichiers Python depuis les blobs publics testés, pour
l'AST et pour les octets copiés. Quatre tests purs sans ignoré et le rejeu
hors ligne du reçu CI passent. Les 63 membres et leur provenance sont
inventoriés ; le premier écart CRLF/LF reste relié au résultat final.
Le moteur, les images et tous les contrôleurs testés restent inchangés.
Cette clôture conserve les incidents d'outillage au lieu de les transformer
en nouvelles acquisitions ou en défauts du moteur. Le rapport, le journal,
le guide, le README et la description GitHub sont actualisés pour M10.

