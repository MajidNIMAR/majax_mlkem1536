# M07 — Mémoire du moteur et validation de la variante streamée

11 novembre 2026. **Jalon mémoire et livraison clôturé : implémentation,
mesures, revue bornée, campagne instrumentée, paquets et contrôles complets
Windows/Ubuntu réussis dans le périmètre décrit.** Le moteur
reste le profil `KEM1536-DEV-Q7681-R1`.

## Référence, décision et code

La méthode est consignée dans [le protocole](PROTOCOLE_M07_MEMOIRE.md), au
commit local `6756500`. Les [budgets](DECISION_M07_BUDGETS.md) sont fixés
après la référence et avant candidat, au commit `b96941b`. Le candidat
mesuré `dev_kem.rs` a pour SHA-256
`3b7594bf96b6dcf3a52001582f8ab832da774ed059db66999e0e5091c8c8d48b`.
L'arithmétique `engine_poly.rs`, les paramètres, domaines et formats sont
inchangés ; les comptes NTT restent 48/55/68.

Le changement conserve les six opérandes transformés, mais traite chaque
polynôme en coefficients dans des propriétaires réutilisés. KeyGen écrit
chaque secret encodé directement dans le propriétaire privé déjà alloué.
Les lignes publiques et les lignes de ciphertext sont encodées au fur et
à mesure. Le déchiffrement décode une paire de lignes à la fois. L'import
privé vérifie la clé publique embarquée sans construire un Box public
intermédiaire. L'ordre longueur/canonicalité secrète/canonicalité publique/
hash est conservé, avec balayage source complet avant décision.

## Profondeur de pile touchée

Les deux versions et les deux hôtes produisent **2240 observations**, dont
les contrôles et calibrations : 14 cas × deux motifs × 20 répétitions ×
deux versions × deux hôtes. Le tableau donne les **maxima observés** parmi
40 observations par cas/version/hôte.

| Hôte | Opération | M06, octets | M07, octets | Réduction du maximum observé |
|---|---|---:|---:|---:|
| windows | KeyGen | 13392 | 8144 | 39.19 % |
| windows | Encaps | 14808 | 7672 | 48.19 % |
| windows | Decaps valide | 23688 | 13064 | 44.85 % |
| windows | Decaps rejetée | 23688 | 13064 | 44.85 % |
| linux | KeyGen | 12824 | 7208 | 43.79 % |
| linux | Encaps | 14536 | 7400 | 49.09 % |
| linux | Decaps valide | 23336 | 12696 | 45.59 % |
| linux | Decaps rejetée | 23336 | 12696 | 45.59 % |

Ce sont des profondeurs touchées dans le harnais natif instrumenté, **pas
un maximum universel de RSP ni le pic du CLI livré**. La marge supérieure
de 512 octets n'est pas peinte ; zéro signifie aucune modification détectée
dans la zone observée. Les motifs peuvent coïncider avec une écriture.
Les calibrations écrivent 8/32/64 Kio et sont vérifiées à chaque observation.
Les entrées de décapsulation et d'import sont fixes au sein du processus,
fraîches et indépendantes entre processus ; les répétitions ne constituent
pas autant de clés différentes. KeyGen et Encaps utilisent l'aléa système.

Les allocations visibles sont les requêtes de Rust GlobalAlloc dans ce
binaire, avec instrumentation qui ajoute elle-même du travail de pile.
Les sorties sont validées et détruites après la fenêtre. Ni métadonnées
natives de l'allocateur, ni allocations système, ni mémoire des entrées
préparées ne sont prises pour la mémoire propre du seul appel.

Les opérations principales ne demandent aucun tas supplémentaire par rapport à M06 :
KeyGen 2 allocations/7616 octets retenus ; Encaps 1/2656 ; Decaps 0. L'import
privé valide passe de 2 à 1 allocation et de 7616 à 5088 octets demandés vivants
au maximum. Les sorties privées retenues restent 5088 octets. Sur erreur
de hash privé, l'allocation publique temporaire disparaît aussi. Les pics
de tas et de pile ne sont pas additionnés en un faux pic simultané.

## Latence comparative

Le panel final contient **80000 observations** : 40000 par hôte, cinq
séries alternées, 1000 observations par opération/version/série. Les 100
échauffements, la validation et la destruction des résultats sont hors
chronomètre. La référence préliminaire de 8000 observations est distincte.
Les observations extrêmes sont toutes conservées. CPU logique 10, sans
fréquence fixée ni isolation globale de l'hôte.

| Hôte | Opération | Médiane M06, µs | Médiane M07, µs | Rapport médian M07/M06 | Rapport p95 |
|---|---|---:|---:|---:|---:|
| windows | keygen | 491.100 | 499.900 | 1.017919 | 1.087399 |
| windows | encaps | 542.000 | 540.400 | 0.997048 | 1.052584 |
| windows | decaps_valid | 668.600 | 665.100 | 0.994765 | 1.025974 |
| windows | decaps_rejected | 668.500 | 665.000 | 0.994764 | 1.032702 |
| linux | keygen | 505.921 | 502.546 | 0.993330 | 0.943712 |
| linux | encaps | 558.890 | 554.525 | 0.992191 | 0.876723 |
| linux | decaps_valid | 684.409 | 684.912 | 1.000734 | 0.988469 |
| linux | decaps_rejected | 685.208 | 684.695 | 0.999251 | 0.984650 |

Tous les rapports satisfont les budgets 1,10 médiane/1,20 p95. Il n'y a pas
de gain uniforme : KeyGen Windows augmente de 1,8 % en médiane et de 8,7 %
au p95 dans ce panel. Les autres médianes sont proches de la référence.
Ces rapports sont descriptifs de cette exécution, sans conclusion de
significativité ni facteur universel de performance.

## Compatibilité et preuves

Les binaires de recherche Windows/Linux retrouvent intégralement les
sorties figées : 1000 vecteurs, 10000 rejets, 10000 mutations et 20000 formats par
hôte. Cela compare les mêmes octets anciennement vérifiés indépendamment ;
ce n'est pas une nouvelle simulation d'échec rare en Python. La régression
lie les empreintes des deux exécutables et les sources de contrôle.

Le vérificateur M07 recalcule les sources, les 94 fichiers liés par la
référence, les grilles mémoire, les latences depuis les stdout originaux,
les statistiques, budgets et reçus de régression : **116 contrôles de budget
sur 116 satisfaits**. Il distingue données invalides et candidat hors budget.
Le pont certificat/programme reconnaît 35 ancrages M07 et conserve les
réalisations historiques ; ce n'est pas une vérification formelle complète.

Un diagnostic distinct utilise huit clés fraîches et cinq classes de
ciphertext : 16000 observations par hôte. Aucun des 32 contrastes par hôte
ne franchit |t|=4,5 : maximum 1,393 Windows et 3,164 Linux. Tous les extrêmes
restent présents. L'exécutable du diagnostic a son empreinte propre ; le
résultat ne prouve pas le temps constant du CLI ou de tous les chemins.

Les observations brutes, contrôleurs et constructions sont conservés dans
l'[archive M07](../results/engine/m07-001/). Le premier
flux Linux fusionné a échoué à la lecture JSON ; il n'a pas été conservé
par l'ancien contrôleur. La deuxième acquisition mémoire complète est
conservée et validée ; les flux sont désormais séparés et sauvés avant
analyse. Cette correction d'acquisition ne change pas le code du probe.

## Campagne instrumentée propre à M07

Les quatre harnais sont reconstruits avec ASan et la bibliothèque standard
Rust reconstruite, Rust 1.91.1 et cargo-fuzz 0.13.1. Le budget déclaré est
60 secondes CPU par harnais, sur CPU logique 10, avec segments supplémentaires
pour atteindre le temps CPU malgré les pauses et entrées-sorties. Les onze
segments totalisent **248,73 secondes CPU**, sans défaut observé. Le build
conserve les empreintes des exécutables, des rlib std, des sources et contrôleurs.

| Harnais | Secondes CPU nouvelles | Exécutions après INITED |
|---|---:|---:|
| import_public | 60,60 | 1023662 |
| import_private | 63,54 | 75985 |
| decapsulate | 63,27 | 14503 |
| api_sequence | 61,32 | 1138 |

Ces compteurs incluent des exécutions répétées et ne comptent pas des entrées
mutées uniques. Chaque harnais a une activité après INITED. Il ne s'agit ni
d'une campagne longue ni d'une mesure de couverture source LLVM. Le nouveau
corpus fuzz n'a pas été rejoué contre l'oracle indépendant ; le contrôle des
corpus figés complets décrit plus haut est une expérience distincte. Aucun
temps CPU historique M03/M04/M06 n'est crédité. Le contrôleur archivé garde
les octets employés au lancement ; l'évolution ultérieure de son routage CLI
autorise seulement le rejeu en lecture seule depuis une archive sous results.

## Limite observée à l'import privé

Le traçage assembleur des binaires de recherche Windows et Linux trouve des
bits de coefficients encodés, avant réduction, dans des spills de pile hors
du propriétaire effacé. Sur le chemin d'erreur de canonicalité secrète,
certains emplacements ne sont pas explicitement effacés avant retour. La
référence M06 recompilée présente déjà cette limite sur ces mêmes chemins :
ce n'est pas une régression introduite par M07. Quand la partie secrète est
valide, la validation publique suivante réutilise les cadres examinés et
réécrit ces emplacements par du public avant succès ou erreur publique/hash.

Cette observation ne démontre pas de fuite distante ou pratique. Elle interdit
de revendiquer l'effacement de tous les temporaires du compilateur, registres
ou chemins d'erreur. Les adresses, cadres, empreintes et limites sont conservés
dans la revue bornée. Les contrôles d'owners ne prouvent pas l'effacement global.

## Livraison et archivage

La revue des quatre binaires originaux est scellée et son reçu se rejoue :
73 membres vérifiés, deux références M06 et six témoins de spill. Les imports
absents du CLI Linux livré ne sont pas couverts par une preuve de leur forme
machine.

Une nouvelle compilation du CLI par hôte reprend le même chemin source,
Rust 1.91.1 et les caches d'outils/dépendances partagés, dans des cibles
distinctes. Linux est identique en octets bruts. Windows diffère seulement
dans TimeDateStamp COFF et CheckSum PE, neutralisés uniquement dans des copies
de comparaison ; les exécutables bruts sont conservés. Il ne s'agit pas
d'une reproduction indépendante par un tiers ou sur machine neuve.

Les ZIP Windows et tar.gz Linux livrent les **premiers originaux revus**,
pas les secondes compilations. Les deux originaux et les deux répétitions
réussissent chacun 16 échanges et 16 rejets, sans afficher les secrets.
Les commandes de recherche sont refusées. Les imports natifs et dépendances
compilées sont inventoriés, les licences rattachées et la source compacte
inclut les 40 entrées mesurées. Les dépendances Cargo sont obtenues
séparément : reconstruire sur une machine neuve demande le registre
ou des caches correspondants.

| Paquet | SHA-256 |
|---|---|
| majax-r6-m07-x86_64-pc-windows-gnu.zip | `fa0e1947149b45af857f041ca53de4c4fe25a9f67cb795134fc46da971aa18b3` |
| majax-r6-m07-x86_64-unknown-linux-gnu.tar.gz | `ebf5c99aa0a8c79edea9d937a806ae94a881e0f568fcd7651155fdbb3f9b389d` |

L'archive compacte versionnée conserve les quatre étapes complètes dans
`measurements.tar.gz`, `binary.tar.gz`, `fuzz.tar.gz` et `delivery.tar.gz`,
plus les contrôles Python. Les inventaires relient tous les octets, sources,
binaires, flux bruts et reçus. Les répertoires vides de défauts sont préservés.
La chaîne revue → collection → binaires est vérifiée, sans rechercher une
empreinte au mauvais niveau du manifeste. Le premier précontrôle de packaging
a refusé cette incohérence de format avant tout build ; le raccord a été
corrigé et testé sur les vrais reçus avant relance.

```powershell
python research/archive_m07.py verify --output results/engine/m07-001
```

Le rejeu extrait uniquement les données dans un répertoire temporaire sous
`target`, recalcule les tableaux et les contrôles, puis retire ce temporaire.
Il ne lance ni compilateur, ni exécutable, ni nouvel objdump ou fuzzing.
Le gel et son premier rejeu passent. La tâche `check` Windows/Linux intègre
ce vérificateur. Le [contrôle complet Windows](../results/engine/m07-verification-001/)
passe : 227 tests Python, Rust avec/sans toutes fonctionnalités, formatage,
Clippy strict, rejeux et auto-tests. Les fichiers restent identiques entre
le début et la fin du contrôle. Le CLI habituel `target/release/kem1536.exe`
est remplacé par l'original Windows revu, avec empreinte et auto-test conservés.
Le passage sur les exécutants GitHub neufs Windows/Ubuntu réussit au
[run 42936652940](https://github.com/MajidNIMAR/majax_mlkem1536/actions/runs/42936652940),
HEAD public `97d776c`, source locale `c7e34d3`. Chaque hôte passe 227 tests
Python, les tests Rust avec et sans toutes fonctionnalités, fmt, Clippy strict,
les vérificateurs et les auto-tests. Après le check complet, chaque hôte
exécute aussi l'original de son paquet, sans reconstruction : 16 échanges,
16 rejets et cinq refus normaux (code 1) de commandes de recherche.

L'[archive de publication](../results/publication/r6-m07-001/) lie les deux
jobs au run/HEAD exacts, conserve les journaux bruts, la provenance committée
et la vérification indépendante des 1932 fichiers exportés/blobs canoniques.
Les étapes ignorées sont celles de l'autre système. Les répétitions de lignes
de tests dans les journaux globaux et par étape ne sont pas des campagnes
supplémentaires. Les données historiques sont rejouées ; les essais natifs
de paquets sont frais. La clôture documentaire conserve les sources exécutables,
contrôles et archives scientifiques du commit testé.
Aucune clôture de C01, preuve globale d'effacement, CT ou audit externe n'est annoncée.
