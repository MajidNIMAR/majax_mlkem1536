# M03 — Fuzzing, binaires et benchmarks P01

25 octobre 2026. Protocole initial 9a226ae, précision du budget CPU et
état de préparation au commit fa87197. Profil R1 inchangé.

## Benchmarks exécutés

CPU AMD Ryzen 7 2700, huit cœurs/seize processeurs logiques, Windows et
Linux x86-64/WSL2 Ubuntu 22.04 sur le même hôte. Rust 1.91.1, release,
sans sanitizer ni couverture. Affinité logique 0 dans chaque système ;
la correspondance entre CPU Windows et vCPU WSL n'est pas démontrée.
La fréquence n'est pas verrouillée ; le plan d'alimentation est enregistré.

Cinq séries de 1000 observations par fonction et moteur, précédées
chacune de 100 échauffements. Ordre des moteurs alterné par série,
30000 observations par système, 60000 au total, sans suppression de valeur.
Les échanges sont validés hors chronométrage. Les interfaces KeyGen et
Encaps incluent l'aléa système. La destruction des sorties est exclue
de la mesure, pour les deux moteurs. Les autres campagnes lourdes de ce
travail étaient arrêtées pendant les mesures.

| Système | Moteur | Fonction | Médiane (ms) | p95 (ms) |
|---|---|---|---:|---:|
| Windows | R1 | KeyGen | 1,987300 | 2,215300 |
| Windows | R1 | Encaps | 2,167600 | 2,583100 |
| Windows | R1 | Decaps | 2,543700 | 2,883100 |
| Windows | ML-KEM-1024 | KeyGen | 0,080800 | 0,098200 |
| Windows | ML-KEM-1024 | Encaps | 0,078500 | 0,117500 |
| Windows | ML-KEM-1024 | Decaps | 0,092500 | 0,135800 |
| Linux/WSL | R1 | KeyGen | 2,033402 | 2,425789 |
| Linux/WSL | R1 | Encaps | 2,401786 | 2,849590 |
| Linux/WSL | R1 | Decaps | 2,772427 | 3,199554 |
| Linux/WSL | ML-KEM-1024 | KeyGen | 0,082051 | 0,103266 |
| Linux/WSL | ML-KEM-1024 | Encaps | 0,078887 | 0,100056 |
| Linux/WSL | ML-KEM-1024 | Decaps | 0,092605 | 0,119278 |

Chaque cellule agrège 5000 observations ; p95 par rang le plus proche
supérieur `ceil(0.95*N)`. Les séries séparées et les durées individuelles
sont conservées, sans choix d'une série favorable. R1 est plus lent
dans ces réalisations. La comparaison porte sur deux profils différents
et deux niveaux d'optimisation : convolution directe de rang 6 pour R1,
NTT de rang 4 pour RustCrypto ml-kem 0.3.3. Elle ne mesure pas le seul
effet du rang, ni un coût intrinsèque de sécurité.

Les pics processus sont relevés séparément sur 1000 parcours complets :
5496832 octets de pic Working Set Windows pour chacun des deux moteurs,
2048 Kio de pic RSS Linux pour chacun. Sous Windows le processus attend
après le calcul, permettant d'interroger le pic avant sa terminaison.
Les définitions des deux OS diffèrent. Ces valeurs identiques et grossières
incluent exécutable, runtime, allocateur et harnais ; elles n'établissent
pas l'égalité de la mémoire propre des algorithmes.

| Format | R1 | ML-KEM-1024 |
|---|---:|---:|
| Clé publique (octets) | 2528 | 1568 |
| Clé privée développée (octets) | 5088 | 3168 |
| Graine de clé privée standard exportable | Pas de format de graine applicatif | 64 octets |
| Chiffré (octets) | 2656 | 1568 |
| Secret partagé (octets) | 32 | 32 |

Les objets internes du témoin ne sont pas décrits par la seule taille du
format développé. Aucun seuil de passage de performance n'est adopté
après mesure. Ces nombres constituent la référence mesurée avant une
future optimisation, à comparer sur le même matériel et le même périmètre.

Pour la prochaine étape, le budget de suivi proposé sur cet hôte est un
p95 de 3 ms pour KeyGen, 3,5 ms pour Encaps et 4 ms pour Decaps, avec le
même périmètre de chronométrage et sans instrumentation. Il sert à mesurer
une éventuelle régression des prochaines modifications ; ce n'est ni un
seuil appliqué rétroactivement à M03, ni une exigence finale sur un matériel
cible encore non choisi. Un écart futur devra être expliqué, en particulier
si une correction mémoire change les allocations.

## Inspection des exécutables

Désassemblage intégral GNU objdump 2.38, en-têtes, symboles, sections,
dépendances et exécutables compressés conservés. Les décomptes sont ceux
des fonctions délimitées par les symboles retenus dans ces fichiers.

| Inventaire | Windows | Linux |
|---|---:|---:|
| Fonctions repérées dans tout le code | 3628 | 996 |
| Instructions désassemblées | 286563 | 147648 |
| Fonctions repérées portant les noms R1 | 26 | 16 |
| Instructions dans ces fonctions R1 | 9807 | 9265 |
| Branchements conditionnels dans ces fonctions | 429 | 420 |
| Divisions entières dans ces fonctions | 0 | 0 |

La différence de symboles ne signifie pas l'absence d'une opération sous
Linux : l'inlining et l'organisation du code changent selon les cibles.
L'analyse Linux résout les relocalisations ELF de la GOT : 3899 transferts
indirects ont une cible repérée dans l'ensemble du binaire, et la fermeture
des appels des fonctions R1 repérées couvre 125 fonctions, contre 32
avant cette résolution. **118 transferts indirects dans les fonctions R1
restent non résolus par cette analyse statique**, notamment via registres.
La fermeture n'est donc pas une preuve d'exhaustivité du graphe dynamique.

Les cinq divisions de la fermeture large Windows repérée appartiennent
aux conversions du compteur de performance et à Instant, dans le chemin
de diagnostic. Ce constat ne doit pas être présenté comme cinq divisions
sur les coefficients secrets. Les bibliothèques système ne sont pas
désassemblées dans cet inventaire.

Les en-têtes Windows portent DYNAMIC_BASE, HIGH_ENTROPY_VA et NX_COMPAT.
Linux porte PIE, GNU_RELRO, BIND_NOW et une pile GNU_STACK RW, sans drapeau
exécutable. Ces propriétés des fichiers ne garantissent pas la politique
effective de chaque environnement d'exécution.

## Revue des chemins cryptographiques et constat ouvert

La multiplication Windows examinée conserve ses six branchements sur
les compteurs publics et le signe négacyclique i+j. La correction de
résidu emploie mul/imul et cmovs sur registres. Les adresses de coefficients
dépendent des compteurs publics. Dans Decaps Windows, la comparaison du
chiffré parcourt les 332 mots de huit octets ; la sélection finale observée
utilise des cmov sur registres. Les boucles d'effacement sont conservées
dans l'assembleur. La génération uniforme est à rejet et dépend de rho,
qui appartient à la clé publique ; elle n'est pas une boucle à durée fixe.

**M03-A01 — Copie temporaire du résultat polynomial sur pile.** Dans
Polynomial::multiply du binaire Windows, une zone résultat de 512 octets
est remplie à rsp+0x20, copiée vers la destination par memcpy, puis la
boucle d'effacement traite les accumulateurs à partir de rsp+0x220.
L'épilogue observé n'efface pas explicitement la zone résultat temporaire
avant de restituer la pile. Cela concrétise la limite déjà documentée de
zeroize vis-à-vis des copies introduites lors des déplacements d'objets.
Les adresses et instructions complètes sont conservées dans le
désassemblage ; aucune lecture de mémoire libérée n'a été effectuée.

Ce constat est une limite de durcissement mémoire, sans fuite exploitable
par le protocole démontrée ici. Une persistance effective et une méthode
de correction doivent encore être qualifiées. Une représentation à
destination stable ou une écriture directe peut être étudiée ; elle devra
être évaluée face au surcoût d'allocations et aux contraintes d'API.
Le moteur n'a pas été modifié pour masquer le constat ou changer les
paramètres pendant cette campagne. La disparition de toutes les copies
secrètes et la validation globale T08 ne sont pas revendiquées.

Les autres branchements, les cibles indirectes non résolues, le code des
bibliothèques système et les effets microarchitecturaux restent des
limites de la revue. Un inventaire automatique intégral et ces vérifications
ciblées ne constituent pas une preuve exhaustive de temps constant ou un
audit indépendant de chaque instruction du programme et de son environnement.

## Fuzzing et suivi

Quatre cibles LLVM/libFuzzer 0.4.13 via cargo-fuzz 0.13.1, Rust 1.91.1,
ASan et bibliothèque standard recompilée. Fixtures publiques de seize clés,
imports bruts, décapsulation, copies et séquences d'API, y compris KeyGen
et échanges avec aléa système. Les graines du mutateur sont fixées ; les
opérations à aléa frais ne sont pas reproduites par la seule graine libFuzzer.

Le premier test court a réussi : 84,23 secondes CPU cumulées, sans erreur
signalée. Le second passage a réussi sur les harnais finaux : 85,01 s CPU,
couverture exportée pour les quatre cibles et 511 requêtes déterministes
du corpus retenu confrontées exactement entre Rust et Python.
Le rejeu utilise l'exécutable Rust Windows sur les entrées retenues par
les harnais Linux et l'oracle Python gelé ; il ne réexporte pas toutes
les sorties du binaire Linux. Les seize
acceptations de l'oracle sur les requêtes de chiffrés incluent les chiffrés
honnêtes ; aucun principe de rejet automatique de toute mutation n'est utilisé.
Les 51 opérations à aléa frais du corpus de séquences sont contrôlées par
les invariants du harnais, sans être reproduites par la seule graine.

L'export LLVM du test court donne, pour la cible de séquences d'API :

| Fichier du cœur | Lignes couvertes / retenues | Pourcentage |
|---|---:|---:|
| dev_kem.rs | 276 / 311 | 88,75 % |
| engine_poly.rs | 53 / 53 | 100 % |
| secret_box.rs | 15 / 15 | 100 % |

Pour dev_kem.rs, 44 des 46 fonctions retenues sont exercées. Ces nombres
sont ceux du corpus court rejoué, par fichier et par cible ; les métriques
de plusieurs cibles ne sont pas additionnées comme des couvertures
indépendantes. Les modules de métadonnées P0 et l'oracle générique ne sont
pas exercés par cette cible. Les branches d'erreur et le diagnostic
requièrent d'autres contrôles. La méthode distingue le guidage des mutations
et l'[export de couverture des sources](https://rust-fuzz.github.io/book/cargo-fuzz/coverage.html).

La campagne prolongée a démarré le 25 octobre 2026 à 16 h 01, heure de Paris,
à partir des sources enregistrées au commit 8ef4ceb. Les quatre travailleurs
sont suivis dans `artifacts/generated/m03-long-001/progress.json` et les
informations de lancement dans `artifacts/generated/m03-launch.json`.
Elle n'est pas encore déclarée terminée. Objectif : six heures CPU par cible, quatre cibles, au moins
24 heures CPU cumulées ; le temps mural et les interruptions sont mesurés
séparément. Les compteurs LLVM de fuzzing ne sont pas un pourcentage de
couverture des lignes : cette dernière est exportée séparément.

Le contrôleur conserve ses exécutables et sources au lancement, segmente
les essais, écrit progress.json, et archive les preuves à la fin. Il prévoit
le rejeu indépendant des entrées déterministes via l'oracle Python M01 et
l'exécutable de test Rust, puis un bilan automatique dans le rapport et le
journal. Toute erreur est conservée et arrête les travailleurs ; aucune
durée ou réussite finale n'est anticipée. La machine doit rester en service
pendant la campagne. Un fichier STOP dans le dossier de campagne permet
de l'interrompre avec conservation des données.

J2/J3/J4 restent ouverts. P01 documente des mesures ; T07 exige encore la
durée et la revue des données finales. Le constat M03-A01 reste ouvert.
