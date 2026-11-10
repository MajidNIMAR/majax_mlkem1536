# M04 — Comparaison exécutée des deux dépôts

25 octobre 2026. Cette étape compare les APIs réelles du premier projet
`MajidNIMAR/majax-mlkem1024-demo` au moteur R1, puis une révision R1 avec NTT
scalaire à sa réalisation scolaire antérieure. Elle complète la
[comparaison des modèles d'attaque](COMPARAISON_ATTAQUES_CADRE_COMMUN_R1.md) :
la vitesse observée n'est pas une mesure de résistance cryptanalytique.

## Réalisations et périmètre

Le premier dépôt est figé au commit
[`3dd7c91b5ec9777fd1afc09db198d00dc0deca88`](https://github.com/MajidNIMAR/majax-mlkem1024-demo/tree/3dd7c91b5ec9777fd1afc09db198d00dc0deca88).
Le comparatif emploie sa bibliothèque `majax-mlkem`, son backend
`pqcrypto-mlkem=0.1.1` et ses APIs publiques normales. Les 29 versions et
empreintes de ses paquets registre sont conservées dans le verrou commun.

R1 est capturé depuis le workspace courant, avec l'empreinte de chaque
source. Le commit de base seul ne suffirait pas à identifier les changements
en cours. La capture NTT employée est dans
`artifacts/generated/m04-pair/ntt-001/sources/NIST/`. La capture scolaire
en dérive : **seuls** `dev_kem.rs` et `engine_poly.rs` sont remplacés par les
sources M02 de `results/engine/hardening-001/sources/`, vérifiées contre les
empreintes `a21bb340…` et `e16599a7…`. Le même pilote, les mêmes dépendances,
le reste des sources et les paramètres sont conservés.

| Propriété | Premier dépôt, ML-KEM-1024 | R1 |
|---|---|---|
| Cœur | PQClean, C portable ou AVX2 sur x86-64 | Rust scalaire, arithmétique identifiée par la capture |
| Construction | Jeu de paramètres ML-KEM-1024 | `KEM1536-DEV-Q7681-R1`, six polynômes, q=7681 |
| Clé publique | 1568 octets | 2528 octets |
| Clé privée développée | 3168 octets | 5088 octets |
| Chiffré | 1568 octets | 2656 octets |
| Secret partagé | 32 octets | 32 octets |
| Représentation de l'API mesurée | Tranches d'octets, import/copie internes à l'appel | Clés typées déjà validées avant l'appel |
| Aléa KeyGen/Encaps | Chemin normal de l'API et du backend | Aléa système du moteur |

Ce sont les coûts des **APIs de bibliothèque disponibles**, pas ceux d'un
cœur mathématique auquel on aurait retiré les imports et allocations. Les
différences de formats, de validation, de rang et de code restent parties
intégrantes de la comparaison. Le backend RustCrypto de M03 n'est pas utilisé
comme substitut du premier dépôt.

## Protocole commun

Le workspace autonome [`comparisons/engine-pair`](../comparisons/engine-pair/README.md)
relie les deux bibliothèques dans un même processus. Il possède son propre
`Cargo.lock` et ne modifie ni le workspace principal ni son pin Rust 1.91.1.
La comparaison utilise **Rust 1.93.0 pour les deux bibliothèques**, GCC 11.4
pour le backend C, `opt-level=3`, `codegen-units=1`, LTO thin, panic abort et
la cible Rust de base `x86-64`. Les appels C AVX2 du premier dépôt restent
sélectionnés par son propre répartiteur lorsque la fonctionnalité `native`
est activée. La seconde construction désactive cette fonctionnalité et
emploie le backend C portable.

Les captures indiquent la relation du verrou commun avec le verrou complet
de R1. Ce dernier contient aussi des outils et témoins absents du comparatif.
Les changements de versions transitives partagées ne sont donc pas cachés ;
le résultat concerne les binaires explicitement construits ici, et ne
réétiquette aucun ancien binaire de production.

Le moteur R1 NTT et le moteur scolaire sont mesurés chacun en paire avec
le premier dépôt, en modes `native` et `portable`. Les deux fichiers de moteur
remplacés incluent la réalisation de la multiplication et ses appels : le
gain mesure cette révision du moteur, sans isoler causalement chaque
optimisation de la NTT ou du traitement des temporaires.

La configuration de mesure autorisée est de **cinq séries, cinquante
préchauffages puis deux cents observations** par opération, par moteur et
par série. Elle produit 6000 observations par processus, donc **24000** pour
les quatre processus du comparatif complet. À chaque série, les moteurs
alternent leur ordre, et l'ordre des opérations est également inversé d'une
série à la suivante.

La préparation de clés/chiffrés de référence, la validation de chaque
échange et la destruction par le pilote des objets retournés sont hors du
chronomètre. Le travail interne de chaque API — dont ses conversions,
allocations et destructions internes — reste inclus. KeyGen et Encaps
traversent leur chemin normal d'aléa. Les interfaces déterministes restent
désactivées. Toutes les sorties JSON sont publiques : tailles, identifiants,
durées et statistiques, sans clé, graine, message ou secret partagé exporté.

Chaque processus est fixé au CPU logique WSL 10. Le modèle du processeur,
l'affinité autorisée, la charge moyenne, les noms/PID/consommations CPU des
processus et l'état des travailleurs de fuzzing sont conservés avant et après
chaque exécution. Les lignes de commande complètes et l'environnement ne sont
pas exportés.

**La machine est chargée.** La campagne M03 précédente continue sur les CPU
2/4/6/8. Des compilations indépendantes peuvent également contribuer à la
charge. Ce protocole enregistre cette situation ; il ne revendique ni
fréquence fixe, ni machine isolée, ni référence de performance sans
contention. Le nouveau fuzzing NTT sur le CPU 10 attend la fin du comparatif.

Les médianes et p95 au rang supérieur sont reconstruits en Python depuis
**toutes** les observations. Aucun échantillon lent n'est filtré. La mémoire
maximale donnée par GNU time est celle du processus entier contenant les
deux moteurs et le pilote : elle n'est pas présentée comme la mémoire propre
de l'un des deux algorithmes.

## État des exécutions

Les captures utilisées sont `ntt-001` et `schoolbook-002`. Les captures
préliminaires `smoke-001`, `smoke-002` et `schoolbook-001` restent conservées.
La première construction de `smoke-002` a réussi ses tests fonctionnels puis
a été arrêtée par Clippy 1.93 sur le style d'un test de parité du pilote. La
réécriture avec `is_multiple_of` est incluse dans `ntt-001` et son dérivé
scolaire ; aucune donnée de cette tentative n'est mélangée aux mesures.

Les quatre constructions ont réussi le formatage, Clippy avec avertissements
interdits et deux tests d'échange/rejet sur les APIs réelles. Les deux
contrôles par construction donnent huit exécutions de tests réussies ; ce
ne sont pas huit tests cryptographiques indépendants.

Les quatre panneaux ont été exécutés de **20:35:15Z à 20:36:33Z**. Les
24000 observations brutes sont conservées et leurs résumés recalculés sans
filtrage. Le contrôleur mesure GNU time sur le processus entier : 68,10 s CPU
au total, incluant préchauffages, validations et sérialisation. Cette durée
n'est pas la somme des seuls appels chronométrés.

Le tableau donne **médiane / p95, en millisecondes**, avec 1000 observations
par case d'opération. « Processus NTT » et « processus scolaire » identifient
la version R1 reliée au pilote ; le moteur 1024 reste inchangé.

| Processus | Moteur mesuré | Backend 1024 du processus | KeyGen | Encaps | Decaps |
|---|---|---|---:|---:|---:|
| NTT | R1 NTT scalaire | AVX2 | 0,962321 / 1,315567 | 1,131762 / 1,481849 | 1,232613 / 1,668505 |
| NTT | Premier dépôt 1024 | AVX2 | 0,099353 / 0,136257 | 0,082959 / 0,124851 | 0,090024 / 0,138302 |
| Scolaire | R1 scolaire M02 | AVX2 | 2,544545 / 3,879969 | 2,547592 / 3,627394 | 2,887136 / 4,193905 |
| Scolaire | Premier dépôt 1024 | AVX2 | 0,091696 / 0,128408 | 0,083133 / 0,124107 | 0,084443 / 0,140303 |
| NTT | R1 NTT scalaire | C portable | 1,007409 / 1,398968 | 1,116949 / 1,483445 | 1,284643 / 1,683750 |
| NTT | Premier dépôt 1024 | C portable | 0,125429 / 0,181330 | 0,123028 / 0,194534 | 0,205728 / 0,251646 |
| Scolaire | R1 scolaire M02 | C portable | 2,263904 / 3,330981 | 2,519277 / 3,799128 | 2,934500 / 4,436856 |
| Scolaire | Premier dépôt 1024 | C portable | 0,115625 / 0,179482 | 0,122562 / 0,193784 | 0,178545 / 0,241774 |

Le rapport des médianes scolaire/NTT vaut respectivement :

| Configuration du comparatif | KeyGen | Encaps | Decaps |
|---|---:|---:|---:|
| Premier dépôt en AVX2 | ×2,644 | ×2,251 | ×2,342 |
| Premier dépôt en C portable | ×2,247 | ×2,255 | ×2,284 |

**La révision R1 NTT accélère les trois opérations dans cette expérience.**
Le moteur du premier dépôt reste plus rapide sur ce poste, y compris dans
sa variante C portable. Ce constat sert à orienter les optimisations ; il
ne compare pas des constructions ayant les mêmes formats, le même rang
ou les mêmes garanties.

Le témoin 1024 inchangé révèle la variation entre processus. Sa médiane de
décapsulation portable passe de 0,205728 ms à 0,178545 ms, soit −13,2 % en
rapportant le second au premier processus. L'encapsulation du même témoin
varie beaucoup moins. Les rapports R1 sont donc publiés comme **gains
observés sous charge**, sans intervalle de confiance, sans garantie sur
d'autres machines et sans interprétation d'écarts fins. Les quatre captures
confirment les quatre travailleurs M03 actifs ; la charge moyenne à une
minute va d'environ 6,18 à 6,70 sur le poste AMD Ryzen 7 2700. L'affinité
WSL ne démontre pas l'absence de partage physique ou de frère SMT.

Les pics RSS du processus complet sont 2560 Kio pour NTT/AVX2, puis 2432 Kio
pour chacun des trois autres processus. Cette mesure agrège deux moteurs,
le runtime et les observations ; elle ne permet pas de classer leur mémoire
propre. Les exécutables du comparatif sont également des programmes qui
contiennent les deux bibliothèques.

`ntt-001/paired-comparison.json` rattache les quatre fichiers bruts par SHA-256,
vérifie l'égalité du pilote, de la chaîne, du profil, du verrou, des formats
et des nombres d'échantillons, puis calcule les rapports. Les fichiers
`controller-measure.py` conservent le contrôleur effectivement chargé pour
les mesures. Les empreintes des deux sources R1 NTT sont :

```text
dev_kem.rs     4bc3f75ce59cb24b8c8ca88e313cc8ab23b71282fb56cc6459c83e745d70756b
engine_poly.rs 906e9e27579f703c569b4231c0e83e07cdeed21dacecd38b4cd1f5a0dbc67579
```

Le marqueur `artifacts/generated/m04-pair/MEASUREMENTS_DONE` a été créé
après les quatre exécutions, autorisant ensuite le nouveau smoke de fuzzing
NTT sur le CPU 10. Il ne déclare pas la campagne M03 longue terminée.
Les notices du premier projet sont conservées séparément dans
`first-project-notices/` pour les deux captures utilisées, avec leurs
empreintes et le commit d'origine ; elles n'altèrent aucun fichier mesuré.

## Comparaison des preuves et de l'intégration

La lecture du commit figé du premier dépôt confirme une bibliothèque, une
CLI JSON, un exemple consommateur, une démonstration HTTP, les trois jeux de
paramètres normalisés et des scripts de distribution Docker. Ses tests
conservent un exemple KeyGen et un exemple Encaps NIST ACVP par jeu de
paramètres, plus des vecteurs externes de rejet C2SP et une matrice d'erreurs
de formats et de mélanges de profils. La procédure de double construction,
les SBOM et les attestations sont décrites dans ses workflows. Ils ne sont
pas déclarés exécutés à nouveau par le présent comparatif.

R1 possède sa spécification propre, sa référence indépendante Python, ses
vecteurs complets et rejets conservés, des études de correction et d'attaques,
ainsi que des preuves de tests, d'instrumentation mémoire et de binaires.
Son dossier est plus détaillé sur la construction développée ici. Il ne
remplace pas le recul cryptanalytique du jeu de paramètres ML-KEM-1024.

Le comportement de l'API R1 est davantage typé. L'import vérifie la
canonicalité et la cohérence documentée des encodages, et ses types privés
ne dérivent pas `Debug`. Dans le premier dépôt figé, `SecretBytes` dérive
`Debug` : un consommateur qui formate ce type pourrait afficher ses octets.
Cette observation porte sur un chemin possible de diagnostic, pas sur une
fuite réseau ou un journal de secrets démontré. Aucun correctif n'est
appliqué au premier dépôt dans cette étape.

## Reproduction

Le [README du comparatif](../comparisons/engine-pair/README.md) détaille la
préparation du premier dépôt et les phases du lanceur. Depuis NIST, sous
Linux/WSL avec la chaîne locale Rust 1.93.0 :

```sh
python3 research/run_engine_pair.py --phase prepare --output artifacts/generated/m04-pair/ntt-nouveau
python3 research/run_engine_pair.py --phase build --output artifacts/generated/m04-pair/ntt-nouveau
python3 research/run_engine_pair.py --phase prepare --schoolbook-of artifacts/generated/m04-pair/ntt-nouveau --output artifacts/generated/m04-pair/scolaire-nouveau
python3 research/run_engine_pair.py --phase build --output artifacts/generated/m04-pair/scolaire-nouveau
python3 research/run_engine_pair.py --phase measure --output artifacts/generated/m04-pair/ntt-nouveau --series 5 --warmups 50 --observations 200 --cpu 10
python3 research/run_engine_pair.py --phase measure --output artifacts/generated/m04-pair/scolaire-nouveau --series 5 --warmups 50 --observations 200 --cpu 10
python3 research/run_engine_pair.py --phase verify --output artifacts/generated/m04-pair/ntt-nouveau
python3 research/run_engine_pair.py --phase verify --output artifacts/generated/m04-pair/scolaire-nouveau
python3 research/run_engine_pair.py --phase compare --output artifacts/generated/m04-pair/ntt-nouveau --compare-with artifacts/generated/m04-pair/scolaire-nouveau
```

Chaque capture doit porter un nouveau nom. Les fichiers gelés de M02/M03 et
la campagne de fuzzing existante ne sont pas remplacés. Les comparaisons
futures doivent conserver le même niveau de précision sur les versions,
les cibles, les objets mesurés et la charge.
