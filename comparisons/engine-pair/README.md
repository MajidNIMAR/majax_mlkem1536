# Comparaison directe des deux moteurs

Ce workspace Cargo autonome relie les APIs réelles de R1 et de
`MajidNIMAR/majax-mlkem1024-demo` au commit
`3dd7c91b5ec9777fd1afc09db198d00dc0deca88` dans un même processus. Il ne
modifie pas le workspace principal ou sa chaîne Rust de production.

Le premier dépôt doit être présent, sans modification, sous
`.tools/comparison/mlkem1024-demo`. Pour une nouvelle copie de travail :

```sh
git clone https://github.com/MajidNIMAR/majax-mlkem1024-demo .tools/comparison/mlkem1024-demo
git -C .tools/comparison/mlkem1024-demo checkout --detach 3dd7c91b5ec9777fd1afc09db198d00dc0deca88
```

Le lanceur `research/run_engine_pair.py` fige les sources courantes, y compris
le moteur R1 en développement, avant de les compiler avec la même chaîne
locale **Rust 1.93.0**, le même profil de compilation et un verrou commun.
Le verrou de comparaison conserve les 29 versions et empreintes des paquets
registre du premier dépôt. La relation avec le verrou complet du workspace
R1 est également enregistrée ; ce binaire n'est pas le binaire de production.

Depuis la racine NIST, choisir un nouveau dossier pour chaque capture :

```sh
python3 research/run_engine_pair.py --phase prepare --output artifacts/generated/m04-pair/exemple-001
python3 research/run_engine_pair.py --phase build --output artifacts/generated/m04-pair/exemple-001
python3 research/run_engine_pair.py --phase smoke --output artifacts/generated/m04-pair/exemple-001 --cpu 10
python3 research/run_engine_pair.py --phase verify --output artifacts/generated/m04-pair/exemple-001
```

La préparation fonctionne aussi sous Windows. Les phases de compilation et
d'exécution emploient Linux/WSL et les outils locaux de `.tools/linux-cargo`
et `.tools/linux-rustup`. Rust 1.93.0 doit posséder `rustfmt` et `clippy`.
Les fichiers, traces, captures de charge, binaires et observations restent
dans le dossier de l'expérience. Les phases refusent d'écraser un résultat.

`native` active uniquement les optimisations du premier dépôt : le répartiteur
PQClean choisit AVX2 sur le poste x86-64 compatible. `portable` désactive ces
optimisations. Le moteur R1 est toujours celui de la capture, construit avec
la cible Rust x86-64 de base. L'ordre des moteurs et des opérations alterne
entre séries. Les fonctions qui génèrent de l'aléa sont mesurées avec leur
source système, sans interfaces de test déterministes. Les validations du
harnais et la destruction des objets retournés interviennent hors du
chronomètre ; le travail interne des APIs reste inclus.

L'essai `smoke` est limité à deux séries, trois préchauffages et dix
observations par opération et moteur : **120 observations par binaire**.
Il vérifie la chaîne et produit des statistiques diagnostiques. Une campagne
de performance est une action distincte, `--phase measure`, à lancer seulement
dans les conditions décidées pour l'étude. Sa configuration par défaut est
cinq séries, cent préchauffages et mille observations par opération et
moteur. La charge et la campagne de fuzzing concurrente sont enregistrées ;
aucun résultat n'est automatiquement déclaré exempt de contention.

Une mesure avant/après la NTT peut conserver exactement le même pilote et
le même verrou, en remplaçant uniquement les deux sources de moteur M02 :

```sh
python3 research/run_engine_pair.py --phase prepare --schoolbook-of artifacts/generated/m04-pair/exemple-001 --output artifacts/generated/m04-pair/scolaire-001
python3 research/run_engine_pair.py --phase build --output artifacts/generated/m04-pair/scolaire-001
```

Les deux captures peuvent partager un cache Cargo explicitement choisi avec
`--build-cache` pour limiter le travail de compilation ; leurs sources,
binaires et preuves restent séparés. Après deux mesures de configurations
identiques, `--phase compare --output <capture-NTT> --compare-with
<capture-scolaire>` vérifie le protocole commun et produit les rapports de
médianes et p95. Les données du backend 1024 inchangé servent aussi de témoin
de variation entre les deux processus.

Les sorties JSON contiennent uniquement des identifiants, tailles et durées
publics. Aucun octet de clé, graine, message ou secret partagé n'est exporté.
Les médianes et p95 au rang supérieur sont recalculés en Python depuis toutes
les mesures, sans filtrage. Cette comparaison mesure le comportement des APIs
avec leurs coûts d'import et de copie respectifs. Elle ne mesure pas une
résistance cryptanalytique.
