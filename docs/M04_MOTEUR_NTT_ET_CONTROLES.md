# M04 — NTT, mémoire et contrôles du moteur R1

25 octobre 2026. Les trois travaux scientifiques ont précédé les changements
de réalisation : [argument de sécurité](ARGUMENT_SECURITE_R1.md),
[lien certificat/programme](LIEN_CERTIFICAT_PROGRAMME_R1.md) et
[comparaison commune des attaques](COMPARAISON_ATTAQUES_CADRE_COMMUN_R1.md).
Le profil, les domaines et tous les formats R1 sont conservés. L'instantané
scientifique antérieur est `results/security/m04-001` ; le code du moteur
optimisé est versionné à partir de `78f5faf`.

## Réalisation de la multiplication

Le produit dans `Z_7681[X]/(X^256+1)` utilise une NTT scalaire complète.
La racine ψ=4055 a l'ordre 512 ; ω=5685=ψ² a l'ordre 256. Les inverses
sont ψ^-1=2811, ω^-1=5653 et 256^-1=7651 modulo 7681.

Multiplier a_i par ψ^i transforme la convolution négacyclique en une
convolution cyclique : pour i+j≥256, ψ^(i+j)=−ψ^(i+j−256).
La NTT cyclique évalue ensuite aux puissances de ω ; l'inverse, normalisé
par 256^-1, puis le facteur ψ^-i rendent le produit négacyclique. Les
coefficients restent canoniques à chaque papillon. Les tables publiques
sont calculées à la compilation ; les divisions et modulos de cette
préparation ne portent pas sur des coefficients secrets.

Le produit de deux coefficients est au plus 7680²=58 982 400. La réduction
utilise la réciproque entière sur 32 bits et une correction ; les opérations
sur données secrètes n'emploient pas une division entière. Les permutations,
boucles et adresses de tables de la transformée dépendent d'indices publics.
Cela décrit le code source ; le compilateur et les binaires sont vérifiés
séparément.

Les tests confrontent 70 couples (six familles de bords et 64 tirages
pseudoaléatoires) à l'oracle de convolution indépendant ; ils vérifient
16 allers-retours, les ordres/inverses, le signe du repli et les bornes de
réduction. La convolution générique demeure séparée du moteur optimisé.
Les vecteurs complets fournissent une seconde comparaison à l'oracle
Python historique.

## M03-A01 et propriété réellement contrôlée

`multiply_into` écrit dans un `Polynomial` détenu par l'appelant. Les
accumulations sont faites en place ; le bruit, le décodage, le message et
le secret PKE sont également remplis dans leur propriétaire. Aucun
`Polynomial` secret n'est retourné par ces fonctions de production. La
matrice publique et les objets initialement nuls peuvent encore être
retournés par valeur.

Le temporaire de résultat de 512 octets signalé par M03-A01 était copié
vers le résultat sans effacement explicite. La nouvelle réalisation écrit
les coefficients finaux directement dans la destination. Ses deux tableaux
de travail de 512 octets sont détenus par `Zeroizing`.

`research/review_m04_wipes.py` vérifie une forme de boucles assembleur
restreinte et examinée : deux ensembles de 512 octets sont intégralement
couverts par les écritures nulles sur le chemin de retour normal. Le test
négatif retire une écriture ou réduit une borne et doit échouer. Ce contrôle
ne démontre ni la provenance de toutes les écritures, ni l'effacement de
tous les registres, spills, temporaires du hachage et copies des appelants.
La sortie directe est examinée séparément dans le désassemblage.

La revue initiale Windows/Linux des binaires de recherche confirme ces
deux boucles. Elle confirme aussi l'absence de division dans `multiply_into`
et la transformée. Les deux divisions recensées dans le cœur du binaire
de recherche proviennent du diagnostic public de chronométrage M02, et
non de l'arithmétique KEM. Le binaire Windows de distribution initialement
examiné (SHA-256 `ea80bc3a7f49ba287cf0958be1e7eceabe55cfc8882cdabc2517b6c58712ca65`)
ne contient aucune division dans les fonctions propres du cœur R1.
Les divisions de sa fermeture directe se trouvent dans la conversion des
compteurs de temps de la bibliothèque standard, utilisée par l'auto-test.

L'inventaire de toutes les fonctions, branches, appels et dépendances est
conservé. Il ne certifie pas une fermeture complète des appels indirects ou
les corps des bibliothèques système. Les transferts par registres sous Linux
doivent rester identifiés dans les limites, même quand un chargement GOT
suggère une fonction de copie ou d'initialisation. Aucun audit exhaustif ni
preuve de temps constant ne découle de l'absence de division du cœur.

La revue du **binaire Linux effectivement livré**, SHA-256
`e025ab71066ba63d3efccf6eb28f5e91a4050d151ea83f4fb1aab4320ced71c9`,
confirme également les écritures directes et les deux effacements de 512
octets. Sa fermeture directe R1 ne contient aucune division recensée.
Une seconde revue relie les deux appels `*%r13` de `multiply_into` à la
case GOT `0x339928`, relocalisée sur `memset` : ils initialisent les deux
scratch à zéro avant les données secrètes. Les 23 autres sites par registre
du cœur restent ouverts à une qualification complète. **M03-A01 est corrigé
pour ces deux binaires livrés** ; son état historique demeure inchangé dans
les preuves M03, et aucun effacement universel n'est déclaré.

## Régressions complètes et diagnostic temporel élargi

Les binaires Windows et Linux optimisés retrouvent chacun, champ par champ :

- les 1 000 vecteurs synthétiques M01 complets ;
- les 10 000 résultats de rejet M01 ;
- les 10 000 mutations M02, précédemment confrontées à Python ;
- les 20 000 contrôles de formats M02, avec les mêmes décisions et aucun
  panic observé.

`research/validate_m04_engine.py` enregistre les empreintes avant/après,
les sources et les décomptes. Il compare les sorties du moteur courant aux
sorties figées ; il ne présente pas cette étape comme une nouvelle
simulation de taux d'échec rares.

Le nouveau mode `kem1536-bench delivery-timing` emploie huit clés fraîches
et cinq classes : honnête, v altéré canonique, premier u non canonique,
dernier u non canonique et chiffré nul. Chaque couple clé/classe conserve
400 observations après 50 préchauffages, soit 16 000 observations par OS.
L'ordre des classes varie publiquement à chaque tour ; la validation et la
destruction du secret retourné sont hors du chronométrage. Aucun secret
n'est exporté par ce diagnostic.

Sur les 32 contrastes par OS, sans retrait de valeurs extrêmes, le maximum
|t| observé est 1,578180 sous Windows et 1,981728 sous Linux, sous le seuil
diagnostique préfixé 4,5. Il n'y a pas de contrôle de comparaisons multiples,
pas de puissance garantie et pas de preuve de temps constant. Les entrées
sont fixes dans chaque classe/clé. La campagne historique de fuzzing et
des compilations étaient actives ; ce sont des diagnostics sous charge,
distincts des mesures P01 antérieures.

## API livrée et exemple d'intégration

Deux tests de l'API publique fonctionnent sans `research-vectors` : liaison
du rejet à z et à onze positions du chiffré sur huit clés, et contrôles de représentation
à chaque frontière des six polynômes. Changer z conserve le chemin honnête
mais modifie le secret de remplacement. Ces observations finies n'attestent
pas l'origine honnête d'une clé importée. Après contre-revue, chaque
mutation change un seul bit depuis une base non canonique fixe, sans
identifiant ajouté ailleurs. Le test peut ainsi détecter un rejet qui
n'utiliserait que le suffixe. Il n'énumère pas les 2656 positions possibles.

L'exemple autonome [`examples/r1-channel-demo`](../examples/r1-channel-demo/README.md)
emploie le KEM, HKDF-SHA256 et AES-256-GCM avec contexte lié au profil,
à la clé publique et au chiffré. Il vérifie les altérations des données,
du tag, du contexte, du nonce, de l'encapsulation et une clé privée différente.
Il suppose la clé publique du destinataire authentifiée ; il ne fournit
pas l'identité de l'émetteur, un protocole de messagerie ou l'anti-rejeu.
Les dépendances facultatives ont leur propre verrou Cargo.

L'exemple réussit ses tests et Clippy strict sous Windows et Linux, puis
s'exécute en release sur les deux cibles sans afficher de secret.

## Performance observée de la révision

Le vrai dépôt 1024 au commit `3dd7c91b5ec9777fd1afc09db198d00dc0deca88`
et R1 ont été comparés sous Rust 1.93.0, sur un même cœur logique WSL.
La production conserve Rust 1.91.1. Quatre processus couvrent NTT/scolaire
et backend 1024 natif/portable : 24 000 observations brutes, cinq séries,
200 observations par série/opération/moteur, 50 préchauffages.

Les médianes ci-dessous utilisent le panneau où le moteur 1024 emploie
son backend natif AVX2. Les unités sont des millisecondes par opération.

| Opération | R1 avant révision | R1 avec NTT | Premier dépôt 1024 AVX2 |
|---|---:|---:|---:|
| KeyGen | 2,545 | 0,962 | 0,099 |
| Encaps | 2,548 | 1,132 | 0,083 |
| Decaps | 2,887 | 1,233 | 0,090 |

Sur les deux panneaux natif/portable, le gain médian de la révision R1 est
de ×2,25 à ×2,64. Les deux fichiers modifiés comprennent l'algorithme NTT
et la gestion des destinations ; ce n'est pas une isolation causale de la
NTT seule. Le moteur 1024 reste plus rapide dans ce diagnostic. La campagne
longue M03 était active et le témoin 1024 inchangé varie jusqu'à environ
13 % entre processus : ne pas transformer les décimales en pourcentages
fins de gain. Les tableaux intégraux, P95, volumes et versions figurent
dans la comparaison directe ; les coûts de sécurité restent séparés.

## Livraisons séparées

L'instantané `results/engine/m04-001` conserve **609 fichiers** avec leur
manifeste, les sources propres, quatre désassemblages complets et leurs
binaires, les observations et les preuves de distribution. Le programme
`research/verify_m04.py --recheck-disassembly` a contrôlé les 609 empreintes,
61 sources archivées, les quatre inventaires et 32000 observations, puis
redésassemblé les quatre binaires. Les deux binaires empaquetés sont reliés
octet par octet à ceux examinés. Les reconnaisseurs de boucles restent des
contrôles restreints, complétés par deux revues directes.

Les deux écarts repérés par la contre-revue — fixture de mutation et
instructions intercalées dans le reconnaisseur — sont conservés avec leurs
corrections et leurs tests négatifs. Les deux tests API corrigés passent
sous Windows et Linux. La tâche complète `check` a été exécutée deux fois ;
la dernière campagne de tests de recherche comprend **115 tests réussis**.

## ASan et fuzzing de la réalisation NTT

Quatre harnais sont construits depuis une copie figée des sources avec
ASan et **la bibliothèque standard recompilée**. Les références aux sondes
de lecture/écriture et de pile ASan de la std sont vérifiées. Les binaires,
versions, graines, corpus et journaux sont conservés.

| Harnais | Secondes CPU mesurées | Exécutions cumulées, rejouages inclus |
|---|---:|---:|
| Import public | 61,43 | 386372 |
| Import privé | 99,88 | 5193 |
| Décapsulation | 101,15 | 3718 |
| Séquences API, grand corpus | 196,51 | 1075 |

Le rejeu initial de la dernière cible absorbe son budget et ne produit
aucune nouvelle mutation. Un complément séparé utilise donc les mêmes
octets de binaire et 32 graines synthétiques : **73,47 secondes CPU et
510 exécutions après initialisation**. Les deux étapes totalisent
**532,44 secondes CPU**. Aucun défaut ASan, fuite signalée ou crash n'est
observé. Le contrôleur mesure le temps CPU du harnais et de l'instrumentation,
pas la seule cryptographie ; les répétitions de graines ne sont pas des
entrées distinctes.

La couverture de lignes n'est pas mesurée par cette campagne. Le compteur
libFuzzer et ses caractéristiques ne deviennent pas un pourcentage de
couverture source. L'oracle indépendant n'est pas rejoué sur tout ce corpus
de fuzzing ; les régressions complètes M01/M02 sont des contrôles distincts.
Les opérations avec aléa système vérifient des invariants frais, sans
prétendre reproduire leurs graines à partir de la seule entrée du harnais.

## Distribution et comparaison

La [distribution reproductible](DISTRIBUTION_M04.md) conserve les preuves
des doubles builds par cible, les paquets, licences et hypothèses système.
La [comparaison directe des dépôts](COMPARAISON_DEPOTS_EXECUTION_M04.md)
emploie le vrai backend du dépôt 1024 sous une chaîne commune. Les contrôles
ASan/fuzz de cette nouvelle réalisation restent séparés de la campagne
longue gelée au code `8ef4ceb` ; ses budgets ne sont pas transférés à la NTT.

Les paquets 004 conservent les octets issus des doubles builds 003, après
vérification de l'égalité exacte de leurs 30 entrées compilables. Les
corrections de tests et d'outils ne sont pas présentées comme quatre
nouvelles compilations. Leur instantané source précède l'archivage final
M04 ; pour la totalité du contrôle de recherche, employer aussi les preuves
`results/security/m04-001` et `results/engine/m04-001` conservées dans le
dépôt NIST. Le build et l'auto-test du moteur n'exigent pas le fuzzing.
