# Cahier des charges du KEM expérimental 1536

**Version 0.1 — Proposition technique pour le développement et l’évaluation**

Le projet vise une implémentation ouverte d’un mécanisme d’encapsulation de clé de rang 6, composé de six polynômes de 256 coefficients. Une encapsulation doit produire un chiffré unique et un secret partagé. Le projet est indépendant de MajaxA et de Majax Messenger.

Le présent document définit des exigences de projet. Il ne constitue pas une norme du NIST. Le nom technique provisoire est **KEM1536-EXP-P0**, version **0.1**. Le nombre 1536 décrit la dimension du vecteur polynomial ; il ne désigne ni une longueur de clé symétrique ni un nombre de bits de sécurité.

## 1 Objectif et résultat attendu

Le résultat attendu est un dépôt source permettant à un tiers de construire la bibliothèque, d’exécuter KeyGen, Encaps et Decaps, de reproduire les tests et de consulter les analyses ayant motivé le choix des paramètres.

Le projet doit fournir un candidat utilisable pour la recherche, accompagné de preuves de fonctionnement et d’une évaluation cryptographique. Le passage au rang 8, soit 2048 coefficients, constitue une évolution ultérieure ; il ne conditionne pas la livraison du rang 6.

La livraison initiale exclut l’intégration dans une messagerie, l’accès à un VPS, un protocole réseau, les optimisations SIMD et toute procédure de certification. Tous les fichiers de ce projet doivent rester sous le dossier local `Codex\NIST` ; aucun dossier daté ne doit être créé à la racine de `Codex`.

## 2 Portée des exigences

**DOIT** indique une exigence nécessaire au jalon concerné. **DEVRAIT** indique une recommandation dont l’écart doit être expliqué. Un choix indiqué comme **profil de départ** sert à l’expérimentation et ne vaut pas validation cryptographique.

Les exigences F01 à F04 ci-dessous sont fixées par l’objectif du projet. Les autres exigences sont proposées pour rendre la réalisation mesurable et reproductible.

**Orientation de recherche précisée par l'utilisateur le 24 octobre 2026.** L'approbation préalable d'une méthode par le NIST ou un autre organisme n'est pas requise pour son étude, son développement expérimental ou sa comparaison. Des choix de distributions, de compression, de codes, de réconciliation ou de construction du KEM peuvent s'écarter des références normalisées. Chaque variante doit définir ses algorithmes, son objectif, ses hypothèses et les propriétés effectivement établies. L'évaluation extérieure est une étape ultérieure dont le résultat n'est pas présumé. Les critères de correction et de sécurité visée du projet restent les objectifs de comparaison ; leur éventuelle révision doit être motivée et enregistrée explicitement. P0 et les instantanés antérieurs conservent leur définition et leurs résultats.

| Exigence | Condition obligatoire | Preuve attendue |
|---|---|---|
| F01 | Le degré de représentation est n = 256 et le rang est k = 6 | Spécification et inspection des structures |
| F02 | Le vecteur secret contient six polynômes de 256 coefficients | Tests des dimensions et des encodages |
| F03 | Une encapsulation appelle une seule instance du KEM de rang 6 | Parcours du code et trace de test instrumentée |
| F04 | La réalisation reste indépendante des systèmes Majax existants | Dépendances et périmètre du dépôt |
| F05 | La bibliothèque expose KeyGen, Encaps et Decaps | Tests de l’API |
| F06 | Un tiers peut reconstruire et tester le code publié | Procédure exécutée dans un environnement propre |

## 3 Structure mathématique

Le candidat conserve la structure Module-LWE suivante :

```text
R_q = Z_q[X] / (X^256 + 1)
s, e ∈ R_q^6
A ∈ R_q^(6×6)
t = A s + e
```

Les 36 entrées de la matrice A couplent les six composantes. Les fonctions d’encapsulation et de décapsulation doivent utiliser ce même système de rang 6. Une concaténation de plusieurs KEM existants ne satisfait pas F03.

La structure algébrique et l’effet des paramètres de bruit et de compression sont décrits dans la [spécification des auteurs de CRYSTALS-Kyber, sections 1 et 4](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf). La présente construction choisit un rang expérimental supplémentaire.

## 4 Profil de départ P0

Le profil suivant est une hypothèse de travail complète permettant de démarrer l’analyse. Les valeurs de bruit et de compression doivent pouvoir être remises en cause par les résultats, sans modifier la contrainte n = 256, k = 6.

| Élément | Valeur de départ | Statut |
|---|---|---|
| Nombre de coefficients par polynôme n | 256 | Fixé |
| Rang du module k | 6 | Fixé |
| Dimension du vecteur n × k | 1536 coefficients | Conséquence arithmétique |
| Module q | 3329 | Profil de départ |
| Distribution du secret s, de l’erreur e de génération et de l’aléa polynomial y | Binomiale centrée CBD avec eta1 = 2 | Profil de départ |
| Distribution des erreurs d’encapsulation | Binomiale centrée CBD avec eta2 = 2 | Profil de départ |
| Compression du vecteur u | du = 11 bits par coefficient | Profil de départ |
| Compression du polynôme v | dv = 5 bits par coefficient | Profil de départ |
| Secret partagé K | 32 octets | Choix de conception |
| Graines d et z | 32 octets chacune | Choix de conception |
| Aléa d’encapsulation m | 32 octets | Choix de conception |

**P0 ne doit pas être présenté comme un jeu de paramètres sûr tant que les critères des sections 7 et 11 ne sont pas satisfaits.** Un changement de q, eta1, eta2, du ou dv doit créer une nouvelle identification de profil et de nouveaux vecteurs de test.

Les primitives retenues sont SHA3-256, SHA3-512, SHAKE128 et SHAKE256, telles que définies dans [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final). Les algorithmes de hachage ne doivent pas être réimplémentés pour ce projet lorsque des bibliothèques éprouvées conviennent.

## 5 Définition des algorithmes et des formats

### 5.1 Base algorithmique

**A01.** Pour le point de départ historique P0, la spécification part des algorithmes 1 à 21 de [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf), en substituant explicitement le profil P0 aux paramètres autorisés par cette publication. Les nouveaux candidats peuvent employer une construction différente, y compris non standardisée, à condition d'en fournir une spécification complète, une identification distincte et l'analyse des propriétés affectées. Les écarts doivent être recensés ; les conventions de Kyber historique, de ML-KEM et des constructions du projet doivent être identifiées sans ambiguïté.

La version de référence de FIPS 203 est celle publiée le 13 août 2024. Le jalon J0 doit figer son empreinte, examiner les mises à jour potentielles signalées sur la [page officielle](https://csrc.nist.gov/pubs/fips/203/final) et consigner les corrections retenues. Une implémentation du rang 6 reste hors des trois jeux normalisés.

**A02.** Les définitions de l’arrondi, de la compression, des encodages, de l’échantillonnage et de la représentation NTT doivent être explicites ou référencées sans ambiguïté. Pour un profil et des algorithmes inchangés, toute optimisation doit conserver les sorties octet pour octet pour les mêmes entrées déterministes. Une modification de construction susceptible de changer ces sorties crée une variante identifiée, ses vecteurs et ses analyses propres.

### 5.2 Interfaces

```text
KeyGen()       -> (ek, dk) ou erreur d’environnement
Encaps(ek)     -> (K, c)   ou erreur de format / d’environnement
Decaps(dk, c)  -> K        ou erreur de format / de clé
```

**A03.** L’API publique doit utiliser des types distincts pour les clés, les chiffrés et les secrets. Elle doit vérifier l’identifiant de profil avant l’appel au cœur cryptographique.

**A04.** Les interfaces déterministes acceptant les graines doivent être réservées aux tests et aux analyses reproductibles. Elles ne doivent pas être exposées par défaut comme une option de génération de clés d’application.

### 5.3 Tailles calculées pour P0

Les tailles ci-dessous sont des calculs du projet à partir des encodages retenus. Elles ne constituent pas une évaluation de sécurité.

| Objet | Formule en octets | Taille P0 |
|---|---|---:|
| Polynôme encodé sur 12 bits | 256 × 12 / 8 | 384 |
| Vecteur de six polynômes sur 12 bits | 384 × 6 | 2304 |
| Clé d’encapsulation ek | 384k + 32 | 2336 |
| Clé de décapsulation dk développée | 768k + 96 | 4704 |
| Partie c1 du chiffré | 32 × du × k | 2112 |
| Partie c2 du chiffré | 32 × dv | 160 |
| Chiffré complet c | 32 × (du × k + dv) | 2272 |
| Secret partagé K | Taille fixée par le projet | 32 |

**A05.** Les formats bruts P0 doivent être exactement les suivants, avec des intervalles d’octets de début inclus et de fin exclue :

```text
ek = t_hat || rho
     t_hat : [0, 2304) ; rho : [2304, 2336)

dk = s_hat || ek || H(ek) || z
     s_hat : [0, 2304) ; ek : [2304, 4640)
     H(ek) : [4640, 4672) ; z : [4672, 4704)

c = c1 || c2
    c1 : [0, 2112) ; c2 : [2112, 2272)
```

H désigne SHA3-256. Les vecteurs avec suffixe `hat` sont sérialisés dans la représentation NTT retenue par la base algorithmique. L’ordre des coefficients et le rangement des bits doivent suivre ByteEncode et ByteDecode de cette base.

### 5.4 Séparation entre profils

**A06.** L’expansion de génération des graines doit incorporer le rang sous la forme de l’octet `0x06`, selon la construction `G(d || 0x06)`, où G est SHA3-512. Les indices de matrice vont de 0 à 5. Les compteurs PRF utilisent 0 à 11 en génération et 0 à 12 en encapsulation.

**A07.** Toute enveloppe ou sérialisation destinée à une application doit porter l’identifiant `KEM1536-EXP-P0` et la version. Les formats bruts ci-dessus n’incluent pas ces champs. Un protocole doit authentifier le choix du profil et empêcher une rétrogradation silencieuse.

L’octet de rang ne sépare pas deux variantes utilisant toutes deux k = 6. Les graines privées ne doivent pas être réutilisées entre profils ; toute future modification de la séparation cryptographique doit être spécifiée et versionnée.

## 6 Validation des entrées et traitement des secrets

**S01.** Les longueurs doivent être vérifiées avant toute lecture. Les coefficients encodés de la clé d’encapsulation doivent être canoniques ; une entrée non canonique doit être refusée et ne doit pas être réparée silencieusement.

**S02.** La cohérence entre la clé d’encapsulation embarquée et son empreinte doit être vérifiée dans une clé de décapsulation importée. Ce contrôle ne suffit pas à démontrer qu’une clé arbitraire a été correctement générée ; la provenance de la clé doit également être maîtrisée.

**S03.** Pour un chiffré de longueur correcte qui échoue au contrôle cryptographique de réencapsulation, Decaps doit produire le secret de remplacement `SHAKE256(z || c, 32 octets)`. La sélection avec le secret normal doit se faire sans branchement dépendant du résultat secret de ce contrôle. Aucun indicateur de rejet cryptographique ne doit être renvoyé à l’appelant.

**S04.** Les erreurs publiques de type ou de longueur doivent être distinguées du rejet implicite de S03. Aucune erreur ne doit contenir de clé, de graine ou de secret partagé.

Ces exigences doivent faire l’objet de tests d’intégration distincts. Une [implémentation pédagogique de ML-KEM](https://github.com/GiacomoPope/kyber-py/blob/main/src/kyber_py/ml_kem/ml_kem.py) peut servir à l’inspection et à la comparaison ; une implémentation destinée à un usage réel doit être évaluée séparément pour ses propriétés temporelles et mémoire.

**S05.** L’implémentation doit utiliser un générateur cryptographique du système d’exploitation et échouer si celui-ci est indisponible. Aucun aléa ne doit provenir de l’heure, d’un identifiant de machine ou d’un générateur de simulation.

**S06.** Le cœur doit éviter les accès mémoire et les branchements dépendant des secrets, utiliser des primitives de comparaison et de sélection adaptées, et effacer les secrets temporaires avec un mécanisme résistant à l’optimisation. Les allocations, copies et limites de cette protection doivent être documentées.

Les conditions d’établissement et d’utilisation des clés doivent être analysées à l’aide de [NIST SP 800-227](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-227.pdf). Le KEM doit être intégré ultérieurement avec une authentification du correspondant et une dérivation de clés tenant compte du contexte. Il ne suffit pas, seul, à assurer une messagerie authentifiée.

## 7 Objectifs et critères cryptographiques

### 7.1 Résistance aux attaques

**C01.** Le projet doit viser une sécurité contre les attaques adaptatives à chiffrés choisis, appelée IND-CCA. Un dossier doit expliquer les hypothèses nécessaires et les conditions de la transformation utilisée, y compris dans les modèles quantiques pertinents.

**C02.** L’analyse doit comparer le rang 6 à ML-KEM-1024 avec le même outil, les mêmes versions, modèles de coûts et budgets d’attaque, en utilisant les distributions propres à chacun des profils. Elle doit couvrir au minimum les familles d’attaques primales, duales et hybrides, les tentatives exploitant les petits secrets et les échecs de décapsulation. Les paramètres de temps, mémoire, nombre de cibles et nombre de requêtes doivent être publiés.

L’objectif de recherche est une marge accrue face aux attaques Module-LWE. Le critère minimal de sélection est une résistance estimée au moins égale à celle de la référence dans chacun des modèles retenus ; tout gain annoncé doit être chiffré et accompagné de ses hypothèses. Toute discordance doit être expliquée et résolue avant le gel du profil. Une augmentation du coût d’une attaque sur les réseaux ne démontre pas, à elle seule, une augmentation de la sécurité de l’ensemble du KEM.

**C03.** Les conclusions doivent traiter les limites dues aux graines, au secret partagé et aux primitives symétriques. Le projet ne doit attribuer ni 1536 bits de sécurité au candidat, ni 384 bits par extrapolation linéaire. Une sortie plus longue d’une fonction de dérivation ne crée pas d’entropie supplémentaire.

### 7.2 Correction et bruit

**C04.** L’analyse doit calculer la distribution du bruit après décompression, produits polynomiaux et décodage. Elle doit inclure l’erreur d’arrondi et traiter la probabilité d’au moins une erreur parmi les 256 coefficients du message.

**C05.** Le seuil de sélection proposé est une probabilité totale d’échec, pour une paire de clés et un chiffré honnêtement générés, au plus égale à **2^(-174.8)** selon une méthode comparable à celle de la référence. Il s’agit d’un objectif du projet, choisi pour ne pas dégrader la correction publiée pour ML-KEM-1024 ; la valeur réelle du rang 6 reste à calculer. [Référence de comparaison : FIPS 203, tableau 1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).

La méthode doit distinguer une borne démontrée d’une estimation heuristique, préciser les hypothèses d’indépendance et quantifier l’effet du nombre de décapsulations. Les attaques utilisant des chiffrés malveillants nécessitent leur propre analyse ; C05 ne les couvre pas.

**C06.** Si P0 ne satisfait pas C05, la compression, puis les autres paramètres, doivent être réévalués. Une modification ne doit pas améliorer la correction au détriment de la résistance aux attaques sans comparaison explicite des deux effets. Le profil ne doit pas être gelé pour préserver une taille de clé ou de chiffré annoncée à l’avance.

Un million d’exécutions sans échec ne démontre pas une probabilité de l’ordre de 2^(-175). Avec zéro échec sur N essais indépendants, la borne binomiale unilatérale à 95 % est `1 - 0.05^(1/N)`, soit environ `3/N`. Les essais détectent les défauts d’implémentation ; l’analyse probabiliste traite les événements extrêmement rares.

## 8 Plan de vérification

Les nombres d’essais suivants sont des objectifs d’ingénierie du projet. Ils ne représentent pas une certification ni une preuve cryptographique.

| Référence | Vérification obligatoire | Seuil de passage |
|---|---|---|
| T01 | Mode témoin ML-KEM-1024 et primitives communes | Tous les vecteurs officiels retenus passent, sans écart inexpliqué |
| T02 | Vecteurs déterministes du profil P0 | Au moins 1000 cas publiés avec graines de test, sorties et états intermédiaires sélectionnés |
| T03 | Accord entre deux réalisations développées séparément | Accord octet pour octet sur T02, y compris les cas de rejet |
| T04 | Parcours KeyGen, Encaps, Decaps aléatoires | Au moins 10 000 parcours au prototype, puis 1 000 000 cumulés avant le gel du candidat ; zéro échec observé inexpliqué |
| T05 | Formats et frontières | Toutes les longueurs interdites proches des tailles attendues, troncatures, ajouts et coefficients non canoniques sont traités sans dépassement |
| T06 | Rejet implicite | Au moins 10 000 chiffrés de longueur correcte dont le rejet est établi par la référence ; vérification exacte du secret de remplacement |
| T07 | Fuzzing des interfaces de décodage et de décapsulation | Au moins 24 heures cumulées, corpus et configurations conservés ; aucun défaut non résolu |
| T08 | Mémoire et comportement indéfini | Analyse adaptée au langage et aux architectures ; aucun défaut détecté non résolu |
| T09 | Variations temporelles et inspection du code compilé | Protocole statistique préétabli, code inspecté et résultats publiés ; tout signal significatif est investigué |
| T10 | Reconstruction et portabilité | Linux x86-64 et Windows x86-64 ; sorties identiques sur les vecteurs déterministes |

Les vecteurs officiels de T01 doivent être issus d’une version identifiée des ressources [NIST ACVP](https://github.com/usnistgov/ACVP-Server). Ils ne valident que le témoin standardisé. Les vecteurs du rang 6 doivent être identifiés comme des vecteurs du projet.

T03 doit éviter une dépendance commune à l’ensemble du cœur arithmétique, qui masquerait les mêmes erreurs. Une comparaison entre deux enveloppes d’une même bibliothèque ne suffit pas.

Une simple altération de bit ne garantit pas, par principe, un rejet ou un secret différent. T06 doit identifier les cas attendus grâce à une référence indépendante et contrôler le chemin effectivement suivi. Ces traces doivent rester confinées à la configuration de test.

L’absence de signal lors de T09 ne constitue pas une preuve de temps constant. Le dossier doit préciser les processeurs, compilateurs, options, classes d’entrées, échantillons et limites des observations.

## 9 Implémentation et performances

**I01.** Le premier cœur devrait être portable, avec une implémentation de référence lisible et une interface indépendante de tout service réseau. Rust est le langage cible proposé ; un prototype mathématique distinct peut utiliser Python. Le choix définitif doit être consigné au jalon J0.

**I02.** Le code repris doit conserver ses licences et attributions. Les dépendances et chaînes de compilation doivent être figées par version et empreinte. L’usage d’un générateur aléatoire déterministe doit être impossible par inadvertance dans la configuration d’application.

**I03.** Une commande documentée doit construire le projet et lancer les contrôles disponibles sur la machine. Les essais longs doivent être activables séparément, avec leur durée et leurs résultats dans le rapport.

**P01.** Les mesures doivent couvrir KeyGen, Encaps et Decaps, ainsi que la mémoire maximale et les tailles échangées. La comparaison avec ML-KEM-1024 doit utiliser le même hôte et des implémentations comparables ; elle doit identifier si une réalisation dispose d’optimisations absentes de l’autre.

Le protocole proposé comprend un échauffement, cinq séries d’au moins 1000 opérations pour chaque fonction et la publication des médianes, percentiles 95 et données brutes. Le système, le processeur, le compilateur et la politique de fréquences doivent être décrits.

Aucun seuil absolu de latence n’est fixé avant l’identification d’un matériel cible. Le premier rapport doit proposer un budget mesurable pour la suite. Une démonstration applicative éventuelle doit utiliser un chiffrement symétrique authentifié et signaler séparément ses propres paramètres et coûts.

## 10 Livrables

| Livrable | Contenu nécessaire |
|---|---|
| Spécification du candidat | Profil identifié, algorithmes, encodages, interfaces et différences avec la base |
| Bibliothèque et outil en ligne de commande | KeyGen, Encaps, Decaps et auto-test sans exposition de secrets réels |
| Référence indépendante | Réalisation destinée aux comparaisons déterministes |
| Dossier de tests | Vecteurs, scripts, corpus, résultats, environnements et anomalies |
| Dossier cryptographique | Estimations des attaques, analyse du bruit, hypothèses et limites |
| Rapport de performances | Mesures brutes et comparaison avec ML-KEM-1024 |
| Distribution source | Licence ouverte, attributions, dépendances, instructions de construction et empreintes |
| Politique de maintenance | Versionnement, signalement privé des vulnérabilités et suivi des correctifs |

Les fichiers de test peuvent publier des graines synthétiques clairement identifiées. Les clés de production, secrets d’application et accès à des services réels sont exclus des livrables.

## 11 Jalons et décision de passage

| Jalon | Résultat à obtenir | Condition de passage |
|---|---|---|
| J0 Base de travail | Sources figées, examen des errata, profil P0 et contrat d’API | Registre des choix et des écarts complet |
| J1 Référence standardisée | Témoin ML-KEM-1024 reproductible | T01 réussi |
| J2 Faisabilité mathématique | Bruit, correction et attaques du rang 6 évalués | C01 à C06 documentés ; paramètres corrigés si nécessaire |
| J3 Prototype de rang 6 | Deux réalisations et parcours complets | F01 à F05, A01 à A07, T02 à T06 et seuil prototype de T04 satisfaits |
| J4 Candidat à examiner | Vérifications longues, durcissement et benchmarks | F06, S01 à S06, I01 à I03, P01 et T01 à T10 satisfaits ; aucun défaut bloquant ouvert |
| J5 Revue indépendante | Examen externe de la spécification et de l’implémentation | Observations publiables traitées, risques résiduels décrits et périmètre de revue identifié |

Un prototype peut être publié dès J3 avec son statut expérimental. Le gel d’un candidat exige J4. La présentation comme composant destiné à un usage réel exige une revue indépendante adaptée à cet usage et une décision explicite fondée sur ses conclusions.

Une révision substantielle des paramètres, des encodages ou des algorithmes doit rouvrir les contrôles affectés. Aucune catégorie NIST supplémentaire, certification FIPS, primauté mondiale ou supériorité globale ne doit être annoncée sur la seule base d’un rang plus élevé ou de tests réussis.

## 12 Antécédents et références

Le rang 6 possède un antécédent théorique : Boudgoust et Scholl décrivent un jeu nommé Kyber1536 dans le cadre d’un chiffrement à seuil, avec une présentation simplifiée omettant la compression du chiffré. Cet antécédent doit être cité dans la future spécification ; il n’établit pas la validation du profil P0. Voir leur [article et sa notice IACR, section 6 et annexe E](https://eprint.iacr.org/2023/016).

Les références servent à préciser les bases et les comparaisons. Les exigences identifiées dans ce cahier des charges et les choix du rang 6 sont ceux du projet.

- [NIST FIPS 203 et mises à jour potentielles](https://csrc.nist.gov/pubs/fips/203/final).
- [Texte de FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf).
- [NIST SP 800-227 sur les mécanismes d’encapsulation](https://csrc.nist.gov/pubs/sp/800/227/final).
- [NIST FIPS 202 sur SHA-3 et SHAKE](https://csrc.nist.gov/pubs/fips/202/final).
- [Spécification des auteurs de CRYSTALS-Kyber version 3.02](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf).
- [NIST ACVP Server et ressources de validation](https://github.com/usnistgov/ACVP-Server).
- [kyber-py, outil pédagogique et expérimental](https://github.com/GiacomoPope/kyber-py).
- [Boudgoust et Scholl, IACR ePrint 2023/016](https://eprint.iacr.org/2023/016).

**État initial :** le cahier des charges est rédigé ; aucun algorithme du rang 6 n’a encore été implémenté ou validé dans ce projet. Le prochain travail porte sur J0, puis sur la référence standardisée et la faisabilité mathématique.
