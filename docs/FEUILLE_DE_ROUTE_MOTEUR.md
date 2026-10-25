# Du dossier de faisabilité au moteur KEM

Décision du 25 octobre 2026, à la demande de l'utilisateur : l'objectif
central est un moteur cryptographique ouvert à six polynômes de 256
coefficients. Chaque étude doit servir une décision pour sa construction.
Le futur article décrit ce travail et ses limites ; son écriture ne
remplace pas le développement du moteur.

**Actualisation M01.** L'utilisateur demande ensuite d'avancer sur le
moteur sans attendre de nouvelle validation. Le [bilan opérationnel](BILAN_J2_ET_DECISION_PROTOTYPE.md)
autorise le prototype R1 en parallèle de J2. Les opérations et la seconde
réalisation sont maintenant disponibles ; le [guide du moteur](MOTEUR_KEM_R1.md)
consigne corpus, essais, commandes et limites. La décision ne sélectionne
pas un candidat final et ne valide aucun jalon encore ouvert.

## Livrables et état effectif

| Livrable | État | Critère vérifiable |
|---|---|---|
| Témoin ML-KEM-1024 | Implémenté séparément | Cas ACVP et échanges frais |
| Correction du rang 6 | P0 rejeté ; témoin q=7681/η=3/u exact/dv=5 certifié dans le modèle CBD | run-003/run-004, C04/C05 |
| Résistance estimée | Familles évaluées, hypothèses et limites du dual documentées | Bilan C02 à achever, sans niveau global acquis |
| Arithmétique polynomiale de référence | Première brique Rust disponible | Convolution indépendante, lois de l'anneau et signe X^256=−1 |
| Profil de développement du rang 6 | R1 spécifié comme base d'essai | Domaines/formats propres, sans sélection finale |
| KeyGen / Encaps / Decaps du rang 6 | Rust et référence Python disponibles | 1000 vecteurs concordants, 10000 échanges frais et rejets appariés |
| Durcissement et performances | M03 : P01 mesuré, campagne longue lancée ; J4 ouvert | 60000 observations Windows/Linux ; quatre objectifs de six heures CPU ; constat mémoire M03-A01 encore ouvert |

L'oracle générique dans Z_q[X]/(X^256+1) reste distinct du moteur.
Le cœur R1 emploie depuis [M02](DURCISSEMENT_MOTEUR_M02.md) une convolution
spécialisée en q=7681, des réciproques entières et des buffers fixes effacés.
Les corpus complets retrouvent les octets M01 sous Windows et Linux.
La NTT et la preuve générale de temps constant restent ouvertes ; toute
optimisation doit retrouver les oracles sur des vecteurs communs.

## Finir J2 avec un bilan de décision

Le bilan opérationnel reprend les exigences du cahier des charges une
par une. Il permet le codage exploratoire sur l'autorisation ultérieure
de l'utilisateur ; le dossier de validation de J2 reste à compléter.

| Exigence | Éléments déjà disponibles | Travail restant pour la décision |
|---|---|---|
| C01 : IND-CCA et hypothèses | Contrat initial et transformation de référence | Expliciter les conditions pour le profil envisagé et ses écarts, y compris les modèles quantiques pertinents |
| C02 : comparaison des attaques | run-001/run-002 et études duales run-008 à run-020 ; veille conservée | Consolider temps/mémoire/cibles/requêtes, couverture des échecs et limites restantes ; classer ce qui bloque le prototype |
| C03 : limites symétriques | Graines et secret partagé de 32 octets dans le contrat initial | Écrire le plafond revendicable et le rattacher au candidat envisagé |
| C04/C05 : bruit et échecs | Rejet P0 et certificat du témoin simple ; variantes de compression comparées | Choisir une base de développement seulement après examen commun de la correction et des attaques ; conserver la marge et les hypothèses |
| C06 : compromis | Comparaisons à seuils communs run-007 | Consigner la décision, les tailles et les raisons de retenir ou écarter les variantes |

J2 n'exige pas de prétendre résoudre toutes les questions ouvertes de
cryptanalyse. Il exige un dossier explicite conforme à C01–C06. Une
question non résolue doit être classée pour sa conséquence sur le candidat
et le prototype, sans être automatiquement remplacée par une nouvelle
série d'expériences. Aucune conclusion de sécurité n'est présumée.

## Limite du volet H13

H13 borne les moments jusqu'à quatre à N=32 sur les listes figées, pour
déterminer ce que le témoin uniforme permet réellement de comparer.
Une fois ce résultat obtenu et contrôlé, arrêter cette extension : pas
de passage automatique à 64/128, pas de recherche automatique du sixième
moment. Les limites de queue et de dimension restent inscrites au bilan
C02, sans être effacées ni transformées en validation du modèle normal.

Le **bilan de développement J2 → J3** est désormais écrit et le prototype
est fonctionnel. M02 a traité la mémoire, l'arithmétique et une seconde
cible Linux/WSL, avec corpus malveillants et contrôle instrumenté.
M03 conserve les désassemblages intégraux et 60000 observations P01 ;
le fuzzing à couverture guidée de longue durée est lancé. La suite porte
sur la revue des données finales et la qualification de M03-A01 avant
une optimisation ou une revendication d'effacement plus forte.
Le dossier cryptographique J2 continue
en parallèle, avec ses limites explicites.

## Ordre de construction du moteur

1. Arithmétique de référence et représentation canonique des polynômes.
   La convolution directe est disponible ; compléter les conversions
   et un oracle distinct avant les optimisations.
2. Encodages, compression/décompression et échantillonnages, selon le
   profil de développement qui sera consigné. Contrôler rejets, limites,
   séparation de domaine et compteurs ; réutiliser les primitives SHA3/SHAKE
   prévues au cahier des charges.
3. Parcours déterministes internes de référence, puis KeyGen, Encaps et
   Decaps de rang 6, selon l'autorisation expérimentale M01. Produire les vecteurs comparables
   entre les deux réalisations exigées par J3.
4. Interface d'application avec aléa système, types distincts, validation
   des entrées et rejet implicite. Les graines déterministes restent dans
   les interfaces de tests ; aucune clé d'application n'est importée.
5. Durcissement, mémoire et benchmarks des trois opérations, puis revue
   externe suivant le cahier des charges. Statut expérimental explicite.

Chaque étape de développement met à jour le journal et le rapport,
ajoute les vérifications utiles et livre du code exécutable ou un
critère de décision vérifiable. Aucun déploiement ou publication n'est
effectué implicitement.
