# Programme M04 — Améliorer le moteur KEM1536

25 octobre 2026. Programme de développement en réponse à la demande de
porter le moteur au niveau du démonstrateur 1024 puis de rechercher un
avantage démontrable. Les [résultats exécutés M04](M04_MOTEUR_NTT_ET_CONTROLES.md)
consignent l'argument conditionnel, le lien de correction, les attaques,
la correction mémoire, la NTT, les contrôles et les doubles builds.
Ils ne remplacent pas les conditions C01–C06 du
[bilan J2](BILAN_J2_ET_DECISION_PROTOTYPE.md).

Le profil R1, ses formats et ses corpus restent la base de comparaison.
Les changements d'implémentation compatibles doivent retrouver ses octets.
Un changement de paramètres, de dérivation ou de construction exige une
nouvelle identité de profil et ses propres preuves. Les méthodes de
recherche restent libres ; une approbation institutionnelle préalable
n'est pas requise pour les développer et les évaluer.

## Priorité confirmée par l'utilisateur

Les trois travaux scientifiques sont exécutés avant les modifications du
moteur : [argument de sécurité exact](ARGUMENT_SECURITE_R1.md),
[certificat relié au programme](LIEN_CERTIFICAT_PROGRAMME_R1.md), puis
[attaques dans un cadre commun](COMPARAISON_ATTAQUES_CADRE_COMMUN_R1.md).
L'instantané `results/security/m04-001` conserve leurs sources et sorties
avant optimisation. Douze nouveaux tests passent. L'argument IND-CCA concret
et le QROM restent ouverts ; aucun dossier institutionnel n'est constitué.
La suite autorisée porte sur les cinq livraisons de construction ci-dessous.

## Séquence de construction après les trois travaux scientifiques

| Ordre | Livraison concrète | Critère de sortie |
|---|---|---|
| 1 | Qualification puis correction de M03-A01, temporaire polynomial de 512 octets sans effacement explicite dans le binaire Windows analysé | Le chemin corrigé n'introduit plus ce temporaire, ou son effacement est explicite dans les binaires visés ; corpus complets inchangés ; ASan et contrôles ciblés repassés. Ne pas en déduire la disparition générale des copies secrètes. |
| 2 | NTT scalaire pour la multiplication négacyclique, en conservant la convolution directe comme oracle | Identités transformée/inverse, multiplication et bornes vérifiées ; 1000 vecteurs et 10000 rejets intégraux inchangés sous Windows/Linux ; nouveau contrôle mémoire/temporel et mesures P50/P95 avec la méthode P01. |
| 3 | Contrôle de durcissement sur les chemins et binaires réellement livrés | Classes de clés/chiffrés plus variées, adresses et branchements sensibles examinés, transferts indirects qualifiés ; écarts documentés par cible et compilation. Les diagnostics statistiques ne deviennent pas une preuve générale de temps constant. |
| 4 | Distribution et intégration au niveau du projet 1024 | Deux builds isolés identiques octet par octet pour une cible fixée, provenance et inventaire des dépendances ; exemple consommateur de la bibliothèque et démonstration KEM → KDF → AEAD avec tests d'altération et contrat d'authentification explicite. |
| 5 | Comparaison directe des deux dépôts, puis revue indépendante | Même machine, même périmètre de chronométrage et mêmes contraintes ; latence, tailles, mémoire et coût d'intégration publiés ; dossier exploitable par des relecteurs externes. Aucun tiers contacté par ce programme. |

La NTT est une piste compatible avec les paramètres actuels :
7681−1 = 15×512, avec 2n=512 pour n=256. La racine 4055 satisfait
ψ^256 = −1 modulo 7681 et permet une NTT négacyclique complète.
Cette possibilité algébrique ne prouve ni un gain de vitesse ni une
résistance accrue aux attaques. Les boucles, réductions, accès mémoire
et temporaires de la réalisation doivent être étudiés à nouveau.
Aucun facteur d'accélération n'est annoncé avant mesure.

Le premier lot de code doit porter sur M03-A01 et ses régressions, puis
sur la NTT scalaire. Les optimisations AVX2/NEON viennent après un cœur
scalaire vérifié. Ne pas ajouter simultanément compression nouvelle,
paramètres nouveaux et optimisation arithmétique : leurs conséquences
doivent rester attribuables.

## Argument de sécurité à développer en parallèle

1. **Contrat et transformation du KEM.** Décrire les adversaires, requêtes,
   clés honnêtes/importées, hypothèses MLWE et primitives, modèles
   classiques/quantique, ROM/QROM et pertes de correction. Vérifier les
   conditions d'une transformation de type Fujisaki–Okamoto pour cette
   construction précise. Livrer une analyse argumentée soumise à relecture,
   ou des conditions ouvertes explicitement identifiées ; pas une preuve
   héritée de ML-KEM.
2. **Correction reliée au programme.** Rattacher le certificat rationnel de
   run-004 aux opérations et distributions effectivement implémentées.
   La borne ≤2^-310,085969 reste conditionnelle au modèle CBD et aux
   hypothèses de primitives documentées. Distinguer clés, requêtes et
   événements adversariaux ; des échanges honnêtes ne mesurent pas ce taux rare.
3. **Comparaison commune des attaques.** Consolider C02 avec le témoin
   ML-KEM-1024 : mêmes versions, budgets, probabilités, modèles de
   réduction, temps/mémoire et cibles. Séparer classique et quantique.
   Couvrir les familles pertinentes, les structures de l'anneau et les
   attaques par échecs/oracles. Classer les angles morts et sensibilités.
   Ne pas prolonger automatiquement les petites études de moments H13.
4. **Relecture extérieure distincte.** Préparer un dossier de construction
   pour la cryptanalyse et un dossier de code pour l'audit d'implémentation.
   Conserver les critiques, résultats négatifs et corrections versionnées.

Un objectif supérieur doit être circonscrit : meilleure marge de correction
dans un modèle commun, durcissement vérifié d'un chemin précis, coût inférieur
à une référence donnée, ou estimation plus favorable face à une famille
d'attaques avec les mêmes hypothèses. Ni le nombre de coefficients, ni celui
des tests, ni l'optimisation arithmétique ne prouvent une supériorité globale.

## Trajectoire institutionnelle

La normalisation d'une construction et la validation d'une implémentation
sont des démarches distinctes. FIPS 203 spécifie ML-KEM-512/768/1024 ;
R1 n'est pas l'un de ces ensembles. Le CAVP teste des fonctions approuvées,
et la validation de module CMVP/FIPS 140-3 ajoute ses propres exigences.
Une validation de primitives ou un audit ne normalise pas automatiquement R1.

Préparer dès maintenant une spécification complète, des justifications,
des résultats reproductibles, une analyse de sécurité et des retours
indépendants est utile à un futur dossier. La recevabilité et le cadre
d'une proposition de nouveau KEM devront être confirmés avec le NIST ;
aucune procédure ouverte ou sélection n'est présumée.

Sources officielles consultées le 25 octobre 2026 :

- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).
- [Recommandations KEM SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final).
- [CAVP](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program).
- [CMVP](https://csrc.nist.gov/projects/cryptographic-module-validation-program).
- [État du programme PQC](https://csrc.nist.gov/projects/post-quantum-cryptography).

## État historique au pointage de la proposition initiale

La reconstruction publique Windows/Ubuntu et les 95 tests Python existent
déjà ; ils ne sont pas à présenter comme une prochaine fonctionnalité.
L'identité octet par octet des binaires R1 reste à établir.

La campagne M03 existante est active sur ses quatre travailleurs au pointage
du 25 octobre 2026 à 18 h 33, heure locale. Environ 32994 secondes CPU
cumulées sont observées à cet instant, sur un objectif de 86400 secondes.
Ce pointage ne clôt pas la campagne et ne préjuge pas sa validation finale.
Aucun processus n'a été arrêté ou remplacé pour préparer ce programme.

À ce pointage initial, aucun correctif mémoire, NTT ou gain de performance
n'était livré. La réalisation effectuée ensuite est décrite dans le
[bilan M04](M04_MOTEUR_NTT_ET_CONTROLES.md) ; l'argument de sécurité
concret et le QROM y restent explicitement conditionnels ou ouverts.

