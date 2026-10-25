# Projet KEM 1536

Espace de travail local pour un KEM expérimental à **six polynômes de 256 coefficients**, indépendant des systèmes Majax existants.

**Moteur expérimental disponible.** Le profil **KEM1536-DEV-Q7681-R1**
réalise KeyGen, Encaps et Decaps en Rust, avec une référence Python
indépendante. Les 1000 vecteurs synthétiques concordent octet par octet ;
10000 échanges frais et 10000 rejets appariés sont contrôlés. Voir le
[guide du moteur](MOTEUR_KEM_R1.md), sa
[spécification](SPECIFICATION_DEV_Q7681_R1.md) et la
[feuille de route](FEUILLE_DE_ROUTE_MOTEUR.md). Le développement
avance sur autorisation de l'utilisateur en parallèle de J2 ; aucune
validation de sécurité, de temps constant ou de J3 n'est acquise.

**Durcissement M02 exécuté.** Buffers secrets fixes et effacés,
arithmétique spécialisée, régression intégrale Windows/Linux et
10000 mutations confrontées à Python. Les campagnes de 20000 formats
et 10000 mutations passent aussi sous AddressSanitizer avec détection
de fuites. Le diagnostic temporel borné ne dépasse pas son seuil,
sans preuve générale de temps constant. Le [dossier M02](DURCISSEMENT_MOTEUR_M02.md)
conserve mesures, limites et commandes de reproduction.

**M03 : performances mesurées et campagne longue lancée.** Les 60000
observations Windows/Linux, les inventaires des binaires et un constat
mémoire ouvert sont dans le [dossier M03](M03_FUZZ_BINAIRES_BENCHMARKS.md).
Le contrôle court final retrouve 511 requêtes déterministes entre Rust
et Python. La campagne de quatre fois six heures CPU est suivie dans
`artifacts/generated/m03-long-001/progress.json` ; sa fin n'est pas anticipée.

**État actuel au 25 octobre 2026 : moteur R1 fonctionnel de référence et analyse J2 ouverte.** P0 échoue au seuil de correction dans le modèle étudié. R1 utilise q=7681/η=3/u exact/dv5 comme base d'essai, sans sélection finale du candidat. H13 a conclu l'extension des moments à N=32. Le [rapport](RAPPORT_RECHERCHE.md), le [journal](JOURNAL_RECHERCHE.md), la [revue des attaques au 24 octobre](VEILLE_ATTAQUES_2026.md) et les instantanés scientifiques préparent le futur article.

La priorité est de terminer la faisabilité avant la sélection finale des paramètres. Le [diagnostic de décapsulation de P0](DIAGNOSTIC_DECAPSULATION_P0.md), conservé dans `run-003`, isole les erreurs de compression et renforce le rejet sous les hypothèses restantes, sans indépendance de l'arrondi final v. Aucun profil de remplacement n'est choisi.

`run-004` ajoute un [témoin de correction avec u exact](DEPENDANCES_ARRONDI_U.md) à q=7681,η=3. La borne de queues 2^-319,633504 et un certificat Chernoff rationnel indépendant 2^-310,085969 satisfont C05 dans le modèle de primitives CBD, sans indépendance des arrondis. Ce témoin de 2656 octets de chiffré théorique ne clôt pas J2 et ne sélectionne aucun profil.

Le [registre des hypothèses](REGISTRE_HYPOTHESES.md) formalise désormais les pistes proposées. H01, [précision mixte](PRECISION_MIXTE.md), teste 240 configurations dans `run-005` et trouve un certificat de 2581 octets : 75 octets gagnés sur le témoin, dont 11 attribuables à la précision mixte de u. Le rapport distingue les 25 cas certifiés des 215 cas non certifiés par cette majoration ; aucun nouveau profil n'est sélectionné.

H02, [quantification décalée par paires](QUANTIFICATION_PAR_PAIRES.md), conserve dans `run-006` un point de 2567 octets avec une borne 2^-175,665600, grâce au support joint `|δ1|+|δ2|≤1`. Il gagne 14 octets sur H01 et reste un point de frontière à faible marge, sans profil sélectionné. La couverture au module réel et la fraction du certificat sont vérifiées indépendamment.

Le témoin ML-KEM-1024 passe 145 cas officiels ACVP sélectionnés, dont 15 rejets implicites, et 32 échanges avec des clés fraîches sous Windows. Les opérations du rang 6 sont implémentées pour R1 ; P0 reste un profil historique de métadonnées, sans moteur propre.

## Démarrer

Depuis ce dossier :

```powershell
.\scripts\engine.ps1 self-test
.\scripts\dev.ps1 check
.\scripts\dev.ps1 profile
.\scripts\dev.ps1 reference
```

Sur une nouvelle machine Windows, exécuter d’abord `.\scripts\bootstrap.ps1`. Les outils et caches sont locaux à `.tools/` et les sorties de compilation à `target/`.

## Organisation

```text
NIST/
  CAHIER_DES_CHARGES_KEM_1536.md   Exigences et critères de passage
  profiles/                      Paramètres versionnés du candidat
  crates/kem1536/                 Bibliothèque de travail
  crates/kem1536-cli/             Commandes locales
  crates/kem1024-reference/       Témoin standardisé et contrôles ACVP
  references/                    Publications, errata et manifeste des sources
  research/                      Vérifications et études mathématiques
  results/                       Instantanés scientifiques versionnés
  vectors/                       Emplacement des futurs vecteurs
  scripts/                       Installation locale et contrôles
  docs/                          Guide de développement
  artifacts/                     Organisation des rapports
  .github/workflows/             Contrôles automatiques prévus
```

## Profil initial

Le profil `KEM1536-EXP-P0` utilise n=256, k=6, q=3329, eta1=eta2=2, du=11 et dv=5. Ses tailles calculées sont 2336 octets pour la clé d’encapsulation, 4704 pour la clé de décapsulation développée et 2272 pour le chiffré. Il est conservé comme point de départ : sa borne d’union d’échec vaut environ 2^-118,44 dans le modèle, au-dessus de l’objectif 2^-174,8. Il n’est pas retenu pour un gel algorithmique.

Le nombre 1536 désigne le nombre de coefficients du vecteur. Aucune sécurité de 1536 bits n’est revendiquée.

## Références et témoin

Le contrat initial de J0 est décrit dans [le contrat algorithmique](CONTRAT_ALGORITHMIQUE.md). L’[examen des errata](ERRATA_FIPS203.md) précise les deux clarifications retenues pour lire la copie de FIPS 203.

Le témoin utilise RustCrypto `ml-kem 0.3.3`, vérifié contre les fichiers NIST ACVP du commit enregistré dans `references/manifest.json`. Les clés des vecteurs sont publiques et réservées aux tests. La commande `reference` produit `artifacts/generated/reference-1024.json`, sans afficher les clés ou les secrets partagés.

Ces contrôles valident le témoin sur la sélection documentée. `run-001` conserve huit scénarios de bruit et 24 estimations historiques. `run-002` ajoute 120 évaluations modernes sous Sage, dont 118 coûts retournés et deux erreurs BKW de P0 conservées. Les modèles de score révisés, le dual avec codes/rotations et les attaques exploitant les échecs restent à compléter avant de clore J2.

Pour reproduire l’analyse sous Windows :

```powershell
.\scripts\research-setup.ps1
.\scripts\dev.ps1 analysis
```

Les nouvelles sorties courantes vont dans `artifacts/generated/j2/`. L’instantané scientifique `results/j2/run-001/` est conservé avec les empreintes des entrées et sorties.

Pour la comparaison moderne sous WSL Ubuntu 22.04 :

```powershell
.\scripts\bootstrap-modern.ps1
.\scripts\dev.ps1 modern
```

Les sorties courantes vont dans `artifacts/generated/modern/` ; l'instantané conservé est `results/j2/run-002/`. Le cache Sage temporaire et les archives de paquets restent sous `.tools/`. Le contrôle ordinaire des instantanés ne nécessite pas Sage.

Consulter le [guide de développement](DEVELOPPEMENT.md) et le [cahier des charges](../CAHIER_DES_CHARGES_KEM_1536.md) pour les commandes, les jalons et les exigences cryptographiques.

La [comparaison d'utilité H01/H02](UTILITE_COMPRESSION.md) conserve maintenant neuf propositions à seuil commun dans `run-007`. À une exigence de borne d'échec ≤2^-200, H02 gagne neuf octets (0,347 %) sur le contrôle simple. Le rattachement aux estimations de clé publique existantes n'apporte aucun nouveau coût d'attaque ni validation des effets propres au format. J2 reste ouvert.

Le [dual avec codes et rotations](DUAL_CODES_ROTATIONS.md) dispose d'un adaptateur calibré : six points publiés reproduits, 1043 évaluations et quatre contre-vérifications à haute précision dans `run-008`. Les coûts du rang 6 restent conditionnels à un modèle GV idéal, aux hypothèses de score, de réduction et de mémoire ; aucun niveau global ni profil n'est validé.

La [stabilisation locale du dual](STABILISATION_DUAL.md) est conservée dans `run-009` : 1187 évaluations nouvelles, 44 trajectoires et quatre points contrôlés sur leurs 32 voisins unitaires d'un ou deux axes, avec contre-vérifications à haute précision. La recherche précise le coût conditionnel estimé au rang 6, sans changer le candidat ni établir un optimum global. Les études suivantes `run-010` et `run-011` traitent le décodeur concret et sa contribution CBD au score ; le score complet reste ouvert.

Les [décodeurs auxiliaires concrets](DECODEUR_CONCRET.md) sont implémentés et exécutés en 7681 dans `run-010`. Pour le code pondéré 140/21, la norme moyenne observée vaut 1,177973 fois le rayon idéal de référence et le décodage exact prend environ 6,752 ms dans le prototype local. Les petits modèles exhaustifs et un vérificateur indépendant contrôlent les résultats. Le score dual et le coût d'attaque restent à justifier ; Decaps du KEM n'est pas implémenté par cette brique.

L'étude [des contributions CBD aux scores](SCORES_DECODEUR.md), figée
dans `results/j2/run-011`, analyse les 2048 résidus des décodeurs auxiliaires.
Elle distingue la dépendance directionnelle du biais, la majoration par norme
et les covariances à secret partagé. Six lois exhaustives et 114 contrôles
à 160 décimales passent. Le score complet de l'attaque et ses queues restent
ouverts ; aucun nouveau coût d'attaque ni profil du KEM n'est sélectionné.

Le [critère CBD comparé à la distance](DECODEUR_CRITERE_CBD.md) est figé
dans `run-012`, après préenregistrement du protocole H05. Les 38 400 blocs
réels ont un minimum CBD certifié. Au point pondéré 140/21, le biais moyen
augmente de 0,43 % sur les cibles fixes, pour environ 25 % de temps local
supplémentaire, certification comprise. Le critère est conservé comme témoin ;
le score complet de l'attaque reste la priorité avant toute révision de coût.

Le [score dual complet sur un modèle réduit](SCORE_DUAL_COMPLET_REDUIT.md)
est figé dans `run-013` : relations duales, résidus, bruit LWE et toutes les
hypothèses de Fourier. Une seconde énumération par bits retrouve les lois
et 80 608 scores. Une meilleure moyenne peut donner un moins bon classement ;
le témoin uniforme montre aussi qu'une variance conforme ne suffit pas à
justifier une queue normale. Ces constats restent limités aux paramètres
réduits et ne révisent pas les coûts d'attaque du rang 6.

La [famille élargie avec LLL](LLL_ET_FAMILLE_ELARGIE.md), figée dans
`run-014`, couvre 32 matrices, trois tailles de liste et 768 panneaux
(224 banques distinctes). La réduction rationnelle en dimension 3 est
certifiée ; son énumération bornée manque néanmoins certains préfixes
exhaustifs. Les contre-exemples de classement et les écarts aux queues
normales persistent dans cette famille réduite, sans coût de sécurité
révisé pour le rang 6.

Les [lois CBD(2)/CBD(3) et réseaux de dimensions 3/5](CBD_ET_DIMENSIONS_SUPERIEURES.md)
sont traités dans `run-015` : 1152 panneaux, 155 banques et 96 lois jointes
exactes, couvrant jusqu'à 2^54 configurations par récurrence entière.
Une méthode indépendante par couches Bernoulli retrouve les lois et tous
les scores. Les contrôles CBD(1) reproduisent H07 exactement. Les limites
de classement et de queues restent visibles, sans révision de la sécurité
globale du rang 6.
