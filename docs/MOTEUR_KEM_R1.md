# Moteur KEM1536-DEV-Q7681-R1

Le dépôt **MLKEM-1536 Core** conserve M10 comme référence exécutable livrée.
Les cycles de recherche suivants vont jusqu'à M15 : leur
[bilan public de portée](ETAT_RECHERCHE_M15.md) présente les avancées de
sécurité et de conformité, ainsi que la séparation entre preuves publiques
rejouables et résultats internes dont les artefacts restent privés. Ces
travaux n'ont pas modifié le code, les paramètres, les formats ou le binaire
canonique du moteur. C01 reste ouvert et Messenger n'est pas autorisé.

Le moteur expérimental réalise **KeyGen, Encaps et Decaps** en Rust,
avec une réalisation Python développée séparément pour les contrôles.
Sa [spécification](SPECIFICATION_DEV_Q7681_R1.md) a été enregistrée avant
les vecteurs au commit e325f50. Le [bilan J2](BILAN_J2_ET_DECISION_PROTOTYPE.md)
explique l'autorisation de développer en parallèle des questions ouvertes.
Le code ne constitue pas une certification ou une validation de J2/J3/J4.

Le [dossier M03](M03_FUZZ_BINAIRES_BENCHMARKS.md) ajoute les mesures P01
Windows/Linux (60000 observations), les désassemblages complets et la
campagne longue lancée sur quatre cibles. Il documente aussi M03-A01,
copie temporaire sur pile non explicitement effacée dans la multiplication
Windows. [M04](M04_MOTEUR_NTT_ET_CONTROLES.md) corrige ce constat précis
dans les binaires livrés, ajoute la NTT, des régressions complètes, les
doubles builds et le comparatif direct des dépôts. Aucune garantie
générale d'effacement des copies n'est acquise.

## Ce qui est implémenté

- Anneau Z_7681[X]/(X^256+1), six polynômes, NTT scalaire négacyclique ;
  convolution directe conservée comme oracle indépendant.
- Représentation exacte canonique sur 13 bits, compression de v sur 5
  bits, conversion du message sur 256 bits et validation des longueurs.
- Matrice uniforme par rejet de candidats 13 bits ; bruit CBD(3) par
  extraction de bits SHAKE, indices de matrice et nonces spécifiés.
- Domaines propres au profil pour SHA3-256, SHA3-512, SHAKE128 et SHAKE256.
- Cœur PKE, génération de clés, encapsulation et décapsulation avec
  réencapsulation, comparaison/sélection via ctutils et secret de remplacement.
- Aléa du système pour les interfaces d'application, erreur explicite
  si la source échoue ; aucune API à graine déterministe dans le build par défaut.
- Types séparés pour clé publique, clé privée, chiffré et secret partagé.
  Pas de Debug/Serialize pour les secrets applicatifs. Effacement au drop
  des octets secrets possédés et des coefficients polynomiaux ; les
  temporaires, copies du compilateur et propriétés temporelles restent à auditer.

Le module [Rust](../crates/kem1536/src/dev_kem.rs) emploie désormais une
[arithmétique privée spécialisée](../crates/kem1536/src/engine_poly.rs)
en q=7681, confrontée à l'oracle générique distinct du dépôt. Le
[durcissement M02](DURCISSEMENT_MOTEUR_M02.md) documente les buffers fixes,
l'effacement et les réductions par réciproques entières.
La [référence Python](../research/kem_r1_reference.py)
utilise hashlib et une convolution entière NumPy de longueur 511,
suivie de la réduction négacyclique. Elle n'importe pas le cœur Rust
et code les bits par un entier Python plutôt que par les boucles Rust.
Cette référence est réservée aux données synthétiques ; ses secrets
ne bénéficient pas d'un effacement mémoire garanti.

| Objet R1 brut | Octets |
|---|---:|
| Clé publique | 2528 |
| Clé privée développée | 5088 |
| Chiffré | 2656 |
| Secret partagé | 32 |

Ces tailles diffèrent de P0 et de ML-KEM-1024. Les types R1 ne doivent
pas servir à interpréter automatiquement les formats d'un autre profil.

## Utilisation locale

Depuis la racine NIST, sous Windows :

```powershell
.\scripts\engine.ps1 build
.\scripts\engine.ps1 self-test
.\scripts\engine.ps1 check
.\scripts\engine.ps1 stress -Count 10000
.\scripts\dev.ps1 check
```

L'auto-test effectue 16 échanges et rejets avec aléa frais, puis affiche
uniquement un bilan. `stress` permet une campagne distincte de la suite
ordinaire. Les commandes `dev-profile` et `status` du binaire décrivent
le profil courant ; la commande historique `profile` conserve les
métadonnées de P0. Aucun fichier de clé réelle n'est créé par l'auto-test.

Sous Linux, les commandes équivalentes sont dans `scripts/engine.sh`.
La chaîne locale WSL2/Ubuntu 22.04 est pilotée par
`scripts/hardening-linux.sh` : tests avec/sans recherche, build release,
sondes assembleur et AddressSanitizer. M02 a exécuté ces contrôles et les
corpus sur cette seconde cible ; T10 reste à examiner sur plusieurs
machines natives. Les commandes ordinaires utilisent `--locked`.

Exemple d'utilisation de la bibliothèque Rust :

```rust
use kem1536::dev_kem::{keygen, encapsulate, decapsulate, Error};

fn exchange() -> Result<(), Error> {
    let (ek, dk) = keygen()?;
    let (ciphertext, sender_secret) = encapsulate(&ek)?;
    let receiver_secret = decapsulate(&dk, &ciphertext);
    assert!(sender_secret.matches(&receiver_secret));
    Ok(())
}
```

L'import de clés passe par `EncapsulationKey::from_bytes` et
`DecapsulationKey::from_bytes`. `Ciphertext::from_bytes` vérifie la
longueur ; les coefficients u non canoniques d'un chiffré bien dimensionné
suivent le rejet implicite. `Decaps` rend toujours le même type de secret,
sans révéler par un booléen si la réencapsulation a été acceptée.
La validation de dk vérifie sa canonicité et H(ek), sans attester une
génération honnête ou la relation t=A*s+e d'une clé importée.
Elle ne mesure pas non plus l'entropie du champ de rejet z. Un z fixé reste
syntaxiquement acceptable ; son acceptation n'établit pas les hypothèses de
sécurité applicables à une clé honnêtement générée.

## Corpus et résultats conservés

**1 000 vecteurs publics synthétiques** dans
`results/engine/r1-001/vectors.jsonl.gz` : d,z,m, clés, chiffré, secret,
secret de remplacement et états intermédiaires rho,sigma,A[0,0]. Les
douze champs concordent entre Rust et Python pour chaque cas. La clé
privée publiée est exclusivement une donnée de test synthétique.

**10 000 échanges frais et 10 000 rejets fonctionnels Rust** réussissent
dans la campagne conservée `fresh-diagnostics.json`. Durée globale
≈111,85 s sur cet hôte, incluant génération, encapsulation, décapsulation
et contrôle du remplacement. Ce temps n'est pas un benchmark P01 par
opération ; aucun secret réel de la campagne n'est enregistré.

**10 000 rejets appariés Rust/Python** sont conservés séparément dans
`results/engine/r1-rejections-001`. Les deux réalisations traitent les
mêmes chiffrés, tous de bonne longueur, avec un coefficient u=8191
non canonique ; un compteur sur les huit derniers octets les distingue.
La référence déchiffre et réencapsule chaque cas, établit le rejet et
retrouve exactement le secret J(z||c) calculé par Rust. Les 10 000
secrets de remplacement sont égaux entre réalisations, sans acceptation
par la référence. La campagne utilise uniquement la clé synthétique 0.
Sa durée appariée instrumentée est ≈84,50 s. Cette famille de rejets
ne couvre pas tout l'espace des chiffrés malveillants.

Les tests unitaires ajoutent les longueurs proches à ±1..32 octets,
les coefficients non canoniques en début et fin de vecteur, les hashes
de dk corrompus, le chiffré canonique nul dont le rejet est établi,
les arrondis et les formats. Un test du build de recherche lie le moteur
courant à l'empreinte du cas 0 déjà confronté à Python.

Les sources utilisées sont **copiées et liées par empreintes** dans
chaque instantané moteur. Cela préserve la réalisation testée tout en
permettant de continuer à développer le code courant. Les empreintes
des exécutables de recherche et de diagnostic sont distinguées ; elles
identifient les exécutables utilisés sans promettre une compilation
reproductible octet par octet. Les vingt instantanés J2 restent figés.

## Rejouer les confrontations

```powershell
# Rejeu intégral Python des 1000 vecteurs et du premier corpus de rejet
.tools/research-venv/Scripts/python.exe research/validate_engine_r1.py
# Rejeu des 10000 rejets appariés à Rust
.tools/research-venv/Scripts/python.exe research/validate_rejections_r1.py
```

`dev.ps1 check` vérifie les empreintes complètes, rejoue 16 vecteurs et
16 rejets appariés, exécute les tests Rust avec/sans la fonctionnalité
de recherche et l'auto-test frais. Les limites de ces échantillons sont
affichées dans les sorties. Les campagnes intégrales ci-dessus sont
distinctes ; leur génération et leur validation complètes sont conservées.

L'export de nouvelles données synthétiques exige le build explicite
`research-vectors` et les commandes `dev-vectors` ou
`dev-rejection-vectors`. Les numéros de cas déterminent les graines
publiques via un domaine TEST propre ; aucune graine d'application n'est
acceptée par cette interface. Ne jamais utiliser ces clés pour une application.

## Critères restant ouverts

Depuis M06, le cœur transforme une seule fois les opérandes réutilisés et
accumule les six produits dans le domaine NTT, avec inverse dans un
propriétaire fourni par l'appelant. Les comptes testés sont 48/55/68
transformations pour KeyGen/Encaps/Decaps, contre 108/126/144 auparavant.
La décapsulation rejetée du test exige aussi 68 transformations. Les
formats, domaines et octets R1 restent identiques sur les corpus
intégraux Windows/Linux. Les [mesures M06](M06_MESURES_ET_DURCISSEMENT.md)
établissent un gain sur la machine enregistrée et une hausse de certaines
frames de pile ; la [contre-revue M06](M06_REVUE_INDEPENDANTE.md) distingue
le traitement des propriétaires des obligations globales encore ouvertes.

Les seuils numériques de T02/T03 sont atteints sur ce corpus R1 ;
la campagne T04 comporte 10 000 échanges ; le corpus apparié T06
comporte 10 000 rejets exacts dans la famille spécifiée. Ces constats
ne valident pas globalement J3 : les exigences d'architecture, de
sécurité et de formats doivent encore être examinées ensemble.

M02 a corrigé la croissance du buffer secret, protégé les temporaires
possédés, confronté les corpus sous Windows/Linux, traité 20000 formats
et 10000 mutations par cible, puis répété ces deux campagnes sous
AddressSanitizer avec détection de fuites, sans erreur signalée. Les
10000 mutations comprennent 5351 chiffrés distincts. Le diagnostic
temporel limité ne dépasse pas le seuil préétabli, sans démonstration
générale de temps constant. Voir les résultats et limites dans le
[dossier M02](DURCISSEMENT_MOTEUR_M02.md).

Poursuivre le fuzzing long à couverture guidée, la revue mémoire et
temporelle complète, les optimisations après la NTT déjà livrée,
la portabilité native et la cryptanalyse J2. Les mesures M04 sont
réalisées sous charge et sont distinctes des mesures historiques P01.
T07/T08/T09/T10 ne sont pas validés globalement par ces seuls contrôles ;
le million de parcours avant gel et la revue externe restent à faire.
Aucune sécurité globale ou preuve IND-CCA propre à R1 n'est revendiquée.

Le bilan historique M01 conserve 25 tests Rust par configuration,
87 tests Python et 603 empreintes indexées. M02 ajoute les contrôles de
réduction, d'effacement et du diagnostic, ainsi qu'un troisième instantané
moteur. `check` vérifie ses empreintes, recalcule toutes les statistiques
temporelles et rejoue 16 mutations indépendamment ; la campagne complète
de 10000 mutations est conservée séparément. Le journal consigne le bilan
final de vérification M02. Aucun fuzzing long ou audit externe n'en est déduit.


Depuis M07, le moteur traite les lignes en coefficients dans des propriétaires
réutilisés, sans modifier les formats R1 ni les comptes NTT 48/55/68.
Le [bilan mémoire et livraison](M07_MEMOIRE_ET_VALIDATION.md) décrit les
mesures Windows/Linux, leurs limites, la revue propre aux nouveaux binaires
et les paquets. L’[archive M07](../results/engine/m07-001/) conserve les
exécutables originaux revus, la source compacte compilable, les licences
et les reçus des répétitions de build. Le CLI livré conserve les auto-tests
frais et désactive les commandes de recherche.

M08 remplace la reconstruction de polynômes pendant l'import par un contrôle
direct des encodages. Les 192 groupes de 13 octets couvrent les 1536 coefficients
du vecteur. Le masque cumulé ne provoque une décision qu'après le balayage
complet ; l'ordre privé longueur → secret → public intégré → hash est conservé.
Les opérations PKE, formats, domaines et comptes NTT 48/55/68 restent identiques.
Le [bilan M08](M08_IMPORTS_ET_VALIDATION.md) consigne 210 budgets
satisfaits, les régressions et la revue ciblée des quatre consommateurs API
Windows/Linux sans fonctionnalité de recherche. Ces images conservent les
imports, y compris lorsque l'édition de liens les retire du CLI livré.

La revue scellée qualifie le retrait des copies décodées ciblées sur les
chemins s-invalid examinés. Elle ne couvre pas toutes les copies PKE, les
registres ou les zones ABI préexistantes. Les quatre budgets de la campagne
principale sont atteints. L'union LLVM couvre 438/604 lignes et 17/36 branches
instrumentées du cœur ; 3156 requêtes déterministes concordent avec Python.
Les deux paquets M08 livrent les originaux inventoriés après comparaison
d'une répétition par hôte. Les paquets M07 gardent leurs
exécutables et leur portée historiques.


## Réalisation M09 — étape historique

Les API publiques et formats R1 restent compatibles. Le moteur utilise
les vues internes de graines à rôle/taille fixes, un remplissage d'entropie
qui propage et efface les échecs partiels avant calcul, un message décapsulé
écrit dans son propriétaire final et une NTT scalaire à tables publiques.
Le [bilan M09](M09_MOTEUR_CONTRATS_ET_QUALIFICATION.md) donne mesures, rejet
de la première vectorisation, correction ciblée, paquets et preuves.
Le moteur fonctionne sur les PC qualifiés ; C01 et l'audit extérieur restent
ouverts. Les images Android/Messenger ne sont pas incluses dans ce périmètre.

L'[étape livrée M09](M09_MOTEUR_CONTRATS_ET_QUALIFICATION.md)
est liée à la CI neuve Windows/Ubuntu 43806407492 (439 tests Python
exécutés par OS, sans test ignoré), à ses paquets originaux et au contrôle
de copie locale. Ce sont des vérifications d'intégration distinctes des
mesures et campagnes figées ; la construction et les octets R1 sont inchangés.

## Réalisation M10 livrée, qualifiée en interne sur PC

L'API et les formats restent R1. La réalisation003 emploie des destinations
possédées pour les dérivations et expansions, une finalisation SHAKE empruntée,
une affectation conditionnelle du secret et une copie de sortie qui conserve
l'effacement du propriétaire local de Decaps. Les deux résidus observés sont
retirés dans les quatre images PC examinées ; le [dossier de cycle secret](REVUE_CYCLE_SECRET_M10.md)
conserve aussi les itérations001/002 et les limites masque/ABI/registres.
Les budgets de mesure passent sur les deux OS. La campagne longue neuve
ASan/std reconstruite atteint ses quatre budgets de 1800 secondes CPU
conservatrices après INITED : 8041,14 secondes CPU totales, dont 7408,48
créditées après INITED, en 33 segments. Elle compte 33197231 exécutions
après INITED, répétitions comprises, sans défaut observé ; aucun temps
historique, de compilation ou d'initialisation n'est crédité. Les corpus
récoltés comptent 3968 entrées après déduplication propre à chaque harnais.

Les objets distincts de couverture LLVM donnent 492/669 lignes du cœur
mappé et 18/38 branches, en conservant les compteurs nuls. Le rejeu du
nouveau corpus confronte 4263 requêtes déterministes Rust/Python, toutes
concordantes, dont 641 sondes de décapsulation après import privé accepté.
Les 1887 opérations à aléa frais encodées dans le corpus restent comptées
séparément et ne sont pas reproduites par l'oracle.

Le [recueil moteur M10](../results/engine/m10-001/) est scellé et rejoué,
et les deux paquets sont qualifiés en interne. Le [check local Windows
complet](../results/engine/m10-verification-001/) passe : 514 tests Python,
aucun ignoré, tests Rust, formatage, Clippy strict et rejeux requis. Les
313 entrées de sources/contrôles enregistrées sont identiques avant/après.
La [CI neuve 43893183494](https://github.com/MajidNIMAR/majax_mlkem1536/actions/runs/43893183494)
passe sur Windows/Ubuntu : 514 tests Python exécutés par OS, aucun ignoré,
et contrôles natifs des CLI/consommateurs originaux. Le [reçu de publication](../results/publication/r6-m10-001/)
relie les 37 entrées compilables qualifiées au commit public testé
`82c63441d1885c1e348884a2d9442ee48b6eaf03`. Le [lecteur de publication figé](../results/publication/r6-m10-controls-001/)
conserve 50 fichiers Python identiques aux blobs Git testés ; ses quatre
tests purs et son rejeu hors ligne du reçu passent sans relancer le moteur.

Le CLI Windows canonique contient désormais l'original M10-003, SHA-256
`2d6aa2e5859ea1df7774e5dd1cbb35827c8e9e1feddbe9f1f72a80c1661d5468`.
La [promotion 002](../results/engine/m10-canonical-002/) vérifie après copie
le profil, 16 échanges, 16 rejets et les cinq refus de commandes de recherche.
La première promotion refusée et son rollback M09 sont conservés séparément.
Le [bilan M10](M10_MOTEUR_ET_QUALIFICATION.md) distingue cette intégration,
la correction des fixtures de la première CI, les mesures et les campagnes.
M10 est la référence livrée dans ce périmètre PC ; M09 devient historique.
Le [volet sécurité](SECURITE_M10.md) et la [décision des paramètres](DECISION_PARAMETRES_M10.md)
ne déclarent ni C01 fermé ni un niveau global de sécurité acquis.
