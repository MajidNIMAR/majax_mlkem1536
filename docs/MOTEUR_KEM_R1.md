# Moteur KEM1536-DEV-Q7681-R1

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
Windows ; aucune garantie générale d'effacement des copies n'est acquise.

## Ce qui est implémenté

- Anneau Z_7681[X]/(X^256+1), six polynômes, convolution directe.
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
temporelle complète, la NTT ou d'autres optimisations comparées aux
oracles, la portabilité native, les mesures P01 et la cryptanalyse J2.
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
