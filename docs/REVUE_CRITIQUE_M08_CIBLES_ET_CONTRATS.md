# Revue M08 — cibles, arithmétique, domaines et erreurs d'import

11 novembre 2026. Revue des cinq observations techniques reçues après la
présentation M08. Les sources et archives M08 restent inchangées. Aucun
nouveau résultat Android, de temps constant ou de cryptanalyse n'est annoncé.

| Observation | Conclusion de la revue |
|---|---|
| `product()` et temps constant ARM | Qualification par cible requise ; aucune fuite Android constatée dans ce travail |
| Argument concret R1 | C01 reste ouvert ; corriger la comparaison numérique : 7681 > 3329 |
| Effacement registres/ABI/PKE | Obligation réelle hors de la conclusion ciblée M08 ; aucune image Android examinée |
| CBD(3), graine et nonce | 192 octets corrects ; cadrage et nonces déjà spécifiés ; indépendance concrète non démontrée |
| Secret non canonique + hash incohérent | Scénario déjà explicitement couvert par le test cité et le consommateur M08 |

## 1. Arithmétique et cible matérielle

[`product`](../crates/kem1536/src/engine_poly.rs) calcule un produit u32,
une multiplication par un réciproque constant en u64, un décalage et une
correction. `RECIP32 = floor(2^32/7681) = 559167` est calculé à la compilation.
Pour ses entrées canoniques, `a,b <= 7680` et `x <= 58982400`.
La source ne contient pas de division de donnée secrète dans cette fonction.
Cela ne fixe pas les instructions émises, les appels auxiliaires ou leur
latence pour toutes les chaînes de compilation et tous les processeurs.

Les images publiées M08 sont GNU x86-64 Windows et Linux/WSL. Il faut
distinguer Android `arm64-v8a` / Rust `aarch64-linux-android` de
`armeabi-v7a` / `armv7-linux-androideabi`, puis identifier le cœur réel.
Le code Rust passe par le backend LLVM de rustc ; le Clang du NDK peut
intervenir pour C/C++ et comme pilote de liaison. Le seul nom « Clang »
ne décrit donc pas la chaîne ayant produit le Rust et son ELF final.
Références : [ABI Android](https://developer.android.com/ndk/guides/abis),
[cibles Rust Android](https://doc.rust-lang.org/rustc/platform-support/android.html),
[NDK et autres systèmes](https://developer.android.com/ndk/guides/other_build_systems).

Exemple matériel borné : le [guide Cortex-A510 r1p3, §3.5, page 18](https://documentation-service.arm.com/static/6346cce8da191e7fe057fc46)
décrit certaines multiplications entières 64 bits à terminaison anticipée
suivant les hauts 32 bits des opérandes, et le rôle de PSTATE.DIT. Dans le
produit réciproque source étudié, `x` et `RECIP32` ont toujours leurs hauts
32 bits nuls : cette condition particulière est constante sur le domaine
des coefficients. Elle ne démontre donc pas une fuite pour cette expression.
Il reste à observer l'abaissement LLVM et les autres propriétés du cœur
retenu. Aucune activation automatique de DIT ou substitution arithmétique
n'est effectuée sur la base de cet exemple.

## 2. Paramètres et C01

[FIPS 203, §8, tableau 2](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
fixe q=3329 pour ses trois profils ; ML-KEM-1024 a rang 4 et eta1=eta2=2.
R1 a q=7681, rang 6, CBD(3), u exact sur 13 bits et v comprimé sur 5 bits.
7681 est supérieur à 3329. L'ensemble degré/rang/module/bruit/compression,
la dérivation des graines et la construction KEM doivent être analysés
ensemble ; cette inégalité ne classe pas leur sécurité globale.

Le [cahier des charges](../CAHIER_DES_CHARGES_KEM_1536.md) conserve P0
historique et les critères C01–C06. Le profil exécuté est décrit dans la
[spécification R1](SPECIFICATION_DEV_Q7681_R1.md), avec sa décision dans le
[bilan de passage au prototype](BILAN_J2_ET_DECISION_PROTOTYPE.md).
Les [analyses conditionnelles M05](SECURITE_CONCRETE_R1_M05.md) et les
raffinements M06/M08 ne ferment pas l'argument concret IND-CCA du KEM.
Les avantages du PKE à graines, le transfert aux primitives concrètes,
les pertes et marges finales et la cryptanalyse externe restent des travaux.

## 3. Effacement et frontière des preuves

La [revue M08](M08_IMPORTS_ET_VALIDATION.md) qualifie le retrait de copies
de bits ciblées dans les consommateurs API par défaut examinés. La source
actuelle de `validate_vector_encoding` ne construit plus de `Poly` : elle
assemble les champs de 13 bits et accumule un masque avant décision.
Un autre compilateur et une autre ABI peuvent produire d'autres copies.
Leur existence ou leur effacement sur Android ne sont pas établis ici.

Les registres, sauvegardes ABI/appelant et autres chemins PKE sont hors de
cette conclusion. L'obligation doit être formulée avant une éventuelle
intégration Android ; ce dépôt indépendant ne démontre ni un déploiement
de R1 dans Messenger ni une vulnérabilité actuelle de ce service.

## 4. Cadrage de l'expansion CBD(3)

La spécification fixe déjà l'entrée du domaine N :

```text
SHAKE256(TAG || ASCII("N") || 00 || seed[32] || nonce[1], 192 octets)
TAG = ASCII("KEM1536-DEV-Q7681-R1") || 00
```

Ces entrées font 56 octets. Deux nonces différents produisent des entrées
distinctes de même longueur, sans ambiguïté de préfixe ou de découpage.
Les 192 octets donnent 1536 bits, soit six par coefficient CBD(3).
Les appels actuels fournissent tous 32 octets de graine : sigma à la
génération et la seconde moitié de G au chiffrement. Les nonces sont
0..5 pour s/r, 6..11 pour e/e1 et 12 pour e2. La réencapsulation répète
intentionnellement les mêmes coins pour reconstruire le chiffré.

[FIPS 203, §4.1](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
emploie lui aussi une expansion SHAKE256 d'une graine de 32 octets suivie
d'un compteur d'un octet, avec sortie de 64eta octets. Ce précédent
explique le motif ; il ne valide pas R1. Le caractère déterministe de SHAKE
concret ne fournit pas une indépendance statistique de ses sorties. Les hypothèses
d'oracle idéal ou de pseudorandomness doivent rester explicites.

Le cas plus subtil `sigma == rseed` est déjà traité en M05 : les mêmes
adresses N donnent r=s et e1=e. Son annulation dans la borne de correction
ne ferme pas sa prise en compte dans l'avantage de confidentialité du PKE.
Changer les labels ou scinder les domaines génération/chiffrement modifierait
R1 et ses vecteurs : ce n'est pas une correction documentaire à appliquer
silencieusement. Une future réalisation peut typer les graines en
`&[u8; 32]`, avec les nouvelles vérifications de compilation nécessaires.

## 5. Priorité des erreurs : cas déjà couvert et revérifié

Dans [`every_encoded_row_is_checked_before_the_private_hash`](../crates/kem1536/src/dev_kem.rs),
la boucle comprend row=0 et position=0. Elle remplace le polynôme secret,
corrompt aussi `private[VECTOR_BYTES + PUBLIC_KEY_BYTES]` par XOR 1,
puis exige `NoncanonicalEncoding`. L'offset du hash est 2496+2528=5024 ;
ek reste inchangé, donc ce XOR rend bien h incohérent. L'autre branche
du test vise le public intégré non canonique avec son hash incohérent.

Le [consommateur M08](../research/m08-import-consumer/src/main.rs) contient
aussi `private_secret_and_hash_invalid`, premier coefficient secret=7681
et h[0] corrompu, code attendu 2. Son mode exhaustif vérifie les 1536
positions et les valeurs 7680/7681/8191 avec hash cohérent puis incohérent.
L'ordre longueur → s → ek intégré → hash est déjà rattaché au contrat.

Vérification ciblée du 11 novembre : le test Rust nommé ci-dessus passe
(un test effectivement exécuté), ainsi que les 13 cas du consommateur
Windows original SHA-256 2c0c58d494823f2d3d03ddac95e8e651799c881fcaaec9034572665427ad5e70.
Le cas combiné renvoie bien 2, `NoncanonicalEncoding`. Les logs et reçu
sont dans `artifacts/generated/m08-review-001`. Aucun test redondant ni
changement d'algorithme n'est ajouté. Les sources contrôlées sont identiques.

L'import privé expose des classes d'erreurs via `Result`. La décapsulation
prend une clé typée et renvoie un secret avec rejet implicite, sans drapeau
de validité du chiffré. Les deux interfaces ne sont pas le même oracle.
L'exposition des diagnostics d'import par une application dépend de son
modèle de menace.

## Travail Android à préparer, non exécuté

1. Identifier ABI, appareil/SoC/cœur, Android/API et mode Termux ou application.
   Figer Rust/LLVM, NDK/Clang/LLD, options, features et verrous.
2. Construire un consommateur qui retient imports et PKE ; conserver l'ELF
   final et ses empreintes. Examiner instructions incorporées, éventuelles
   divisions/aides logicielles, branches, adresses et chemins d'erreur/drop.
3. Rejouer les contrats et corpus sur l'appareil réel. Déclarer les classes
   d'opérandes/clés et la méthode avant des mesures temporelles natives.
   Une émulation fonctionnelle peut tester le comportement ; elle ne mesure
   pas la latence du cœur réel.
4. Distinguer copies nouvelles, données déjà détenues par l'appelant et
   zones ABI. Corriger selon les constats, puis revoir le nouvel artefact.

Ce plan est prospectif et attend une cible précise ; aucun résultat de
cross-compilation ou d'exécution Android n'est acquis par la présente revue.
