# M09 — cycle de vie des secrets du moteur

16 novembre 2026. Périmètre : réalisation Rust du profil
`KEM1536-DEV-Q7681-R1`, sur PC GNU x86-64 Windows et Linux. Cette revue
interne est distincte d'un audit par un tiers. M08 et ses preuves restent figés.
L'intégration Messenger et la qualification Android sont différées.

## Contrat de propriété

Le tableau suit les données sensibles jusqu'à leurs propriétaires. Un owner
`Zeroizing` ou `SecretBox` efface sa propre mémoire à sa destruction normale ;
cette propriété ne certifie pas les copies de registre, sauvegardes ABI,
copies du compilateur, secrets conservés par l'appelant, arrêt brutal ou
abandon du processus. Une panique qui déroule la pile exécute les destructeurs ;
une compilation avec abandon à la panique ne donne pas cette garantie.

| Opération | Données | Propriétaire et frontière |
|---|---|---|
| KeyGen | d et z, puis sigma | Tampon d'entropie `Zeroizing<[u8;64]>`, dérivation KG sous owner effacé ; d/z sont empruntés |
| KG/PKE | s, r, e, e1, e2 et produits | `Polynomial` et `NttPolynomial` contiennent des tableaux `Zeroizing<[u16;256]>` ; écriture dans les owners existants |
| KG | six transformées du secret | Tableau local de six `NttPolynomial`, détruit avec la fonction ; aucune rétention entre opérations |
| Clé privée | s encodé, ek intégré, h, z | `SecretBox<5088>` fixe ; import seulement après longueur, canonicité s, canonicité ek, puis hash |
| Export privé | copie explicite de l'encodage | `Zeroizing<Vec<u8>>` renvoyé à l'appelant, qui peut néanmoins faire ses propres copies |
| Encaps | m et sortie G | Tampon de message et dérivation sous owners effacés ; key/coins sont des vues de taille fixe dans M09 |
| Chiffrement/réchiffrement | transformées r, accumulateur et polynômes | Owners locaux fixes ; tampon de rechiffrement détenu par `decapsulate` |
| Déchiffrement | s décodé, v−sᵀu, m récupéré | Polys sous owners ; M09 écrit le message dans le tampon détenu par l'appelant interne |
| Décapsulation | G, clé favorable, clé de rejet | Owners effacés ; comparaison et sélection CT au niveau source, sans drapeau de rejet public |
| Empreintes/expansion | état SHA3/SHAKE après graines/messages | Fonctions des dépendances verrouillées, fonctionnalités `zeroize` activées dans les manifestes |
| Clé partagée | 32 octets | `SharedSecret(Zeroizing<[u8;32]>)`, sortie volontaire à durée de vie contrôlée par l'appelant |

`Ciphertext` contient des octets publics. M08 utilisait le trait `Clone`
générique de `SecretBox` pour le copier. M09 retire ce trait du stockage
générique et place la copie explicitement dans `Ciphertext` : allocation
initialement nulle, puis copie des octets. Le type du propriétaire privé ne
permet donc plus une duplication générique implicite. Cela restreint une API
interne ; aucune fuite passée n'en est déduite.

Les conversions `recover_message_into` et `pke_decrypt_into` retirent le retour
d'un message secret rempli entre deux fonctions de production. Le tampon m
est créé par `decapsulate`, rempli et détruit dans ce propriétaire. Elles
réduisent une frontière de déplacement ; elles ne garantissent pas que LLVM
élimine toute autre copie. La sélection finale et les autres retours de
petits owners demeurent des frontières à examiner dans les images concrètes.

Les branches d'erreur d'import s'exécutent avant l'allocation et la copie du
nouveau propriétaire privé. Les octets fournis restent dans la mémoire de
l'appelant ; le moteur n'a ni la propriété ni l'autorisation de les effacer.
L'ordre des erreurs est un contrat déjà testé depuis M08. La vérification
syntaxique ne prouve ni l'entropie de z, ni la relation algébrique d'une clé
importée, ni son origine honnête.

## Revue des images de cette réalisation

Le collecteur `research/m09_lifecycle_inventory.py` conserve les deux images
originales, la fermeture complète du manifeste de qualification (dont les six
entrées de source/manifestes du cœur), les commandes et
versions d'objdump, les en-têtes, relocalisations ELF, désassemblages intégraux
et index par adresse physique. Les adresses distinctes portant le même nom
démanglé restent distinctes. Les appels directs et les slots ELF RELATIVE
résolus donnent une fermeture explicite ; les appels indirects non résolus et
transferts externes restent visibles. Le contrôleur ne confond pas cette
fermeture avec la totalité des chemins du système.

Chaque collecte impose un manifeste source et les reçus de build Windows et
Linux : empreinte du manifeste, empreinte et chemin exacts des images,
version rustc, puis égalité des fichiers source avant et après collecte.
La capture utilise les sources gelées ayant servi aux builds, sans attribuer
une image à la seule présence d'un fichier courant dans le dossier de travail.

Les témoins de stores zéro sont des instructions littérales ; leur comptage
n'est ni un nombre de secrets effacés ni une preuve de boucle complète.
Les adresses de pile ne constituent pas une analyse de provenance des données.
La présence d'une division dans la fermeture générale doit être examinée
selon ses opérandes ; son absence ne suffit pas à établir le temps constant.
Les dépendances système externes ne sont pas incluses intégralement.

Quatre régressions du collecteur contrôlent les homonymes physiques, la
résolution RELATIVE, la conservation des appels inconnus et le refus d'un
périmètre sans symbole moteur. Le rejeu `verify` utilise les données conservées
et n'exécute aucun binaire, compilateur ou objdump. La collecte et l'examen des
images finales sont enregistrés séparément, sans transférer la qualification
M08 aux nouvelles empreintes.

### Première capture M09 : constat négatif conservé

Les acquisitions `m09-lifecycle-cli-001` et `m09-lifecycle-consumer-001`
conservent quatre images nouvelles du candidat `m09-final-001` et la source
de manifeste `89cec589ed2d8b8533cc263c1a22a7933f0f024263edef41c58acbb4dac67d1f`.
Leur rejeu de données réussit. Le CLI Linux ne retient pas les imports ;
le consommateur distinct les retient. La fermeture énumérée contient cinq
divisions Windows, dans les conversions de compteurs de temps de la bibliothèque
standard, et aucune division Linux. Ce compte n'est pas une preuve CT.

L'optimisation par tables a provoqué l'auto-vectorisation de `transform`.
Sa frame locale passe, sur les CLI comparés, de `sub rsp,0x48` à `0x148`
sur Windows et de `0x28` à `0x88` sur Linux. Les pushes des registres sont
distincts de ces réservations ; ce ne sont pas des pics de pile du KEM.
Windows sauvegarde désormais XMM6 à XMM14 dans neuf slots de 16 octets,
puis les restaure sans effacer ces slots. Linux n'a pas ces sauvegardes XMM
dans le prologue observé. Une sauvegarde ABI à l'entrée ne suffit pas, seule,
à identifier la nature des octets sauvés.

Une trace positive a cependant été reliée au PKE du CLI Windows original,
SHA-256 `c6e5a6b720c103a718a717612842f6fdce1bbd46b0d5977234c9d0e3b0cf93fa` :

1. À `0x140050590..0x140050628`, le chiffrement ajoute l'erreur scalaire e2
   et Encode(m). `packssdw` à `0x140050612` laisse les huit derniers
   coefficients dans XMM8, puis `movdqu` à `0x140050617` les écrit dans
   leur owner, sans vider XMM8.
2. Le memset et le remplissage du polynôme public suivants doivent préserver
   XMM8 selon l'[ABI Windows x64](https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-170#x64-register-usage).
   `forward_into`, appelé à `0x1400506ad`, ne
   modifie pas XMM8 ; il restaure XMM6/7 et saute vers `transform` à
   `0x14005b7ba`.
3. `transform` sauvegarde XMM8 à `0x14005c5ff`, dans son slot `rsp+0xd0`,
   hors de l'owner de polynôme. L'épilogue le recharge à `0x14005cc22`,
   sans effacer cette sauvegarde.

Ce chemin établit un résidu compilé supplémentaire dérivé d'un secret
dans la première variante Windows. Il ne constitue pas une fuite de
protocole démontrée, ni une preuve que tous les autres slots contiennent
des secrets. Il interdit de présenter cette première variante comme une
amélioration sans réserve de l'effacement. Les captures sont conservées
comme résultat négatif ; l'acceptation de la réalisation finale doit traiter
ce constat et qualifier toute variante suivante sur ses propres images.

### Variante scalaire 002 : traitement du mécanisme ciblé

Une variante suivante ajoute un `std::hint::black_box` sur le facteur de
table public, en conservant la même arithmétique, les mêmes tables et les
octets R1. Le hint n'est pas une primitive d'effacement ou de temps constant :
la [documentation Rust](https://doc.rust-lang.org/std/hint/fn.black_box.html)
précise qu'il n'offre aucune garantie cryptographique. Cette limite est
également présente dans la source locale de Rust 1.91.1, `core/src/hint.rs`,
lignes 306–311. La correction algébrique n'en dépend pas ; sa propriété
machine doit être contrôlée pour chaque image qualifiée.

La nouvelle capture `m09-final-002`, manifeste
`0829c8112ce771072c63ae07ae5a7f32cc7a06cf91531950047ddd4685cea3eb`,
est examinée par deux nouvelles collections CLI et consommateur par défaut,
puis par `research/m09_scalar_review.py`. Les quatre corps de `transform`
ne contiennent aucun registre SIMD et aucune division. Ils conservent le
jeu de registres généraux sauvegardés de M08. Les six stores explicites de
frame sont tracés aux pointeurs, indices publics et à un unique facteur
public de deux octets. Les résultats secrets des butterflies sont écrits
dans le propriétaire polynomial. Le mécanisme précis de sauvegarde XMM8
du candidat 001 est donc absent dans ces quatre corps examinés.

| Image 002 | Empreinte SHA-256 |
|---|---|
| CLI Windows | `9eb95fb2cb9a8531a216012b4cff71d6b10d1a7951285d9d3c666f8186002255` |
| CLI Linux | `7cc2368a7827c33ee1b1563ef9fa9b155189691d58769e99f68def399f41fd01` |
| Consommateur Windows | `8e80df32180529308007b37726e1534a976f390713f2635e483b52f810a032a4` |
| Consommateur Linux | `6f9b46af780c748804a93aba4c22356c8575d787068be6c56eeaf7fb20e0cc60` |

Sur le CLI Windows, le facteur public est chargé à `0x14005c6ca`, écrit
dans le slot `rsp+0x2e` à `0x14005c6da`, puis relu à `0x14005c6df`, avant
son produit avec un coefficient. Les deux loads de coefficients et les
deux stores de résultat concernent le propriétaire. Le CLI Linux présente
la chaîne correspondante `0x2bbeea`, `0x2bbef9`, `0x2bbefe`, avec le slot
`rsp+0xe`. Les adresses des deux consommateurs sont conservées dans le reçu.

La réservation locale de frame de `transform` est maintenant 88 octets
Windows et 56 octets Linux, soit 16 octets de plus que M08 dans les deux
cas, hors pushes. Cette hausse et le coût de la table publique restent
présents dans le bilan mémoire ; aucune amélioration uniforme de mémoire
n'est déduite du retrait de retours de message.

Le message récupéré est assemblé par OR directement dans le propriétaire
de `decapsulate` : `rsp+0x40` Windows et `rsp+0x20` Linux. Dans chaque image,
32 stores zéro littéraux couvrent ses octets avant le retour normal
observé, soit 128 témoins sur les quatre images. Ce contrôle ne prouve pas
l'effacement des autres temporaires, des chemins exceptionnels, des
registres ou des copies ABI/appelant. Les contrôles de provenance et de
témoins sont des contrôles de données et une revue interne bornée, distincts
d'une preuve formelle de flot d'information.

Les collections 002 et leur revue sont scellées :

- CLI : provenance `5272a85de937b08beec91a678cf2c15877146c367e93f1c2728eabfd2646ac47` ;
- consommateur : `6602f56bac5a5466089b63f2ee3e1c5487b0dbf4280e49bd6922a93c2c6979f7` ;
- revue scalaire : `8116e35ea0b8357ea6be649c2c88b3105ddcf111bdbbfd56bcfa16e482467d9b`.

Le rejeu pur des quatre images réussit. Les sept tests du lecteur comprennent
des contrôles négatifs vérifiant le refus d'une sauvegarde SIMD, d'une division,
d'une attribution ambiguë et d'un effacement incomplet ou situé après le
retour. Leur petit modèle du propriétaire ne représente pas une couverture
supplémentaire du moteur. Les mesures, corpus, fuzzing et critères de
publication restent des qualifications séparées.

## Obligations conservées

- Examiner les copies de secret restantes par chemin et image finale ; une
  liste de stores zéro ne prouve pas l'effacement de tous les registres/ABI.
- Conserver la séparation entre propriétés source, observations machine et
  diagnostic temporel statistique ; aucun des trois ne vaut preuve globale CT.
- Mesurer la pile et le tas avant/après une modification structurelle. Une
  réduction de frontières de retour ne démontre pas une baisse du pic mémoire.
- Soumettre la construction précise et les propriétaires aux questions de la
  revue indépendante décrites dans `REVUE_EXTERNE_M09.md`.

