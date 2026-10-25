# KEM1536-DEV-Q7681-R1 — Spécification d'essai

Version R1 du 25 octobre 2026, avant calcul des vecteurs. Cette construction
expérimentale est indépendante des paramètres normalisés ML-KEM. Elle
reprend l'organisation PKE + dérivation/réencapsulation/rejet de
[FIPS 203, algorithmes 13–21](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
avec les écarts explicités ci-dessous. Sa sécurité n'est pas déduite de
la standardisation. Voir le [bilan J2](BILAN_J2_ET_DECISION_PROTOTYPE.md).

## Paramètres et représentations

Anneau Z_7681[X]/(X^256+1), rang 6, toutes erreurs et secrets PKE CBD(3).
Calcul de référence dans le domaine des coefficients, sans NTT.
Chaque polynôme exact est codé sur 256×13/8=416 octets, coefficients
0..7680, bits de poids faible d'abord, coefficients dans l'ordre croissant.
Les encodages exacts contenant 7681..8191 sont non canoniques.
Une compression n'est appliquée qu'à v, sur 5 bits, soit 160 octets.

| Objet brut | Format | Octets |
|---|---|---:|
| ek | t[0..5] exacts puis rho | 2528 |
| dk développé | s[0..5] exacts puis ek puis h puis z | 5088 |
| chiffré c | u[0..5] exacts puis v compressé | 2656 |
| secret partagé K | chaîne | 32 |

Ces octets bruts sont utilisables uniquement avec les types et commandes
du profil R1. Aucun en-tête universel ou détection automatique de profil
n'est défini. Les anciens formats P0 ne sont pas acceptés par ces types.

## Primitives et séparation

TAG est l'ASCII `KEM1536-DEV-Q7681-R1` suivi de l'octet nul. Tout appel
absorbe TAG, puis une étiquette ASCII suivie de l'octet nul, puis les
arguments dans l'ordre ci-dessous. Leurs longueurs sont fixes.

| Fonction | Primitive | Étiquette | Arguments | Sortie |
|---|---|---|---|---|
| expansion de graine | SHA3-512 | KG | d(32), octet 6 | rho(32), sigma(32) |
| hachage de clé publique | SHA3-256 | H | ek(2528) | h(32) |
| dérivation d'encapsulation | SHA3-512 | G | m(32), h(32) | K(32), rseed(32) |
| rejet implicite | SHAKE256 | J | z(32), c(2656) | Kbar(32) |
| matrice A[i,j] | SHAKE128 | A | rho(32), i(1), j(1) | flot variable |
| bruit | SHAKE256 | N | graine(32), nonce(1) | 192 octets |

Chaque candidat uniforme de A utilise deux octets successifs du flot,
entier petit-boutiste masqué par 8191. Accepter s'il est inférieur à
7681, sinon lire le candidat suivant ; retenir 256 coefficients. Aucun
reste modulo q ne remplace le rejet. Indices i,j dans 0..5.

Pour le bruit, lire les 1536 bits des 192 octets, poids faible d'abord.
Le coefficient j est la somme des bits 6j..6j+2 moins celle des bits
6j+3..6j+5, puis représentation canonique modulo q. En génération :
nonces 0..5 pour s et 6..11 pour e. En chiffrement : nonces 0..5 pour
r, 6..11 pour e1 et 12 pour e2, à partir de rseed.

## Encodages et cœur PKE

`Compress_d(x)=floor((2^d*x+floor(q/2))/q) mod 2^d` pour x canonique.
`Decompress_d(y)=floor((q*y+2^(d−1))/2^d)` pour y dans 0..2^d−1.
Le message m est lu en 256 bits de poids faible d'abord et encodé par
Decompress_1. Son décodage utilise Compress_1.

Génération PKE : dériver rho,sigma ; générer A,s,e ; t=A*s+e.
Chiffrement : u=A^T*r+e1, v=t^T*r+e2+EncodeMessage(m), puis compression
de v seulement. Déchiffrement : DecodeMessage(Decompress_5(v)−s^T*u).
Toutes les sommes et produits sont effectués dans l'anneau spécifié.

## KEM et validations

KeyGen tire d et z, indépendants, de 32 octets chacun via le système ;
forme ek, h=H(ek), et dk=s||ek||h||z. Encaps valide ek, tire m de
32 octets via le système, dérive (K,rseed)=G(m||H(ek)), chiffre m et
retourne (c,K). Une panne d'aléa est une erreur explicite.

Decaps valide le format de dk, déchiffre c en m', dérive (K',rseed'),
réencapsule en c', calcule Kbar=J(z||c) et choisit K' si c=c', sinon
Kbar. La comparaison et la sélection emploient une primitive dédiée ;
aucun indicateur de rejet n'est rendu par l'API d'application.

Les longueurs invalides sont rejetées explicitement. Un chiffré de bonne
longueur avec u non canonique suit le rejet implicite ; son u est réduit
uniquement dans le calcul interne de référence, puis la comparaison avec
le chiffré canonique reconstruit établit le rejet. L'import de ek rejette
t non canonique. L'import de dk vérifie s et ek canoniques et h=H(ek).
Il ne certifie pas qu'une clé importée a été produite honnêtement, ni
qu'elle vérifie la relation algébrique t=A*s+e avec un petit e.

Les types de clé privée et de secret partagé ne journalisent pas leurs
octets. Les interfaces à graines déterministes sont réservées à une
fonctionnalité de compilation de recherche, inactive par défaut. Les
vecteurs publiables utilisent exclusivement des graines synthétiques.

## Conditions restant ouvertes

Le moteur de référence n'est pas une réalisation durcie : l'arithmétique
modulaire, les allocations et les branches doivent être analysées, les
temporaires secrets effacés autant que possible puis audités, les tests
de mémoire/fuzzing/temps et la seconde plateforme exécutés. Aucune preuve
IND-CCA propre à ce profil ni niveau global ne sont acquis. Les essais
fonctionnels ne certifient pas C05 ou les propriétés temporelles.
