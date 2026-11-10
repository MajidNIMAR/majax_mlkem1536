# Argument de sécurité de KEM1536-DEV-Q7681-R1

**Complément du 26 octobre 2026 :** [M05](SECURITE_CONCRETE_R1_M05.md)
établit un transfert de correction aux bruits expansés dans le modèle RO
et instancie des majorants conditionnels ROM/QROM avec budgets explicites.
Les avantages du PKE à graines et de la PRF de rejet restent inconnus ;
C01 demeure ouvert. Le texte ci-dessous conserve le raisonnement M04 et
sa portée historique, sans prétendre un transfert aux primitives concrètes.

25 octobre 2026. Analyse de construction effectuée sur la spécification R1
et `crates/kem1536/src/dev_kem.rs`. Ce document fournit un argument
conditionnel, une réduction du cœur idéal et le rattachement précis de la
transformation FO. Il ne déclare pas une preuve IND-CCA complète du programme
concret, ni un nombre de bits de sécurité global.

Le code examiné provient du commit
`4baca843ae1d159a059670485c7970642506e3bc` ; SHA-256 du fichier examiné :
`a21bb340bd5af3c4983f1f76b59ef542aea67edf4c62ad7ff23e8205612cb564`.
Une optimisation de multiplication préservant les opérations et les octets
R1 conserve cet argument algébrique ; elle exige sa propre vérification de
raffinement et de fuite du programme. Une modification de domaines, de
paramètres ou de transformation ne bénéficie pas automatiquement de ce texte.

## 1. Expérience visée et périmètre

L'expérience IND-CCA mono-utilisateur visée génère une clé honnête par
KeyGen, remet `ek` à l'adversaire, puis fournit un défi `(c*, K_b)` : `K_0`
est issu d'une encapsulation honnête et `K_1` est uniforme sur 256 bits.
L'adversaire peut demander Decaps sur des chaînes de 2656 octets autres que
`c*`, avant et après le défi. Il doit distinguer les deux clés. Le jeu doit
interdire la chaîne de défi exacte, pas seulement un objet Rust identique.
Les requêtes de longueur différente reçoivent une erreur publique et ne
constituent pas une réponse de décapsulation.

Deux modèles sont distingués :

- **ROM classique** : accès classique aux fonctions de hachage idéalisées et
  à Decaps.
- **QROM** : adversaire quantique, accès en superposition aux fonctions
  publiques idéalisées, mais requêtes **classiques** de décapsulation. Cela
  ne prouve pas la sécurité d'un oracle Decaps quantique cohérent.

L'expérience vise des clés produites honnêtement. Importer une clé privée
canonique avec `h=H(ek)` ne prouve pas sa provenance, sa distribution CBD,
ni la relation `t=A*s+e` avec petit `e`. Le contrat actuel de l'import est
donc cohérent avec ce jeu, mais ne couvre pas une sécurité contre toutes les
clés malicieuses acceptées. Les fautes, fuites mémoire, chronométrage,
consommation, compromission de l'aléa et authentification des clés publiques
nécessitent des modèles supplémentaires. La confidentialité du KEM ne
fournit pas l'identité du pair.

## 2. Construction exacte et carte vers le code

Posons `R=Z_7681[X]/(X^256+1)` et `χ=CBD(3)`, coefficient par coefficient.
Tous les vecteurs suivants ont six polynômes. Dans le modèle de bruits
idéaux, les coefficients des tirages distincts sont indépendants.

```
d,z ← {0,1}^256 indépendants
(ρ,σ) = KG(d,6)
A[i,j] = Uniform(ρ,i,j)
s,e = Noise(σ,0..11)
t = A*s + e
ek = Encode13(t) || ρ
dk = Encode13(s) || ek || H(ek) || z

m ← {0,1}^256
(K,rseed) = G(m,H(ek))
r,e1,e2 = Noise(rseed,0..12)
u = Aᵀ*r + e1
w = tᵀ*r + e2 + EncodeMessage(m)
c = Encode13(u) || Encode5(Compress5(w))

m' = DecodeMessage(Decompress5(v) - sᵀ*u)
(K',rseed') = G(m',H(ek))
c' = Encrypt(ek,m',rseed')
Kbar = J(z,c)
Decaps(dk,c) = K' si c=c', sinon Kbar
```

| Élément de l'argument | Réalisation vérifiée |
|---|---|
| `KG` et partage ρ/σ | `pke_keygen`, `derive(b"KG\\0", [d,[6]])` |
| `A` et rejet uniforme | `uniform`, candidats de 13 bits, rejet des valeurs ≥7681 |
| χ exacte à partir de bits idéaux | `noise`, 192 octets, différences de deux sommes de trois bits |
| Clé et chiffré PKE | `pke_keygen`, `pke_encrypt_into`, `pke_decrypt` |
| Entropie d'application | `keygen` tire 64 octets ; `encapsulate` tire 32 octets ; panne propagée |
| Liaison à la clé publique | `hash_public`, puis entrée `m || H(ek)` de `derive(b"G\\0",...)` |
| Validation de domaine du PKE déterministe | `decapsulate` recalcule tout `c'` et compare tous les octets |
| Rejet stable par clé et chiffré | `xof::<32>(b"J\\0", [z,c])` |
| Sélection | `CtEq` puis `CtSelect`, aucun drapeau applicatif de rejet |

Les étiquettes incluent un octet nul et sont préfixées par
`KEM1536-DEV-Q7681-R1\0`. Leurs arguments ont des longueurs fixes : il n'y a
pas d'ambiguïté de concaténation dans le domaine R1 défini. `KG` et `G`
emploient SHA3-512 sur des domaines disjoints ; `N` et `J` emploient
SHAKE256 sur des domaines disjoints. Cela autorise leur modélisation par des
restrictions indépendantes d'oracles aléatoires. Ce n'est pas une preuve que
les fonctions Keccak concrètes sont des oracles indépendants.

Les formats examinés sont : `ek=2528`, `dk=5088`, `c=2656`, `K=32`
octets. Les 1536 désignent les coefficients du vecteur, pas des bits de
clé symétrique.

## 3. Réduction du PKE idéal à deux distributions MLWE précises

Définissons `D_(a,b)` sur `(B,y)`, où `B` est uniforme dans `R^(a×b)`,
`x←χ^b`, `f←χ^a`, puis `y=B*x+f`. L'hypothèse décisionnelle utilisée est
l'indistinguabilité de `D_(a,b)` et de `(B,U)` avec `U` uniforme. Elle
concerne ici l'anneau R1 et **χ=CBD(3)** ; elle n'est pas
un théorème de difficulté pour ces paramètres.

Pour éviter toute ambiguïté, les deux instances requises sont :

1. `D_(6,6)` pour remplacer la clé publique `t=A*s+e` par un vecteur
   uniforme `t0`.
2. `D_(7,6)` pour remplacer le couple de chiffrement
   `(Aᵀ*r+e1, t0ᵀ*r+e2)` par un vecteur uniforme de sept polynômes.

Voici une réduction explicite pour un chiffrement défi du **PKE idéal à
matrice uniforme publiée et tirages χ indépendants**, avant les expansions
par graines :

- **H0** est le jeu réel idéal : `t=A*s+e` et le défi est chiffré selon les
  équations R1.
- **H1** remplace `t` par `t0` uniforme. Le simulateur utilisant
  `D_(6,6)` peut encore chiffrer avec la clé publique donnée ; il n'a pas
  besoin de connaître `s`. L'écart de probabilité de succès est borné par
  l'avantage du distingueur MLWE correspondant.
- **H2** utilise la matrice augmentée `[Aᵀ ; t0ᵀ]`, uniforme de taille
  `7×6`. Le simulateur `D_(7,6)` reçoit soit ses sept échantillons avec
  secret `r`, soit sept polynômes uniformes. Il ajoute `EncodeMessage(m_b)`
  au dernier polynôme et applique exactement l'encodage/compression R1.
- Dans H2, ce dernier polynôme est uniforme dans R. Lui ajouter l'un ou
  l'autre message ne change pas sa loi. La distribution du défi est donc
  indépendante de `b`, même après compression déterministe.

Avec `Adv_CPA=|Pr[b'=b]-1/2|`, et ε6/ε7 des écarts de probabilité de
distingueurs des deux hybrides, cela donne

`Adv_CPA(PKE_idéal) ≤ ε6 + ε7`.

Une convention normalisant l'avantage CPA à `|2Pr[b'=b]-1|` double le
membre de droite. Le temps des réductions comprend les expansions et le
chiffrement ; il ne s'agit pas d'un coût Core-SVP ni d'une estimation
concrète de ε6 et ε7.

La compression de `v` n'empêche donc pas ce raisonnement. Elle ne permet
pas de dire que les 160 octets compressés sont uniformes : `7681` n'est pas
divisible par `32`. La distribution correcte dans H2 est celle de
`Compress5(U)` pour `U` uniforme modulo 7681. L'encodage exact de `u` ne
donne pas un bruit additionnel de compression à créditer comme gain de
sécurité.

La spécification des auteurs Kyber présente une démarche apparentée avec
clé/chiffré pseudorandomisés (§4.3.1). Notre argument ci-dessus explicite
les deux dimensions et la compression pour R1 ; il ne réutilise pas ses
estimations de paramètres ni son théorème KEM. [Spécification Kyber
v3.02](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf).

## 4. Ce qu'il faut payer pour revenir au PKE du programme

Le PKE idéal précédent publie une matrice uniforme entière et utilise des
bits frais indépendants. R1 publie une graine `ρ`, tire `s,e` depuis `σ`
et les bruits de chiffrement depuis un `rseed` de 256 bits. Les jeux ne
sont pas statistiquement identiques une fois les fonctions fixées.

| Transition | Hypothèse/obligation concrète |
|---|---|
| Matrice uniforme entière → `Uniform(ρ,i,j)` avec ρ public | Modèle d'oracle de SHAKE128 et simulation/programmation des 36 flots au point ρ ; le rejet des candidats est non biaisé dans le modèle idéal. Un simple PRG secret ne justifie pas une graine **publique**. |
| `(ρ,σ)` indépendants → SHA3-512 `KG(d,6)` | Modèle de KG ; recherche de d et requêtes antérieures au point à programmer comptabilisées. Le fait que la sortie fasse 512 bits ne crée pas 512 bits d'entropie à partir de d. |
| Tirages χ frais → SHAKE256 `N(seed,nonce)` | Pseudorandomisation des sorties aux graines cachées, cohérence des requêtes publiques et des nonces, collisions/réutilisations entre graines σ et rseed. |
| Coins frais → `rseed=G_R(m,H(ek))` | Dérandomisation FO ; les requêtes adaptatives doivent être comptées, pas remplacées par un nombre d'échanges honnêtes. |
| Oracle de rejet → SHAKE256 `J(z,c)` | Hypothèse PRF à clé secrète z ou analyse dans l'oracle public préfixé ; prendre en compte la recherche de z. |

Ces coûts peuvent être regroupés sous un terme **Δ_expansion** dans un
théorème conditionnel, mais ne sont pas évalués numériquement ici. Il faut
préciser le nombre total de clés, points d'oracle et graines considérés
avant d'assigner une borne de collision ou de programmation. Donner un
unique terme `Q/2^256` à tout cet ensemble serait insuffisant, en
particulier dans le QROM.

La référence Python concordante vérifie les mêmes fonctions concrètes.
Elle n'établit pas les hybrides de pseudorandomisation précédents.

## 5. Rattachement FO et résultat réellement obtenu

Fixons une clé publique honnête et `h=H(ek)`. Dans le modèle aléatoire,
décomposons le résultat de 512 bits en deux restrictions indépendantes :

`G_K(m)=G(m,h)[0..32]`, `G_R(m)=G(m,h)[32..64]`.

Le PKE dérandomisé `T` chiffre alors `m` avec `G_R(m)` et ne déchiffre en
`m'` que si `Encrypt(ek,m',G_R(m'))=c`; sinon il renvoie un symbole
interne `⊥`. Le KEM retourne `G_K(m')` dans le premier cas et `J(z,c)`
dans le second. R1 suit exactement cette organisation, sans rendre `⊥`
visible à l'application.

**Lemme R1 de rigidité.** Pour toute clé de bonne représentation et tout
chiffré de longueur correcte, si `T.Dec` ne vaut pas `⊥`, alors
`T.Enc(ek,T.Dec(dk,c))=c`. C'est la condition de comparaison de Decaps
elle-même ; ce lemme ne suppose pas que tous les chiffrements honnêtes
déchiffrent correctement. Il est distinct d'une preuve de temps constant.

**Lemme R1 de représentation.** Si un coefficient de `u` reçu est dans
7681..8191, la réencapsulation reconstruit toujours un `u` canonique,
donc les chaînes ne peuvent pas être égales. Le résultat est exactement
`J(z,c)` pour ces entrées. Il n'existe pas deux encodages de bonne
longueur acceptés comme le même chiffré par la comparaison ; réduire `u`
à l'intérieur du déchiffrement ne change pas ce fait.

Dans la terminologie FO, il s'agit de la variante avec clé dérivée du
message, PKE dérandomisé, vérification de domaine et rejet implicite.
Les demi-sorties indépendantes de G donnent accès aux deux oracles à
chaque requête : leur regroupement ne permet pas de diviser le budget de
requêtes par deux dans une borne. Le rejet préfixé par z a un domaine
distinct du hachage du message.

HHK fournit le cadre classique de cette composition. Son erratum exige la
rigidité et corrige des comptes de requêtes ; R1 satisfait la rigidité par
réencapsulation. La borne globale ROM du §3.3 pour la variante implicite
à clé issue du message comporte un terme linéaire de correction et un terme
de devinette de message, sans exiger γ-spread. [HHK, version originale
intégralement consultée](https://people.inf.ethz.ch/dhofheinz/pdf/conf/tcc/HofheinzHK17.pdf),
[errata du 2 novembre 2021](https://eprint.iacr.org/2017/604.pdf).

On peut donc formuler le **résultat conditionnel** suivant pour le modèle
FO idéal correspondant : si le PKE de base est IND-CPA, satisfait la
δ-correction requise, et les oracles/simulations sont ceux du théorème,
alors sa composition FO implicite est IND-CCA en ROM. Les lemmes et
hybrides ci-dessus établissent le rattachement de construction et du PKE
idéal, pas toutes les transitions du programme à ce modèle.

Il serait incorrect de publier la borne Kyber
`2 Adv_MLWE + Adv_PRF + 4 Q δ` comme une borne démontrée pour R1. Ses
constantes, variantes de KDF, domaines et comptes d'oracles ne sont pas
automatiquement ceux du programme. Le résultat de ce travail est un
**argument conditionnel C01 exploitable**, avec conditions identifiées et
des sous-arguments démontrés, pas la fermeture de C01.

## 6. La correction fournit le bon quantificateur, dans le modèle idéal

Le [rattachement du certificat au programme](LIEN_CERTIFICAT_PROGRAMME_R1.md)
établit le calcul d'erreur et les seuils. En notant

`B=eᵀ*r - sᵀ*e1 + e2`,

l'échec du PKE honnête implique qu'au moins un coefficient vérifie
`|B_j|≥1800`, car le rayon commun sûr est 1799 et l'erreur de
quantification est toujours dans `[-120,120]`. L'enveloppe est valable
pour chaque message et chaque valeur de l'arrondi ; aucune indépendance
du bruit d'arrondi n'est nécessaire.

Pour une clé idéale fixée `κ=(A,s,e)`, posons

`β(κ)=Pr_ω[∃j : |B_j|≥1800 | κ]`,

où `ω` désigne **des bruits de chiffrement frais idéaux**. Alors

`max_m Pr_ω[Dec_κ(Enc_κ(m;ω))≠m] ≤ β(κ)`.

En prenant l'espérance sur les clés honnêtes :

`δ_wc := E_κ[max_m Pr_ω[échec|κ,m]] ≤ E_κ[β(κ)] ≤ δ_run004`.

La borne rationnelle existante affiche
`log2(δ_run004) ≈ -310,085969` (valeur affichée arrondie ; le certificat
entier fait foi). Cela donne plus qu'une mesure moyenne sur les messages :
cela traite le pire message **avant** la moyenne sur clés, dans le modèle
idéal. Le certificat n'impose pas pour chaque clé `β(κ)≤δ_run004`.

Cette distinction permet une conséquence également rigoureuse dans ce
modèle : pour `0<τ≤1`, l'inégalité de Markov donne
`Pr_κ[β(κ)>τ] ≤ min(1,δ_run004/τ)`. Par exemple, la fraction de clés
idéales dont cette enveloppe dépasse `2^-128` est bornée par environ
`2^-182,085969`. Cela ne certifie pas une clé particulière et n'est pas
une attaque ni un niveau global de sécurité.

Ce δ ne suffit pas à lui seul à borner un attaquant choisissant des
messages selon leurs sorties G observées : la transformation doit payer
la recherche parmi les requêtes. Un coût de recherche quadratique en
QROM, lorsqu'il apparaît dans un théorème précis, porte sur le budget
d'oracle du jeu, pas sur le seul nombre de décapsulations. Sans théorème
instancié, ne pas annoncer `Q_D*δ_run004` comme borne IND-CCA complète.

## 7. QROM : engagements et limite actuelle

Le modèle quantique exige la difficulté quantique des **deux** instances
MLWE, la modélisation quantique des primitives et une réduction de la
transformation qui traite des échecs et de l'accès aux oracles. Une
réduction ROM ne devient pas QROM en remplaçant tous les coûts par leur
racine carrée.

Les travaux sur les échecs séparent notamment la recherche exploitant la
clé publique et la recherche sans clé dans les oracles. Leur distinction
explique pourquoi un taux honnête ne représente pas une capacité de
recherche adaptative. Ils étudient des variantes explicites dont le
transfert au rejet implicite demande son propre rattachement.
[Hövelmanns–Hülsing–Majenz, *Failing gracefully*, version arXiv v1
consultée](https://arxiv.org/abs/2203.10182v1).

Une attention supplémentaire concerne la dispersion des chiffrés : dans
le PKE idéal à bruits indépendants, les 1536 coefficients de `e1` et
l'encodage exact de `u` donnent pour tout `r` fixé une masse ponctuelle
d'au plus `(20/64)^1536=(5/16)^1536`. Ce calcul ne prouve **pas** une
γ-spread de cette valeur pour le PKE concret : celui-ci n'a que `2^256`
graines de chiffrement possibles par message, donc son support contient
au plus `2^256` chiffrés. Sa min-entropie statistique ne peut dépasser
256 bits. Une substitution de PRF n'est pas une identité statistique.

La conclusion actuelle est donc : **argument ROM conditionnel identifié ;
aucune borne QROM concrète fermée pour le programme R1**. Il reste à
choisir et instancier un théorème quantique avec sa définition exacte de
correction, ses exigences de dispersion ou leur remplacement, les jeux
d'échecs et les pertes d'expansion. Cette obligation est précise et
distincte du durcissement du code.

## 8. Graines de 256 bits et plafonds génériques C03

Deux recherches existent indépendamment du rang du module :

- **Retrouver d depuis ek** : énumérer les d de 256 bits, reconstruire la
  clé publique et comparer. Une bonne graine donne le secret PKE ; z
  n'est pas nécessaire pour déchiffrer un chiffré honnête et retrouver K.
- **Retrouver m depuis le chiffré défi** : pour chaque m de 256 bits,
  calculer `G(m,H(ek))`, rechiffrer et comparer c. La bonne valeur fournit
  directement K. En cas de collisions de chiffrés il faut traiter le
  candidat correct ; cela ne renforce pas le paramétrage.

Dans le modèle générique usuel, ces espaces donnent des recherches de
l'ordre de `2^256` évaluations classiques et `2^128` évaluations quantiques
séquentielles de prédicats réversibles. Les coûts en portes, profondeur,
mémoire et expansion polynomiale restent à compter. Ce sont des plafonds
d'espace de recherche, pas une preuve que ce coût est nécessaire, ni une
comparaison directe avec un coût BKZ. Ils interdisent de promettre 1536
bits de sécurité ou une résistance sans borne en augmentant seulement k.

Pour une clé fixe, répéter m répète `(c,K)` : après T encapsulations
indépendantes, la probabilité de collision de messages est au plus
`T(T-1)/2^257`. Le seuil anniversaire n'est pas le coût de récupération
d'un secret cible. Une collision SHA3-256, une préimage de graine et une
attaque MLWE sont également des objectifs distincts.

`z` de 256 bits protège le chemin de rejet ; sa recherche ne représente
pas automatiquement une récupération de K pour les chiffrés honnêtes.
Un objectif de sécurité multi-utilisateur ou de liaison entre clés doit
compter les clés et encapsulations, ainsi que les collisions possibles de
H(ek). Le présent argument est mono-utilisateur.

## 9. Décision technique issue de ce travail

| Propriété | État et preuve disponible |
|---|---|
| Définition du jeu et du profil exact | Établie ici et raccordée aux fonctions du programme |
| Réduction CPA du cœur à bruits idéaux | Deux hybrides explicites `MLWE_(6,6)` et `MLWE_(7,6)` |
| Rigidité du PKE dérandomisé | Conséquence directe de la comparaison avec la réencapsulation |
| Chiffrés u non canoniques | Rejet implicite établi par unicité de la représentation reconstruite |
| δ-correction avec pire message et moyenne sur clés | Obtenue conditionnellement aux bruits idéaux et au certificat rationnel |
| Transfert des expansions à l'implémentation | Hypothèses et coûts à formaliser, pas d'évaluation numérique acquise |
| Composition FO classique | Rattachement conditionnel établi ; borne concrète complète R1 à formaliser |
| Composition quantique | Conditions identifiées ; théorème exact non instancié |
| Difficulté effective des deux MLWE | Relève de la comparaison commune des attaques ; aucune réduction de difficulté CBD concrète démontrée ici |
| Fuites, fautes, effacement et intégration | Propriétés de réalisation séparées, pas couvertes par IND-CCA abstrait |

Il n'est pas nécessaire de changer immédiatement les formats ou les
paramètres pour poursuivre ce programme de preuve. Il est nécessaire de
conserver la réencapsulation complète, les domaines distincts, l'absence de
drapeau de rejet et les contraintes de génération honnête. Supprimer la
réencapsulation ou exposer sa comparaison modifie les hypothèses de ce
document et impose une analyse propre.

## Références primaires et traçabilité de lecture

1. [Spécification locale R1](SPECIFICATION_DEV_Q7681_R1.md), le
   [bilan C01–C06](BILAN_J2_ET_DECISION_PROTOTYPE.md), le
   [rattachement de correction](LIEN_CERTIFICAT_PROGRAMME_R1.md) et le code
   source nommé en tête. Ce sont les sources de nos équations et formats.
2. [NIST FIPS 203, algorithmes 16–18](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf),
   pour comparaison du découpage K/r, de la réencapsulation et du rejet
   implicite ; les paramètres R1 n'y figurent pas.
3. [Kyber v3.02, 4 août 2021](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210804.pdf),
   §4.3.1–4.3.2 et §5.5 lus intégralement ; PDF récupéré, SHA-256
   `1c54ad57022e00b77ff7acd40e9b38a962e7fbbd02bea73b183349c53a8f8aee`.
   Cette version dérive encore K avec le haché du chiffré ; elle ne décrit
   donc pas à l'identique le KEM R1.
4. [Hofheinz–Hövelmanns–Kiltz 2017](https://people.inf.ethz.ch/dhofheinz/pdf/conf/tcc/HofheinzHK17.pdf),
   version du 26 septembre 2017, §2.1 et §3.1–3.3 lus intégralement ;
   SHA-256 `33412e6927c288f40384d594fd21915dce0a755487489a0a5f7c1961a63df290`.
   [L'erratum de 2021](https://eprint.iacr.org/2017/604.pdf) a été vérifié
   dans l'extrait primaire indexé ; son PDF complet était inaccessible au
   téléchargement lors de cette séance. Les théorèmes individuels de la
   version 2017 ne sont pas employés sans les corrections de rigidité et
   de comptage indiquées par cet erratum.
5. [Hövelmanns–Hülsing–Majenz 2022](https://arxiv.org/abs/2203.10182v1),
   §2 et définitions des jeux d'échecs examinés ; SHA-256 du PDF consulté
   `8ae9bc66b45d58c8ce055bae6978440211c532566b395dd03f8e8e682bb09a12`.
   Cette version v1 n'est pas présentée comme la dernière amélioration des
   bornes.
6. [Ge–Yang–Yu–Yu, ePrint 2025/1641](https://eprint.iacr.org/2025/1641),
   et [Majenz–Sisinni, ePrint 2025/1997](https://eprint.iacr.org/2025/1997)
   ont été repérés dans la veille, mais les textes complets n'ont pas pu
   être récupérés lors de cette séance. Aucun de leurs théorèmes ou gains
   n'est appliqué ici. Leur existence ne vaut pas validation de R1.

Les PDF consultés ont été stockés dans un cache de travail ignoré
`artifacts/generated/cca-primary/`. Les empreintes permettent de distinguer
les versions relues ; les fichiers figés historiques n'ont pas été changés.
