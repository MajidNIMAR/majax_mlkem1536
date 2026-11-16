# M09 — contrats internes, cycle secret et NTT à tables publiques

16 novembre 2026. La réalisation retenue est le candidat scalaire **002**,
profil `KEM1536-DEV-Q7681-R1`, compatible avec tous les formats et domaines
R1 antérieurs. Les cinq chantiers ont produit du code, des analyses et des
preuves distinctes. Le programme reste indépendant de Messenger et
d'Android. Une qualification interne ne vaut pas audit extérieur.

## Ce qui change dans le moteur

- Les graines de bruit sont empruntées sous forme de tableaux de 32 octets.
  `KeygenNoise` et `EncryptionCoins` distinguent leurs rôles ; les méthodes
  nommées conservent les nonces 0..5, 6..11 et 12. Aucun nouveau domaine de
  hash ou format n'est introduit. La vue `seed_tail` ne copie pas le secret.
- KeyGen et Encaps remplissent leur propre propriétaire d'entropie. Un échec
  efface explicitement les octets partiellement remplis, puis remonte avant
  le calcul cryptographique. Les tests injectent chacun des 65 préfixes KG
  et 33 préfixes Encaps, vérifient un appel de taille exacte et zéro NTT.
  Le fournisseur de test reste privé ; les API publiques utilisent l'OS.
- La récupération et le déchiffrement PKE écrivent le message dans le
  propriétaire créé par Decaps, au lieu de retourner deux buffers remplis.
  `SecretBox` n'a plus de `Clone` générique ; seul le chiffré public possède
  une copie explicite avec stockage indépendant.
- Deux tables publiques de 255 facteurs remplacent le recalcul de 1024
  produits publics par transformée. Leurs 1020 octets sont contrôlés par
  exposants indépendants ; les comptes de transformées restent 48/55/68.
  Le hint `black_box` porte uniquement sur le twiddle public. Il ne garantit
  aucune propriété cryptographique : les images finales doivent être revues.

La production conserve `unsafe_code=forbid`. Le pont certificat reconnaît
`M09-typed-noise-destination-message-1`, 62 ancrages examinés, avec les
branches historiques M02/M04/M06/M07/M08 conservées. Ce contrôle lexical
et les vérifications entières ne constituent pas une preuve formelle Rust.

## Une variante rejetée, puis un correctif qualifié

La première variante à tables a gagné environ 20–22 % sur son panneau KEM,
mais son témoin multiply_add Linux a dépassé son budget. La revue des
images complètes a surtout tracé e2+Encode(m) vers XMM8, puis une nouvelle
sauvegarde ABI hors propriétaire effacé dans les deux images Windows.
Cette variante et ses paquets sont **rejetés pour la livraison**. Leurs
données, dont la trace de 16 octets, restent conservées.

La variante scalaire est préenregistrée séparément. Ses quatre images
finales CLI/consommateur n'ont ni SIMD ni division dans transform. Les six
stores de frame examinés proviennent d'indices, pointeurs et du twiddle
public. Le mécanisme de copie XMM8 observé dans 001 a disparu de ces
fonctions. Les 32 octets du message ont des stores zéro avant retour normal
dans chaque image, soit 128 témoins. La réservation locale de transform
augmente de 16 octets contre M08, hors pushes. Cela ne prouve ni tous les
chemins PKE, ni les registres/ABI/copies de l'appelant, ni le temps constant.
La [revue du cycle secret](REVUE_CYCLE_SECRET_M09.md) donne les adresses,
empreintes, hypothèses et limites.

## Mesures finales du moteur complet

Cinq séries AB/BA, 500 observations et 100 échauffements par opération,
version et OS, CPU logique 10 : **40000 latences**, sans exclusion.
Les captures de sources, cibles et images sont séparées. Fréquence non
fixée, caches/outils partagés, isolation complète de l'hôte non démontrée.
La référence est M08, pas un moteur d'un autre dépôt.

| Opération | Windows M08 → M09, médiane µs | Réduction | Linux/WSL M08 → M09, médiane µs | Réduction |
|---|---:|---:|---:|---:|
| KeyGen | 488,800 → 419,500 | 14,18 % | 501,062 → 435,257 | 13,13 % |
| Encaps | 537,750 → 458,900 | 14,66 % | 553,481 → 475,742 | 14,05 % |
| Decaps valide | 663,700 → 564,800 | 14,90 % | 678,690 → 581,109 | 14,38 % |
| Decaps rejet | 662,100 → 564,400 | 14,76 % | 697,092 → 579,844 | 16,82 % |

Chaque médiane respecte ≤1,05 fois la référence et chaque p95 ≤1,20.
L'objectif d'au moins 5 % de gain sur chaque OS est atteint. Le panneau
scalaire préalable de 40000 observations et le panneau vectorisé rejeté de
50000 restent distincts ; on ne combine pas leurs gains ni ceux de M06/M08.

La mémoire conserve 216 observations de référence M08 reconstruites dans
M09 et ajoute 216 observations du candidat : 18 opérations × deux peintures
× trois répétitions × deux OS. Les 14 opérations hors calibrations/noop
respectent maximum de pile référence +1024 octets et absence d'augmentation
des requêtes/octets d'allocation. Les maxima KEM observés sont :

| Opération | Windows référence → candidat, octets | Linux référence → candidat, octets |
|---|---:|---:|
| KeyGen | 7792 → 7792 | 7208 → 7192 |
| Encaps | 7672 → 7672 | 7400 → 7400 |
| Decaps valide/rejet | 13064 → 13048 | 12696 → 12696 |

La pile peinte n'est ni RSS ni une borne universelle du pic RSP ; 512 octets
au sommet ne sont pas peints. Un zéro détecté sous cette marge ne prouve
pas une pile nulle ou un effacement. La frame statique +16 et les tables
publiques restent des coûts, même si les maxima instrumentés n'augmentent pas.

## Correction et tests nouveaux

Sur chaque OS : 1000 vecteurs et 10000 rejets concordent intégralement aux
corpus R1 ; 10000 mutations sont confrontées à l'oracle Python gelé et
20000 entrées de formats sont vérifiées. Le consommateur par défaut passe
13 cas d'import, un échange/rejet frais et 88576 sondes finies. Le CLI par
défaut passe 16 échanges/rejets et refuse cinq commandes de recherche.

Diagnostic temporel neuf : 16000 observations par OS, huit clés et cinq
classes. Maximum |t| Windows **2,11069986**, Linux **1,11651668** ; zéro
franchissement de 4,5. C'est une absence de signal dans ce diagnostic, pas
une preuve de temps constant.

Le build ASan/std reconstruit M09 de la tentative002 fournit les quatre
images utilisées par l'acquisition003 : **194,64 s CPU**, dont une borne
inférieure conservatrice de **175,90 s après INITED**, quatre budgets de
30 s atteints, huit segments et 1046348 exécutions après INITED, répétitions
comprises. Aucun défaut observé. Pas de couverture source LLVM ni de rejeu
indépendant du nouveau corpus de fuzz dans ce smoke ; les régressions et
mutations indépendantes ci-dessus sont des contrôles distincts. Aucun
temps M08 n'est transféré et aucun second build ASan n'est inventé pour003.

Les incidents sont conservés : CPU16 indisponible avant création, Python
Linux3.10 sans tomllib avant compilation001, segment API002 terminé dès
l'initialisation, puis écart d'addition flottante lors du rejeu003. La
reprise003 est une nouvelle acquisition avec les mêmes images M09, sans
crédit des exécutions002. Le post-traitement corrige uniquement la cohérence
des totaux (<1 ns de tolérance) ; les budgets individuels restent stricts,
les données brutes inchangées et aucun segment n'est rejoué pour cet arrondi.

## Sécurité et publication

Le [sous-lemme M09](SECURITE_M09.md) remplace conditionnellement les bruits
à graines par des CBD frais pour un défi CPA dans le ROM classique, avec
matrice toujours semée et perte rationnelle explicite. Les 380 panneaux,
153512 triplets et 512 transcripts adaptatifs contrôlent le comptage.
La veille primaire est actualisée sans importer les gains d'autres profils.
**C01, le PKE à matrice semée, le QROM et le transfert à Keccak concret
restent ouverts.** Aucun nouveau niveau global de sécurité n'est attribué.

Deux paquets de recherche livrent les originaux qualifiés, sources compactes
et licences. Une répétition par OS est vérifiée : Linux brut identique ;
Windows égal hors seuls timestamp COFF/checksum PE. Outils, hôte, caches
et chemin source sont partagés : aucune reconstruction par un tiers n'est
revendiquée. Les notices du CLI et des diagnostics sont distinctes.
Les documents compacts conservent leur état de capture, notamment
l'addendum avant ajout de résultats ; le rapport courant fournit le bilan.

La capsule moteur, le check local complet et la CI neuve sont des reçus
distincts. Leur clôture et leurs identifiants seront consignés après succès.
Le [dossier de revue externe](REVUE_EXTERNE_M09.md) prépare périmètre,
reproduction et questions ; aucun tiers n'a été contacté et aucun audit
extérieur n'est déclaré. Le moteur continue d'évoluer comme programme
de recherche et d'ingénierie ; Android/Messenger restent hors de cette tranche.


## Clôture locale M09 avant publication

La capsule moteur `results/engine/m09-001` est gelée et rejouée : 5618
membres, neuf groupes, provenance SHA-256
`0e785d177c8814d4cf0ae04696049dbe3d273620ed1d4a57c4bfb4819e064397`.
Le grand recueil des résultats rejetés est fractionné en deux parties ;
sa concaténation retrouve exactement l'archive originale et sa somme.
`m09-chunks-001` fige les adaptateurs de stockage, sans modifier les données
scientifiques, les images ou le manifeste moteur.

Le contrôle complet Windows réussit en 16 min 28 s : fmt, Clippy strict,
Rust par défaut/toutes fonctionnalités, 438 tests Python et tous les rejeux
requis. Les 279 entrées de sources/contrôles restent identiques avant/après.
`results/engine/m09-verification-001` conserve le reçu et le journal.
Un durcissement ultérieur du seul lecteur de stockage vérifie explicitement
les parties même si le tar complet est aussi présent ; quatre tests ciblés
et la suite entière de 439 tests Python passent. Ce suivi distinct est dans
`m09-reader-review-001`. Les 37 entrées compilables qualifiées sont inchangées.

Les deux paquets originaux sont qualifiés en interne, avec sources compactes
et licences. Le dossier externe est concret et prêt pour une remise, sans
contact tiers ni audit déclaré. La publication normale sur GitHub et sa CI
neuve Windows/Ubuntu constituent la dernière vérification de cette clôture ;
leurs identifiants et leur résultat seront ajoutés après constat effectif.
