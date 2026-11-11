# M07 — protocole de mémoire et de comparaison du moteur

11 novembre 2026. Début autorisé par l'utilisateur. La référence est le
cœur M06 du commit local `f345e6ac8be50ed904a26601466327b29e81dde8` :
`dev_kem.rs` SHA-256
`eb7635eedc73c3db93d7baa81a86817157969a82890f797acfb3694a767e0262` et
`engine_poly.rs` SHA-256
`ffe7b50dfebfe8d9998296672bd1973a8376a02cb06f2338418e27f23a392ac2`.
Les données et binaires M06 restent figés. Le profil R1, ses formats,
domaines et comptes de transformées 48/55/68 sont conservés.

## Séquence et séparation des décisions

1. Capturer les entrées compilables et le même harnais de référence.
2. Construire et mesurer M06 sous Windows et Linux avec Rust 1.91.1.
3. Consigner les résultats bruts, la dispersion et les limites. Fixer
   alors les budgets d'acceptation dans une décision enregistrée, avant
   de modifier le cœur ou de mesurer un candidat.
4. Comparer une variante qui traite les polynômes en coefficients un
   par un tout en gardant les six opérandes NTT réutilisés. Tout gain
   annoncé attend les mesures ; le payload des objets source ne constitue
   pas une mesure du binaire.
5. Rejouer les corpus intégraux et contrôler les nouveaux exécutables.

## Mesure mémoire : objet effectivement observé

Le harnais séparé utilise un thread natif neuf et une zone bornée de sa
pile active en lecture/écriture. Deux motifs publics peignent les adresses
inactives sous la frontière du harnais, avec marge de sécurité. Un scan
après le retour observe la profondeur maximale de mémoire touchée. Des
contrôles sans opération, des fonctions écrivant des tailles connues et
le refus d'une saturation vérifient le fonctionnement du dispositif.

Cette **profondeur de pile touchée** est une observation dynamique native.
Elle ne mesure pas les seules réservations de pile sans écriture, et
n'établit ni un maximum universel de RSP ni une borne supérieure de pile.
Les coûts du callback et du runtime restent présents. Le contrôle vide
est rapporté séparément ; le soustraire ne donne pas une isolation exacte
du moteur. Les frames LLVM statiques et le RSS restent des métriques
distinctes. Aucun contenu de pile ou octet secret n'est exporté.

Le compteur d'allocations instrumente seulement les requêtes de
`Rust GlobalAlloc` pendant l'appel. Il distingue les nombres, tailles
demandées, profondeur maximale demandée et sorties encore possédées à
la fin. Il ne compte pas les en-têtes de l'allocateur ni toute allocation
des bibliothèques système. Les entrées sont préparées avant la fenêtre ;
les résultats sont validés et détruits après celle-ci. Les pics de pile
et de tas ne sont pas additionnés pour inventer un pic simultané.

Les opérations principales sont KeyGen, Encaps, Decaps valide et rejetée.
Les imports et erreurs exposés par l'API sont examinés séparément. La
partie non sûre du harnais est réservée à cette instrumentation, avec
revue de ses bornes ; l'interdiction de code non sûr du moteur demeure.

## Latence, compatibilité et livraison

Le harnais `m07-measure` utilise les quatre opérations principales,
l'aléa système et une validation hors chronomètre. Comme M06, il mesure
l'appel jusqu'au retour, sans inclure la destruction des sorties. Les
allocations et écritures du rapport sont hors chronomètre. Les versions
sont comparées sur le même hôte, avec ordre alterné et échauffement ; les
observations extrêmes sont conservées et la charge de l'hôte est déclarée.

Le critère fonctionnel est l'égalité exacte des corpus R1 : vecteurs,
rejets, mutations et formats, sur les deux systèmes. Toute modification
de validation garde le balayage complet et l'ordre des catégories
d'erreurs. Les revues d'effacement et de copies portent sur les nouveaux
binaires identifiés par empreinte, avec leur périmètre explicite. Aucun
diagnostic fini n'est présenté comme une preuve globale de temps constant
ou d'effacement.

Le rapport et le journal seront actualisés après référence, décision,
comparaison et contrôles. Les échecs et variantes écartées seront conservés.
