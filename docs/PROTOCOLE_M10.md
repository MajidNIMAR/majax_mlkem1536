# M10 — argument exact, décision des paramètres, durcissement et qualification longue

16 novembre 2026. L'utilisateur autorise les chantiers 1 à 4 décrits après
M09. Le chantier 5 de revue extérieure est différé : aucun contact ni audit
tiers dans cette tranche. Les références M09 et antérieures restent intactes.
Référence de recherche avant changement : `8b8e68c82ec84b5900af4ff9acec9dcbcbea96a7` ;
référence publique : `e8a90d451a9ef2f732e5da427fc034f583f5058e`.

## 1. Argument de sécurité exact

Étudier le PKE à matrice et bruits semés du profil R1, le raccord FO/IND-CCA,
les pertes, le temps, la mémoire et les requêtes de la simulation. Rechercher
les théorèmes primaires applicables et contrôler les raccords au programme.
Des calculs exacts et modèles finis doivent pouvoir réfuter leurs extensions
abusives. Distinguer classique, QROM et primitives SHA3/SHAKE concrètes.

La sortie scientifique attendue est un argument compositionnel pour les
parties justifiées, avec critères et obstacles explicites pour le reste.
Une hypothèse supplémentaire n'est pas une preuve héritée de ML-KEM.
C01 ne sera déclaré fermé que si tous ses termes et ressources sont reliés
au jeu exact et à la cible annoncée. Une obligation encore ouverte interdit
une revendication de sécurité finale, même si tous les tests passent.

## 2. Décision des paramètres

Évaluer R1 et la référence ML-KEM-1024 à conventions communes : coût des
attaques connues, mémoire, succès, cibles, plafonds des graines/messages et
correction. Préciser les familles effectivement recalculées, les résultats
historiques réutilisés et les modèles non disponibles. Ne pas transformer
une sortie Core-SVP ou un estimateur heuristique en preuve globale.

Le critère historique C05 est conservé dans son modèle et sa population ;
les effets de requêtes répétées/adaptatives restent distincts. Conclure
par une décision justifiée de conserver R1 pour le développement ou de
retenir un nouveau profil. Aucun gel cryptographique final ne sera déclaré
en présence d'un obstacle C01/C02 non résolu. Tout nouveau profil changerait
son identité, ses vecteurs et ses preuves ; ne pas modifier R1 en silence.

## 3. Durcissement PC

Capturer la référence avant patch. Examiner KG, expansion de bruit, PKE,
message décodé, réchiffrement et sélection finale du secret, y compris
erreurs et copies ABI. Corriger les constats concrets ; garder les formats,
domaines et sorties déterministes R1, l'aléa OS public et `unsafe_code=forbid`.
Toute nouvelle réalisation du pont de correction conserve les anciennes
branches sur leurs sources figées. Les hypothèses de compilation ne valent
que pour les images effectivement collectées et leurs cibles précises.

Conserver les constats négatifs M09. Les images finales Windows GNU x86-64
et Linux GNU x86-64 sont revues séparément, CLI et consommateur par défaut.
Leurs empreintes, instructions et chemins examinés sont consignés. Aucun
temps constant ou effacement universel n'est déduit d'une revue bornée.

Avant campagne : même protocole de comparaison KEM que M09, mais référence
M09 et candidat M10 compilés dans des cibles nouvelles. Cinq séries AB/BA,
500 observations/opération/version/OS, 100 échauffements, CPU10, sans exclusion.
Budget médiane <=1,05 fois M09, p95 <=1,20. Aucun gain minimal n'est imposé
au durcissement. Si un coût dépasse ce seuil, conserver le résultat et
motiver une décision nouvelle avant toute promotion, sans changer le seuil
rétroactivement. Probe mémoire inchangé : 18 opérations, deux peintures,
trois répétitions/version/OS ; sur les 14 opérations utiles, maximum de
pile touchée <= référence+1024 octets et aucune hausse des allocations
demandées. Pile peinte, frames, RSS et mémoire publique restent distincts.

Les corpus intégraux 1000 vecteurs/10000 rejets/10000 mutations/20000 formats
et les 88576 sondes du consommateur sont rejoués sur les images neuves.
Diagnostic temporel neuf : huit clés, cinq classes, 400 observations par
OS, seuil |t|>=4,5 imposant enquête ; aucune exclusion pour faire disparaître
un signal. L'absence de signal ne prouve pas le temps constant.

## 4. Qualification longue du candidat retenu

Plan machine dans `research/m10-campaign-plan.json`, figé avant acquisition.
Quatre harnais locaux : import_public, import_private, decapsulate,
api_sequence. Sources/harnas/oracle/contrôleurs et dépendances sont capturés.
ASan et std reconstruite, Rust1.91.1, verrouillage Cargo et mode hors ligne.
Quatre workers distincts CPU8/12/14/6, disponibles lors du précontrôle.

Chaque harnais doit atteindre **1800 secondes CPU conservatrices après
INITED** ; aucun temps historique, compilation ou initialisation n'est crédité.
Observer le CPU du processus lors de INITED et soustraire sa borne haute,
ainsi que 0,02 seconde pour l'arrondi GNU time. Sans observation valide,
le segment n'apporte aucun crédit post-INIT. Segments demandant 300 secondes
murales, même en fin de budget, maximum 64 segments par worker. Une demande
libFuzzer n'est pas un plafond strict de durée observée. Chaque segment
doit contenir des exécutions après INITED ; conserver toute interruption,
erreur ASan, entrée en échec ou budget manqué. Une reprise est une nouvelle
acquisition explicitement reliée, jamais une substitution des données.

Geler les corpus bruts et une déduplication par octets/SHA-256. Couverture
source/branches LLVM dans des objets distincts avec std distribuée, car
cargo-fuzz0.13.1 interdit --build-std dans son mode coverage. Fusionner les
profils avec tous les objets, conserver les fonctions/branches à zéro et
classer les lacunes ; ne pas additionner des fractions qui se recouvrent.
Rejouer les requêtes déterministes du nouveau corpus contre Rust et l'oracle
Python gelé, en séparant les opérations à aléa frais. Toute divergence ou
défaut bloquant doit être traité avant acceptation de la qualification.

Clôture : sources finales fixées, check complet, données et lecteurs figés,
rejeu hors ligne, paquets et CI Windows/Ubuntu reliés aux sources exactes.
Rapport et journal actualisés au fil des résultats. La version peut rester
un candidat de recherche si C01/C02 ne permettent pas une sélection finale.
