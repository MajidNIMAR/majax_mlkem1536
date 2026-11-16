# M09 — dossier de revue indépendante

16 novembre 2026. Ce document prépare une revue reproductible de MAJAX R6.
Il ne constitue ni un audit externe effectué, ni une certification, ni un
classement de sécurité. Aucun tiers n'a été contacté par ce travail.

## Objet et limites de la demande

Examiner le KEM expérimental exact `KEM1536-DEV-Q7681-R1`, n=256, rang=6,
q=7681, CBD(3), u encodé exactement sur 13 bits et v comprimé sur 5 bits.
Le nom 1536 désigne six polynômes de 256 coefficients ; il ne désigne pas
1536 bits de sécurité. Les paramètres, domaines et construction sont propres
au projet et ne sont pas une quatrième variante normalisée de ML-KEM.

La revue demandée couvre l'argument conditionnel C01 et son écart aux
primitives concrètes, le lien du certificat de correction au programme, les
coûts d'attaques dans leurs conventions explicites et l'implémentation PC.
Messenger, Android, réseau applicatif, stockage mobile et protocole de
transport ne font pas partie de cette tranche.

## Parcours vérifiable du dépôt

| Élément | Point d'entrée | Travail attendu du réviseur |
|---|---|---|
| Construction exacte | `docs/SPECIFICATION_DEV_Q7681_R1.md`, `crates/kem1536/src/dev_kem.rs` | Vérifier formats, labels, nonces, expansion et rejet implicite |
| Décision du prototype | `docs/BILAN_J2_ET_DECISION_PROTOTYPE.md`, cahier des charges | Distinguer sélection expérimentale, correction et sécurité non fermée |
| Argument C01 | `docs/SECURITE_CONCRETE_R1_M05.md`, `docs/SECURITE_M09.md`, modèles sous `research/` | Refaire les jeux, pertes, ressources et hypothèses de primitives |
| Pont de correction | `research/verify_r1_certificate_bridge.py`, branches historiques et nouvelle réalisation M09 | Vérifier les identités et leur correspondance au code précis |
| Attaques | `docs/COMPARAISON_EXPERIMENTALE_M05.md`, résultats de sécurité figés | Contrôler budgets temps/mémoire, compression, distributions et extrapolations |
| Owners et erreurs | `docs/REVUE_CYCLE_SECRET_M09.md`, tests Rust du moteur | Examiner les chemins valides, invalides, entropie partielle et propriétaires |
| Arithmétique | `crates/kem1536/src/engine_poly.rs`, `docs/OPTIMISATION_M09.md` | Vérifier bornes intermédiaires, NTT, canonicalité et absence de changement des sorties |
| Référence indépendante | `research/kem_r1_reference.py`, fixtures et archives moteur | Rejouer sorties exactes ; ne pas créditer de temps de fuzz historique à M09 |
| Exécutables | Paquets et reçus M09 après qualification | Reproduire depuis source figée et comparer les octets selon la convention annoncée |
| Preuves historiques | `results/engine/m08-001` et `results/publication/r6-m08-001` | Rejouer les archives figées, sans les assimiler à des mesures M09 |

Le commit local et le commit public, les empreintes source, vecteurs, images,
outils et reçus de validation doivent être fournis avec la référence M09
finale. Les chemins de cette table qui décrivent une acquisition nouvelle
n'attestent pas de son achèvement : les reçus finaux en donnent la portée.

Un résultat négatif de M09 doit faire partie de la remise : la première
variante à tables NTT vectorisées est rejetée après identification, dans les
deux images Windows, d'une nouvelle sauvegarde ABI de 16 octets dérivés de
e2+Encode(m), hors owner effacé. Les collections et la trace littérale de
`m09-lifecycle-review-001` conservent cette observation ; sa provenance est
`443641a7bf45422c1fb7b6f93ce5a99b549003a61dd2a7cf9f95d796a4722645`.
Le traitement ciblé est vérifié sur les quatre images de la variante
scalaire 002 : absence de SIMD dans `transform`, stores de frame tracés à
des données publiques, propriétaire du message identifié et 32 octets
effacés avant le retour normal par image. Sa revue a pour provenance
`8116e35ea0b8357ea6be649c2c88b3105ddcf111bdbbfd56bcfa16e482467d9b`.
Le réviseur doit refaire ces contrôles, examiner le hint public et les
autres frontières ABI. Cette correction ciblée ne prouve pas l'effacement
de toutes les copies ABI du logiciel et ne préjuge pas des autres critères
de publication de la réalisation finale.

## Questions prioritaires et résultats attendus

1. **C01, PKE à graines.** Le jeu exact et la réutilisation des adresses N
   correspondent-ils aux appels du programme ? Quelles hypothèses doivent
   être ajoutées pour remplacer les oracles idéaux par SHA3/SHAKE ? Fournir
   une réduction ou une objection localisée, avec ressources et constantes.
2. **Correction.** Le certificat concerne-t-il les distributions et messages
   énoncés, avec les arrondis et dépendances effectivement employés ? Toute
   hypothèse manquante ou contre-exemple doit préciser la population concernée.
3. **Cryptanalyse.** Les avantages ou coûts comparés incluent-ils les mêmes
   conventions de mémoire, réduction, multi-cibles et probabilité de succès ?
   Les petits modèles de scores sont-ils extrapolés au-delà de leur portée ?
4. **Implémentation.** Les chemins de KG, PKE, réchiffrement et sélection
   introduisent-ils copies non effacées, contrôle ou adresses dépendant de
   secrets ? Une observation doit désigner source, empreinte de l'image,
   adresse et données concernées, séparément d'une fuite exploitable.
5. **Reproductibilité.** Un tiers peut-il reconstruire et rejouer la référence
   publiée avec les dépendances et versions déclarées ? Consigner toute
   différence brute avant normalisation et toute limite de l'environnement.

Chaque constat sera inscrit avec sévérité justifiée, périmètre, reproduction,
preuve ou hypothèse, correction proposée et état de contre-vérification.
Un résultat négatif, un blocage mathématique ou une divergence doit être
conservé avec les autres résultats.

## Modalités de remise

Le dossier peut être remis à un cryptanalyste et à un spécialiste de
l'implémentation à partir d'un commit public immuable. Le réviseur choisit
ses propres outils et peut reconstruire ses propres images ; cette
indépendance ne sera déclarée qu'après réception et vérification de son
rapport. Le rapport devra préciser auteur, date, version examinée, temps
consacré, exclusions et limites de conclusion. Une revue ponctuelle ne
remplacera pas un audit complet de la construction et du logiciel.

L'envoi effectif, le destinataire, le budget et toute publication sous son nom
restent à définir avec l'utilisateur. La préparation du présent dossier et
les revues internes ne constituent pas une approbation extérieure acquise.


## Référence concrète de remise M09

La réalisation scalaire finale002 est qualifiée en interne. Manifeste de
sources : `0829c8112ce771072c63ae07ae5a7f32cc7a06cf91531950047ddd4685cea3eb`.
CLI Windows : `9eb95fb2cb9a8531a216012b4cff71d6b10d1a7951285d9d3c666f8186002255` ;
CLI Linux : `7cc2368a7827c33ee1b1563ef9fa9b155189691d58769e99f68def399f41fd01`.
Les paquets et toutes les étapes sont dans `results/engine/m09-001` ; la
provenance moteur est `0e785d177c8814d4cf0ae04696049dbe3d273620ed1d4a57c4bfb4819e064397`.
Le contrôle complet local et le suivi du lecteur sont scellés séparément.
Le bilan M09 expose les limites et les incidents ; la CI publique sera reliée
au commit testé, aux cartes d'export et aux 37 entrées compilables exactes.
Cette remise ne crédite aucun tiers d'une approbation qu'il n'a pas fournie.
