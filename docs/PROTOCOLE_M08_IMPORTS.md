# M08 — Import des clés, résidus compilés et validation élargie

11 novembre 2026. Protocole fixé avant toute modification du cœur M07.
Le profil reste `KEM1536-DEV-Q7681-R1`, q=7681, rang six, n=256,
CBD(3), u exact sur 13 bits et v sur 5 bits. Aucun domaine, format ou
algorithme mathématique du KEM n'est modifié par cette étape.

## Référence et hypothèse

La référence a `dev_kem.rs` SHA-256
`3b7594bf96b6dcf3a52001582f8ab832da774ed059db66999e0e5091c8c8d48b`.
M07 a observé des bits de coefficients hors propriétaire effacé sur des
imports privés s-invalid. La validation actuelle construit une Poly pour
obtenir seulement un masque de canonicalité. Hypothèse M08 : un balayage
direct du format par groupes de 13 octets/huit coefficients simplifie
ce chemin. La disparition des résidus n'est pas supposée à la source ;
elle doit être établie sur les formes machine réellement conservées.

## Compatibilité et couverture fonctionnelle

- Conserver les 1536 coefficients parcourus avant décision de canonicalité,
  et l'ordre longueur → secret → public intégré → hash.
- Conserver exactement les sorties des corpus complets : 1000 vecteurs,
  10000 rejets, 10000 mutations et 20000 formats par hôte.
- Un consommateur de bibliothèque avec fonctionnalités par défaut conserve
  les imports par des wrappers non intégrés. Il examine les 8192 valeurs
  possibles sur huit alignements et les frontières q−1/q/8191 dans toutes
  les positions publiques, secrètes et publiques intégrées, avec erreurs
  de hash combinées. Ces sondes ne sont pas le vecteur exhaustif complet.
- Les fixtures structurelles de latence sont identiques entre processus ;
  le smoke distinct génère une vraie paire fraîche et utilise les clés
  importées pour un échange et un rejet. Aucun secret d'application.

## Construction et mesures avant toute charge de fuzzing

`research/run_m08.py` capture les entrées compilables, les include Rust,
les deux petits workspaces et les contrôles. Rust 1.91.1, cibles Windows
GNU x86-64 et Linux x86-64 via Ubuntu22.04/WSL, caches d'outils/dépendances
partagés déclarés. Référence/candidat ont des cibles séparées ; les six
configurations d'un même couple version/hôte partagent leur cache Cargo.
Les copies de chaque binaire et les recettes sont identifiées par SHA-256.

Le probe M08 reprend le mécanisme natif M07 et ajoute quatre cas privés
invalides : secret premier/dernier, public intégré, secret/public/hash
combinés. Ses parties non sûres restent limitées à l'instrumentation ;
la production garde `unsafe_code=forbid`.

- Mémoire : 18 cas × deux motifs ×20 répétitions par version/hôte.
  Toutes les calibrations 8/32/64 Kio et tous les compteurs doivent passer.
  La profondeur de pile touchée n'est ni une borne de RSP ni le pic du CLI.
  GlobalAlloc mesure les requêtes Rust, pas RSS ou allocations natives.
- Latence : cinq séries alternées AB/BA, 1000 observations/opération/
  version/série, 100 échauffements hors panel, CPU logique10. Quatre
  opérations KEM et onze opérations d'import sont des panels distincts.
  Retour API chronométré ; validation et drop hors fenêtre. Aucune exclusion,
  aucun remplacement d'une durée nulle ; une acquisition invalide reste
  conservée et une éventuelle reprise porte un nouvel identifiant.
- Budget : au plus +512 octets de maximum observé par cas non calibrant,
  aucune hausse des nombres/requêtes/pics de tas, mêmes octets retenus.
  Rapports candidat/référence médiane ≤1,10 et p95 ≤1,20 sur chaque opération.
  Les budgets sont opérationnels, sans affirmation de significativité.

Les seuils sont dans `research/m08-acceptance.json`, fixés avant référence
et candidat. Une amélioration mémoire ou une régression est publiée telle
quelle. Les autres entrées compilables sont identiques entre les captures.

## Revue machine

Revoir les quatre consommateurs (M07/M08 × Windows/Linux), avec références,
recettes, sources et listes d'instructions conservées. Suivre le balayage,
les erreurs et les résidus identifiés jusqu'au retour ; conserver tout
nouveau résidu ou trajet non résolu. L'absence d'import dans le CLI Linux
ne vaut pas preuve de sa forme machine. Les registres, tous les systèmes
et tous les chemins ne sont pas couverts par une preuve universelle.
Le candidat n'est retenu pour ce correctif qu'avec un constat explicite
sur les résidus ciblés, la compatibilité et les budgets.

## Campagne nouvelle et posttraitements

Le plan `research/m08-fuzz-plan.json` fixe **1800 secondes CPU par harnais**,
soit au moins7200 secondes CPU nouvelles. Quatre workers peuvent s'exécuter
en parallèle sur les CPU8/10/12/14, correspondant aux cœurs4/5/6/7 exposés
par WSL ; l'isolation globale de l'hôte n'est pas garantie. Segments au plus
600 secondes murales, temps CPU utilisateur+système compté séparément,
sans transfert de M03/M04/M06/M07. Chaque harnais doit exécuter après INITED.

La campagne ASan reconstruit std. cargo-fuzz0.13.1 refuse la combinaison
build-std et instrument-coverage : les binaires et profils de couverture
source sont donc distincts, ASan mais sans std reconstruite. Conserver les
quatre objets/profils, exports complets et union, y compris les zéros ;
ne pas transférer leurs propriétés ou empreintes entre instrumentations.
Dédupliquer et figer le nouveau corpus, puis confronter les comportements
déterministes pris en charge au Python indépendant NumPy2.3.5. Distinguer
entrées uniques, exécutions répétées, requêtes comparées et opérations fraîches.

## Sécurité, livraison et rapport

Un volet C01 borné examine l'information latérale classique sur la clé de
rejet dans le modèle idéal. Il ne modifie pas le moteur et ne ferme pas C01.
La canonicalité des clés importées ne prouve pas leur entropie/provenance.
Préserver tous les résultats historiques, mettre à jour rapport et journal,
reconstruire les paquets, vérifier les originaux et les contrôles complets
Windows/Ubuntu. Aucune preuve générale de temps constant, d'effacement,
sécurité globale, audit externe ou standardisation n'est acquise par ces essais.
