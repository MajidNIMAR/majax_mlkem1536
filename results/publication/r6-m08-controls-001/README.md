# MAJAX R6 M08 — lecteurs du reçu de publication

Ce dossier conserve les quatre fichiers exacts des helpers et tests utilisés
pour la capsule CI `results/publication/r6-m08-001`. Le manifeste donne leurs
empreintes SHA-256 ainsi que celle de ce README. Il s’agit de lecteurs figés du
reçu, distincts de la version du moteur.

Depuis la racine du dépôt, rejouer la vraie capsule :

```sh
python -B results/publication/r6-m08-controls-001/freeze_m08_publication.py verify --output results/publication/r6-m08-001
```

Vérifier les lecteurs copiés avec leurs onze tests purs :

```sh
python -B results/publication/r6-m08-controls-001/test_m08_publication_helpers.py -v
```

Ces deux actions lisent les fichiers conservés et utilisent uniquement des
fixtures synthétiques pour les tests. Elles ne sollicitent ni réseau, ni Git,
ni identifiants, ni compilateur ou exécutable cryptographique. Le calcul de
ROOT par `parents[3]` reste valide à cet emplacement. Les fixtures temporaires
sont créées sous `target/m08-publication-helper-tests`.

Les fichiers `capture_m08_ci_receipt.py` et
`verify_m08_public_snapshot.py` conservent aussi les opérations de collecte
d’origine, avec leurs modes explicites distincts. Ces opérations de collecte
ne sont pas lancées par les deux commandes de rejeu ci-dessus.

La capsule CI est liée au commit public
`b0491eb3960dbcd0642f42f423397f05c58e5cbd`, au commit source local
`33a1828b70c7816ed8ba191ff6c5f3432141315c` et au run `43008567843`.
Elle conserve les contrôles hébergés Windows/Ubuntu et les smokes natifs des
originaux. Les archives historiques y sont relues ; aucune nouvelle campagne
ou preuve globale de sécurité ne découle de ce lecteur.
