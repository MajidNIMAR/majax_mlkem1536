# Licences et provenance du lot M15

Les contributions originales du projet sont soumises à la licence
[Apache-2.0 du dépôt](../../../../LICENSE). Le
[NOTICE](../../../../NOTICE) et les
[notices relatives aux tiers](../../../../THIRD_PARTY_NOTICES.md) du dépôt
restent applicables. Cette licence ne remplace pas les conditions propres
aux dépendances externes.

## Contributions du projet

Les programmes de modélisation et de vérification, les acquisitions
arithmétiques sélectionnées et leur documentation sont des contributions
du projet. Les deux sources Rust lues par le lot sont déjà présentes dans
le dépôt ; elles ne sont pas vendoriées une seconde fois dans ce dossier.
Les attributions existantes dans les fichiers restent applicables.

## Solveur Z3

Le solveur est une dépendance externe fournie par **The Z3 Theorem Prover
Project**. Le paquet sélectionné est `z3-solver 4.15.4.0`, wheel
`z3_solver-4.15.4.0-py3-none-win_amd64.whl`. Les métadonnées de publication
capturées dans [pypi-release.json](pypi-release.json) identifient sa licence
comme `MIT License` et son projet d'origine comme
[Z3Prover/z3](https://github.com/Z3Prover/z3).

[solver-source.json](solver-source.json) conserve l'URL officielle, la taille
et l'empreinte du wheel. [solver.lock.json](solver.lock.json) et
[toolchain.json](toolchain.json) lient le contenu installé à cette
distribution. Le wheel et le paquet installé ne font pas partie des
fichiers source sélectionnés pour publication : l'installation les obtient
séparément dans le cache local ignoré `.tools/m15-proof/`.

L'indication de licence ci-dessus décrit les métadonnées du paquet Z3 ;
elle ne réattribue pas les composants d'exécution Windows livrés avec le
wheel. Leurs conditions d'origine restent applicables. Ce lot ne prétend
pas fournir un texte de licence embarqué absent du wheel et ne présente
pas le solveur ou ses composants tiers comme des créations du projet.

## Interpréteur et autres références

CPython est fourni séparément par l'utilisateur. Ce lot ne redistribue
ni l'interpréteur ni sa bibliothèque standard. Les références et documents
externes évoqués dans les travaux plus larges M11–M15 ne sont pas incorporés
à cette sélection sous forme de copies PDF ou HTML.

La conservation de ces sources et attributions n'implique ni audit externe,
ni approbation du projet par les auteurs des dépendances.
