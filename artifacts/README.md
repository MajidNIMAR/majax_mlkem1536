# Résultats des vérifications

Le sous-répertoire `generated/` est réservé aux rapports produits automatiquement et est ignoré par Git. Les rapports devront identifier le profil, le commit source, la chaîne de compilation, l’hôte et les commandes exécutées.

Les outils locaux et caches restent dans `.tools/`, les compilations dans `target/`. Ces répertoires ne font pas partie de la distribution source.

Les résultats scientifiques sélectionnés et conservés se trouvent dans `results/`, qui est versionné. Les commandes d’analyse n’écrasent pas ces instantanés. Le rapport et le journal de recherche sont dans `docs/`.

`retained/` conserve une seule copie locale des produits historiques utiles
que les anciens instantanés avaient omis : huit exécutables de couverture
M03, quatre exécutables comparatifs M04 et une archive source finale M04.
Les exécutables sont compressés ; `retained/INDEX.json` donne leurs
empreintes et les liens vers les preuves correspondantes. Ce dossier
est ignoré par Git et reste à conserver lors d'un nettoyage des caches.

Le dépôt public de publication est rangé séparément sous
`publication/majax_mlkem1536/`, à la racine de la copie de recherche. Les
sources primaires dédupliquées restent dans un cache local privé. Le
[guide de publication](../docs/PUBLICATION_GITHUB.md) distingue les preuves
publiées des notes d'entretien du poste, exclues de l'export public.

