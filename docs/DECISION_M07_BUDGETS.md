# M07 — décision des budgets après référence

11 novembre 2026. Décision locale consignée après les mesures complètes du
cœur M06 et avant toute modification du cœur ou mesure d'un candidat. La
méthode a été enregistrée au commit `6756500`. Le reçu
`artifacts/generated/m07-001/acceptance.json` lie les données de référence
par leurs SHA-256 ; il sera conservé dans l'instantané final.

## Référence acquise

Les deux systèmes fournissent chacun **560 observations mémoire** :
14 cas × deux motifs × 20 répétitions. Les contrôles de démarrage de
28 cas par système sont distincts de cette référence. Le harnais mesure
la profondeur de pile touchée et les requêtes GlobalAlloc à son API de
retour ; ce ne sont ni un maximum universel de RSP ni le pic du CLI livré.

| Système | KeyGen, min–max octets | Encaps, min–max | Decaps valide/rejetée, min–max |
|---|---:|---:|---:|
| Windows | 12984–13392 | 14808–14808 | 23688–23688 |
| Linux | 12824–12824 | 14536–14536 | 23336–23336 |

Les requêtes observées sont constantes sur ces répétitions : KeyGen
2 allocations/7616 octets retenus ; Encaps 1/2656 ; Decaps 0. L'import
privé valide utilise temporairement un objet public et atteint 7616 octets
demandés vivants pour 5088 retenus. Les maxima de pile et de tas ne sont
pas additionnés en un faux maximum simultané.

La référence de latence contient 4000 observations par système, soit
200 par opération dans cinq séries ; 25 échauffements sont hors panel.
Le rapport entre la plus grande et la plus petite médiane de série
atteint environ 1,095 sous Linux pour Decaps valide. Fréquence et activité
générale de l'hôte ne sont pas isolées.

Un premier lancement Linux a rencontré une erreur de lecture JSON dans
le contrôleur qui mélangeait stdout et stderr ; ce flux initial n'a pas
été conservé. La deuxième acquisition complète est conservée séparément
puis validée, sans sélection d'observations dans le panel. Le contrôleur
sépare désormais les deux flux et les conserve avant analyse. Le code et
les binaires du harnais ne changent pas pour cette correction d'acquisition.

## Critères fixés avant le candidat

- **Pile primaire :** pour chacune des quatre opérations et chaque système,
  le maximum candidat doit être au moins **2048 octets sous le minimum
  de référence**. Ce seuil dépasse la dispersion de 408 octets observée
  et correspond à quatre polynômes de stockage ; il ne promet pas le gain.
- **Imports et erreurs :** aucun maximum de pile touchée ne doit augmenter
  de plus de **512 octets**, avec le même harnais et les mêmes motifs.
- **Tas demandé :** aucun accroissement du maximum du nombre de requêtes,
  du total des tailles demandées ou du pic demandé vivant, pour chaque
  cas API. Les octets retenus à l'API de retour restent identiques à la
  référence. Une migration cachée de pile vers tas ne satisfait pas le jalon.
- **Latence :** rapport candidat/référence ≤ **1,10 en médiane** et ≤
  **1,20 au p95**, pour chaque opération et système. Ce sont des budgets
  pratiques prédéclarés face à la dispersion, pas des seuils de
  significativité. Les écarts, même acceptés, seront publiés.
- **Comparaison finale :** cinq séries alternées, **1000 observations par
  opération et version**, 100 échauffements, CPU logique 10 ; toutes les
  observations sont conservées. La destruction des sorties est hors timer.
- **Compatibilité :** mêmes octets sur les corpus R1 intégraux, mêmes
  formats, décisions de rejet et ordre d'erreurs, comptes NTT 48/55/68,
  interdiction de code non sûr dans le moteur.
- **Livraison :** contrôles complets et revue propre aux nouveaux binaires
  Windows/Linux, avec leurs empreintes. Une amélioration du stockage ne
  constitue pas une clôture de C01, une preuve CT ou d'effacement global.

Le candidat envisagé conserve les six opérandes NTT réutilisés et traite
les polynômes en coefficients un par un. Il sera retenu seulement après
confrontation à ces critères ; une régression sera consignée et traitée.
