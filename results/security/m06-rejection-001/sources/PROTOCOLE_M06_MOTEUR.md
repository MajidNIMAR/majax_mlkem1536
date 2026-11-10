# M06 — moteur avec accumulations en domaine NTT

10 novembre 2026. L'utilisateur autorise l'implémentation du programme
proposé après M05. Le point de départ est le commit
`693c6a305b5143b9b00b912353bbae153cad4e4f`. Le projet reste sous NIST,
indépendant des moteurs applicatifs Majax. Aucun push n'est implicite.

## Question de construction

Le moteur M04 transforme les deux opérandes et effectue une inverse à
chaque multiplication. M06 doit réutiliser les vecteurs transformés et
accumuler leurs produits avant de revenir aux coefficients. Les comptes
structurels visés sont 48/55/68 transformations pour KeyGen/Encaps/Decaps,
contre 108/126/144 auparavant. Ce ne sont pas des gains de latence mesurés.

R1 conserve q=7681, n=256, rang 6, CBD(3), u exact, v sur 5 bits, les
domaines, formats, tailles et graines. Le rejet implicite réencapsule et
compare toujours le chiffré entier. Une entrée et des graines identiques
doivent produire les mêmes octets. La nouvelle représentation NTT demeure
interne : elle n'est pas un nouveau jeu de paramètres.

## Périmètre du code

- Séparer les types internes en coefficients et dans le domaine NTT.
- Remplir les destinations détenues par l'appelant ; ne pas réintroduire
  de retour de polynôme secret par valeur ou de cache secret persistant.
- Réduire les sommes à chaque terme, en conservant des coefficients
  canoniques et des bornes d'intermédiaires explicites.
- Conserver la convolution indépendante et les calculs de référence.
- Vérifier les comptes sans ajouter de compteur au chemin de production.

Un cache de matrice, une clé préparée, le SIMD, les encodages spécialisés
et les changements de paramètres sont des décisions ultérieures soumises
au profilage. Ils ne sont pas ajoutés à ce jalon pour multiplier les
sources possibles de régression.

## Critères de vérification et de mesure

La vérification doit retrouver intégralement, sous Windows et Linux,
les 1000 vecteurs, 10000 rejets, 10000 mutations et 20000 contrôles de
formats des corpus figés. L'égalité avec ces sorties anciennement
confrontées à Python ne sera pas présentée comme une nouvelle simulation
des événements de décapsulation rares.

Les nouveaux binaires doivent avoir leur propre revue d'arithmétique,
de destinations, d'effacements et d'inventaire de branches et appels.
Les diagnostics de temps et le fuzzing ne constituent pas une preuve
générale de temps constant ou d'effacement de toutes les copies.

Les mesures avant/après utilisent des sources et binaires figés, la même
chaîne et une affinité explicite. L'ordre des versions doit varier. Les
compilations et le fuzzing lourds attendent la fin de cette fenêtre.
Conserver médiane/p95, observations brutes, conditions machine et mémoire
séparée par version. Un mauvais résultat doit rester dans le bilan.

La campagne instrumentée s'exécute sur la version M06 figée, avec budget
CPU propre, sources, outils, corpus et journaux conservés. Une couverture
source n'est annoncée qu'après un export effectif ; les compteurs cov/ft
de libFuzzer ne sont pas convertis en pourcentage de lignes. Le rejeu de
corpus par la référence indépendante conserve les échecs et son périmètre.
Les temps M03 et M04 ne sont jamais attribués à ce nouveau moteur.

## Volet de sécurité indépendant

La question ciblée est la sécurité du rejet `J(z,c)`, préfixé par z de
256 bits, avec D accès classiques à la fonction indexée et q accès publics
à l'oracle. Les analyses classique et quantique restent distinctes.
Les constantes ou transferts non vérifiés restent ouverts. Un résultat
dans le modèle RO ne prouve pas la sécurité de Keccak concret et ne ferme
pas à lui seul C01 ou les avantages CPA/OW du PKE à graines.

## Conservation et décision

Créer de nouveaux instantanés M06 et vérifier leurs empreintes ; ne pas
modifier les archives M01–M05 et J2. Le rapport et le journal doivent
consigner le code livré, les résultats effectifs, les limitations et les
éventuelles campagnes encore actives. La tâche complète `check` est requise
après stabilisation. La livraison doit être rattachée à un commit local
et ne suppose pas une publication distante ou un audit extérieur.
