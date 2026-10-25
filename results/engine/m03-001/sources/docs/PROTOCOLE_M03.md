# M03 — Fuzzing guidé, inspection des binaires et performances

Préenregistrement du 25 octobre 2026, sur instruction de l'utilisateur.
Les campagnes complètent M02 sans réécrire ses résultats ni modifier le
profil R1. Aucune nouvelle sélection de paramètres ou clôture de J2.

## Fuzzing prolongé

Quatre cibles : import public, import privé, décapsulation sous plusieurs
clés synthétiques, et séquences structurées d'API à partir de clés valides.
Corpus initial issu des données publiques M01, longueurs proches des trois
formats, valeurs limites et mutations. libFuzzer, couverture LLVM et ASan
sur Linux/WSL, versions verrouillées dans un workspace de test distinct.
Le moteur applicatif n'active pas les interfaces déterministes.

Objectif T07 : quatre travailleurs de six heures CPU effectivement
mesurées, soit au moins 24 heures CPU cumulées de fuzzing. Les durées murales
par processus et la consommation CPU seront distinguées ; la veille de la
machine et les interruptions ne seront pas présentées comme du calcul.
Segments de dix minutes murales au plus, prolongés jusqu'au budget CPU ;
une sortie normale de segment conserve le corpus et reprend avec la graine
suivante. Une sortie en erreur ne déclenche aucune reprise automatique.
Conserver les codes de sortie, journaux, graines, corpus, défauts et
compteurs de couverture. Limiter chaque processus à 2 Go et chaque entrée
à 16384 octets. Toute erreur met fin au travailleur concerné et reste
conservée ; pas d'effacement/reprise silencieuse d'un défaut.

Une vérification courte précède la campagne longue. Le contrôleur écrit
des points d'avancement et un bilan final automatiquement ; tant que la
durée n'est pas atteinte, T07 reste explicitement en cours. Une couverture
de lignes/régions sera mesurée séparément : les compteurs libFuzzer ne
sont pas un pourcentage de couverture des sources.

## Inspection des binaires

Conserver les empreintes et le désassemblage intégral des exécutables
applicatifs Windows et Linux, ainsi que leurs en-têtes, sections,
dépendances, symboles et options de construction. Examiner le graphe
d'appels atteignable depuis les opérations R1, les divisions, les
branchements, les accès mémoire et l'effacement ; identifier les branches
publiques et toute dépendance secrète suspecte. Les bibliothèques système,
appels indirects, chemins non résolus et propriétés microarchitecturales
restent des limites explicites. Une extraction exhaustive du désassemblage
n'est pas, à elle seule, une preuve complète de temps constant.

Toute anomalie trouvée est enregistrée et investiguée. Une correction
change le commit et les empreintes ; conserver le constat antérieur et
relancer les vérifications affectées avant de figer les mesures finales.

## Benchmarks P01

Même hôte, même compilateur, release sans ASan ni couverture pour R1 et
ML-KEM-1024 RustCrypto verrouillé. R1 emploie une convolution directe ;
le témoin dispose d'une NTT. Ce contraste doit figurer dans toute comparaison.
Les interfaces avec aléa système sont mesurées pour les deux réalisations.

Échauffement de 100 opérations par fonction et cinq séries de 1000
opérations pour KeyGen, Encaps et Decaps de chaque moteur. Valider les
échanges hors zone chronométrée ; consommer les sorties avec black_box.
Préparer les entrées avant mesure ; destruction des sorties après mesure,
en précisant ce périmètre. Alterner l'ordre des moteurs selon les séries.
Conserver toutes les durées individuelles, médiane et p95 par série et
agrégées. Mesurer séparément le pic RSS du processus, qui inclut runtime,
allocateur et harnais ; ne pas le nommer mémoire exacte de l'algorithme.
Rappeler les tailles des clés/chiffrés/secrets et la représentation du dk.

Mesurer avant le fuzzing long, sans compilation ni autre campagne lourde
lancée en parallèle par ce travail. Enregistrer CPU, OS, affinité, politique
de fréquences accessible, compilateur et empreintes. Pas de sélection des
séries favorables ni de seuil de performance inventé après mesure.

## Conservation

Rapport et journal actualisés après chaque résultat significatif. Nouvel
instantané M03 avec sources et empreintes ; campagne vivante conservée
séparément jusqu'à sa fin, sans présenter ses compteurs provisoires comme
un succès final. Aucun déploiement ou publication distante.
