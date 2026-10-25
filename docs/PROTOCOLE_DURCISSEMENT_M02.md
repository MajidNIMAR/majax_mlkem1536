# M02 — Protocole de durcissement R1

Préenregistrement du 25 octobre 2026, avant nouvelles campagnes et
mesures temporelles. L'utilisateur autorise le durcissement complet
possible sur cet hôte, sans nouvelle validation de routine.

## Corrections prévues et invariants

Remplacer la croissance des buffers secrets par des stockages de taille
fixe, effacer explicitement les accumulateurs et temporaires possédés,
réduire les copies évitables, séparer validation d'import et calcul
interne sur objets validés. Éliminer du cœur arithmétique R1 les divisions
et les corrections conditionnelles dépendant d'un secret au niveau source,
avec bornes et tests ; conserver l'oracle générique séparé. Examiner
l'assembleur généré sur les hôtes disponibles, sans en déduire une preuve
universelle de temps constant.

Conserver strictement les domaines, octets de formats, distributions et
sorties R1. Recalculer les 1000 vecteurs et 10000 rejets appariés avec le
code durci, contre les corpus figés M01 et leur oracle Python archivé.
Ne pas réécrire ces corpus. Enregistrer des résultats nouveaux et leurs
sources/provenance sous results/engine/hardening-001.

## Robustesse et mémoire

Tester les frontières des trois imports, tous les emplacements de
coefficients non canoniques, des chiffrés canoniques altérés, données
arbitraires bien dimensionnées et longueurs invalides. Graines synthétiques
fixes pour reproductibilité. Aucun échec/panic ni secret de remplacement
divergent accepté. Un rejet attendu doit être établi par l'oracle ou par
l'impossibilité d'une réencapsulation canonique égale à l'entrée.

Écrire une campagne bornée de 20000 entrées de formats et 10000
décapsulations malveillantes dans plusieurs classes, plus échanges frais.
Ce test de mutations ne remplace pas 24 h de fuzzing à couverture guidée.
Employer les outils mémoire/portabilité déjà disponibles, ou une chaîne
locale si elle peut être installée sans modifier les systèmes globaux.
Toute indisponibilité doit être nommée ; aucune vérification non exécutée
ne doit être déclarée réussie.

## Diagnostic temporel préalable

Comparer sous une clé synthétique fixe les classes suivantes :
chiffré honnête, chiffré canonique dont le rejet est établi, chiffré à u
non canonique. Échauffement 100 décapsulations, 2000 observations par
classe, ordre mélangé par graine publique fixée avant mesure. Conserver
les durées brutes et l'ordre, calculer moyenne/variance et t de Welch pour
chaque paire. Signaler |t|≥4,5 comme signal à investiguer, sans l'appeler
preuve de fuite. Ne pas ajuster le seuil après résultat.

Un premier et un éventuel second passage après correction gardent leurs
données, y compris les signaux défavorables. Un diagnostic sans signal
n'établit pas le temps constant : faible taille, bruit OS/CPU, une clé,
classes limitées, bibliothèques et compilateur restent des limites.

## Livraison

Mettre à jour le rapport après les corrections puis après les campagnes.
Exécuter les contrôles courants et archiver les nouveaux résultats avec
versions, paramètres et empreintes. Fournir commandes et limites. Le
durcissement ne ferme pas la cryptanalyse J2, n'établit pas IND-CCA, ne
constitue pas un audit indépendant et n'autorise pas une présentation
comme composant de production validé.
