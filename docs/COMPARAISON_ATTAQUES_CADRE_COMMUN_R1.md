# Comparaison des attaques dans un cadre commun : R1 et ML-KEM-1024

**Extension du 26 octobre 2026 :** le [panneau M05](COMPARAISON_EXPERIMENTALE_M05.md)
ajoute 108 estimations pour six profils/problèmes, dont Aigis, Kyber
historique et KINDI, en séparant les observations comprimées et leurs
proxys. Il ne remplace pas les 30 paires historiques ci-dessous et ne
détermine aucun niveau global de sécurité.

25 octobre 2026. Cette étape répond au troisième travail prioritaire de
l'utilisateur. Elle consolide les calculs conservés, sans lancer de nouvelle
campagne d'estimation ni prolonger H13. Le programme
[`compare_attacks_common.py`](../research/compare_attacks_common.py) est
exécutable avec Python standard. Il vérifie les empreintes et les versions,
forme **30 paires strictes à partir de 60 estimations**, puis rattache **quatre
points du dual avec codes** aux diagnostics de score et de mémoire. Les
résultats de développement sont dans
`artifacts/generated/r1-common-attacks/final/` ; les données scientifiques
sources restent les instantanés versionnés run-002/008/009/016.

**Décision : conserver R1 pour le développement.** Dans les modèles appariés,
les coûts retournés pour R1 sont plus élevés que pour le témoin 1024.
Cette comparaison ne motive pas un changement immédiat de paramètres.
Elle ne permet pas d'attribuer un niveau global à R1 ou de le déclarer plus
sûr que ML-KEM-1024 : il manque notamment un coût validé du score réel du
dual, une comparaison des compromis mémoire et l'argument de sécurité du
KEM complet. Les travaux de moteur peuvent avancer avec ces limites
identifiées, sans attendre une nouvelle série de moments.

## 1. Objets comparés et contrat d'adversaire

| Propriété | Témoin ML-KEM-1024 | Candidat `KEM1536-DEV-Q7681-R1` |
|---|---:|---:|
| Degré de l'anneau | 256 | 256 |
| Rang du module | 4 | 6 |
| Dimension aplatie du secret | 1024 | 1536 |
| Module q | 3329 | 7681 |
| Secrets et erreurs de la clé publique | CBD(2) | CBD(3) |
| Budget `key` : coefficients publics disponibles | 1024 | 1536 |
| Budget `extended` : scénario séparé | 1280 | 1792 |
| Taille du message aléatoire d'encapsulation | 256 bits | 256 bits |

Les paramètres normalisés proviennent de
[FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) ; le
candidat est défini par sa [spécification R1](SPECIFICATION_DEV_Q7681_R1.md).
Le témoin des estimations est un problème mathématique : ce volet ne mesure
ni RustCrypto ni le backend PQClean du premier dépôt GitHub.

Le contrat partagé porte sur **une cible, une clé publique, aucun oracle de
fuite et aucune clé auxiliaire compromise**. Chaque attaque peut choisir un
sous-ensemble du budget disponible. La règle `key` donne à chaque scénario
toute sa clé publique : elle emploie le même type de ressources, avec des
nombres de coefficients différents parce que les rangs diffèrent. Ce n'est
pas une expérience à m=1024 fixé pour les deux candidats.

Le plongement d'un module dans un système LWE oublie la structure des lignes
circulantes. Il est donc conservé comme **heuristique LWE**, distinct du
panneau MLWE. Les 1536 coefficients ne créent pas 1536 rotations : le degré
de l'anneau est 256 dans les deux cas.

Le scénario `extended` n'est pas mélangé au scénario `key`. Il donne 256
échantillons supplémentaires au modèle ; leur disponibilité sous la loi LWE
appropriée à partir d'un chiffré réel n'a pas été démontrée. Les dépendances,
la compression et l'interaction avec la clé publique du chiffré demandent
leur propre analyse. Ce scénario n'est pas une attaque validée du KEM.

Les attaques par chiffrés choisis, erreurs, faute physique et fuite
d'implémentation sont hors du contrat numérique ci-dessous. Elles restent
des surfaces du moteur ; un bon chiffre LWE ne les élimine pas.

## 2. Versions, probabilités et unités : ce qui peut être apparié

| Panneau | Version exacte | Modèle de ressources | Portée du succès |
|---|---|---|---|
| run-002, communautaire | `malb/lattice-estimator@f31b86fe490ab11abb4a69efa13007583791e10a` | GSA pour les primaux ; mémoire exponentielle sans plafond | Convention propre à chaque algorithme |
| run-002, rotations primales | `TabOg/mlwe-hybrids@a92f335665eef69927d2d8f49832bd595a6dac32`, estimateur `6019056011d10d7e9c30a0d5da2d2f729fbc2eec` | Usage CBD dense exploratoire d'un code conçu surtout pour secrets creux | Amplification des suppositions du prototype, sans preuve pour le scénario réel |
| run-008/009, dual avec codes | `TabOg/CodedDualAttack@e2104ca50a293ed09b8fcec703cd2b143d21bee8` et sa dépendance de réduction embarquée | Code idéal GV, score normal, mémoire sans plafond | Sous-ensemble nul visé à 0,6 ; budget normal des faux candidats ≤0,05 |

Le consolidateur lie les deux manifestes amont à leurs empreintes dans les
provenances historiques. Il refuse les doublons, les versions différentes,
une cible ou un oracle différents, et les paires dont le modèle de coût ou
le budget d'échantillons diffère. Un nombre manquant n'est pas remplacé par
un résultat d'un autre modèle.

### Audit ciblé des conventions de succès

L'inspection du code exact f31b86f confirme un détail susceptible de fausser
une comparaison : dans
[`estimator/lwe.py`](https://github.com/malb/lattice-estimator/blob/f31b86fe490ab11abb4a69efa13007583791e10a/estimator/lwe.py),
`LWE.dual_hybrid` désigne **MATZOV**, et non la fonction distincte
`lwe_dual.dual_hybrid` munie d'un argument `success_probability=0.99`.

| Nom conservé | Convention réellement employée |
|---|---|
| `usvp` | Condition géométrique GSA ; pas de probabilité globale de succès explicitée dans le travail conservé |
| `bdd` / `bdd_hybrid` / `bdd_mitm_hybrid` | Amplification des suppositions vers 0,99 lorsque cette étape intervient ; géométrie et succès complet restent heuristiques |
| `dual` | Objectif du solveur de 0,99 sous les hypothèses de distribution et d'échantillonnage |
| `dual_hybrid` | Formule MATZOV de nombre de vecteurs avec un paramètre interne μ=0,5 ; ce paramètre n'est pas un certificat de récupération à 99 % |
| `bkw` | Objectif interne de distinction 0,99 ; amplification des échantillons, avec modification du bruit, conservée |
| `arora-gb` | Heuristique de degré de régularité ; aucun certificat de succès commun aux autres familles |
| dual avec codes | Objectifs 0,6 et 0,05 séparés ; la probabilité globale 0,55 n'est pas acquise en l'absence de justification des scores vrai/faux |

Il est légitime de comparer R1 au témoin **dans une même ligne**. Il serait
incorrect de transformer toutes ces lignes en attaques ayant un succès
commun certifié à 0,99, puis d'en prendre un minimum global.

Les logarithmes `rop` classiques sont des opérations modélisées par
l'estimateur, avec ses conventions finies. Les valeurs quantiques remplacent
le coût de réduction par une sensibilité asymptotique tout en conservant le
reste du calcul de l'estimateur : elles ne sont ni des cycles CPU ni un
nombre de portes physiques. La mémoire `mem`, le nombre de vecteurs `N`,
les octets et les qubits ne sont jamais assimilés.

## 3. Comparaisons appariées sur la clé publique

Les nombres sont `log2(rop)` ; la notation ne donne pas des bits de sécurité
du KEM. Tous les points ci-dessous ont le budget `key`, sans plafond mémoire.
Les sorties complètes, y compris les coordonnées d'optimisation et les
champs mémoire disponibles, se reconstruisent depuis run-002.

| Famille, calcul classique conservé | Témoin 1024 | R1 |
|---|---:|---:|
| uSVP | 275,104360 | 402,822557 |
| BDD | 270,723623 | 398,255919 |
| Hybride BDD | 270,749916 | 398,274016 |
| Hybride BDD avec rencontre au milieu | 495,907011 | 842,036625 |
| Dual simple | 288,525711 | 422,275993 |
| Dual hybride MATZOV | 262,335680 | 383,772563 |
| BKW avec amplification propre au modèle | 315,037405 | 468,828751 |
| Arora–GB, heuristique de régularité | 3455,354741 | 6624,138047 |

Les six premières lignes emploient le coût de réduction MATZOV. BKW et
Arora–GB ont leurs propres formules : le champ historique `MATZOV-classical`
de leurs travaux n'est pas passé à leur fonction comme modèle de réduction.

Les valeurs élevées des deux variantes hybrides ne signifient pas que cette
famille générale est moins efficace : il s'agit de points retournés par un
optimiseur et des options précises. On conserve aussi les résultats
défavorables et on ne les utilise pas comme bornes inférieures du coût
d'une attaque mieux optimisée.

| Famille, sensibilité quantique BCSS23 | Témoin 1024 | R1 |
|---|---:|---:|
| uSVP | 224,006200 | 340,110100 |
| BDD | 224,883734 | 341,119794 |
| Hybride BDD | 224,883734 | 341,119794 |
| Hybride BDD avec rencontre au milieu | 495,907011 | 842,036625 |
| Dual simple | 231,695200 | 350,362100 |
| Dual hybride MATZOV | 214,789480 | 325,958069 |

BCSS23 emploie la pente `0,2563 β` du crible à deux tuples. Les facteurs
sous-exponentiels, les ressources quantiques cohérentes, la profondeur et
la réalisation des portes ne sont pas comptés. Changer uniquement la pente
de réduction ne transforme pas le code de toutes les étapes en une attaque
quantique complète optimisée.
[Source primaire BCSS23](https://eprint.iacr.org/2022/676).

Les paires `extended` sont conservées séparément. Pour les six familles
utilisant la réduction, les chiffres retournés sont ici identiques aux
paires `key`. Cela constate que ces appels n'exploitent pas leur budget
supplémentaire pour retourner un meilleur coût ; cela ne valide pas les
échantillons d'un chiffré. BKW et Arora–GB changent avec ce budget : leurs
sorties restent dans le JSON intégral, sans promotion en attaque effective.

Les deux paires de rotations primales CBD denses retournent respectivement
270,749916 / 398,274016 et 491,922584 / 838,059718. Leur applicabilité reste
exploratoire ; elles ne remplacent pas le traitement MLWE du dual ci-dessous.
Le [travail sur les isométries de coefficients](https://eprint.iacr.org/2026/279)
justifie d'examiner cette structure, sans autoriser à soustraire son gain
annoncé sur Kyber à un autre profil ou à un autre estimateur.

## 4. Dual avec codes : temps, succès et mémoire réunis

Les minima locaux de run-009 ont été confrontés numériquement par une
seconde voie et sont stables dans les 32 voisins déclarés. Ils ne sont pas
des optimums globaux. Les quatre points partagent le même modèle idéal GV
et les mêmes objectifs internes 0,6 / 0,05.

| Scénario | Convention | m retenu | β0 / β1 | log2(rop) | log2(N) | log2(octets de liste empaquetée) |
|---|---|---:|---:|---:|---:|---:|
| Témoin 1024 | LWE | 790 | 807 / 788 | 258,459513 | 163,524775 | 174,817096 |
| Témoin 1024 | MLWE des auteurs | 797 | 801 / 783 | 256,968923 | 162,487181 | 173,784097 |
| R1 | LWE | 1236 | 1245 / 1205 | 381,711763 | 250,060093 | 262,096610 |
| R1 | MLWE des auteurs | 1230 | 1234 / 1195 | 378,984845 | 247,984906 | 260,016262 |

Le volume est recalculé indépendamment par
`ceil(dimension_réseau × ceil(log2(q)) / 8)` octets par vecteur :
2508, 2516, 4201 et 4186 octets respectivement. Il désigne **cette
représentation d'une liste matérialisée** ; il omet les auxiliaires du
crible, les index et l'espace de travail. Ce n'est pas une borne mémoire
universelle sur toutes les attaques.

Sous des sensibilités communes de `2^40`, `2^60` ou `2^80` octets, aucune de
ces quatre listes matérialisées ne tient. Aucun de ces budgets n'est adopté
comme règle du projet. Le programme conserve `bounded_memory_attack_cost =
null` : il ne retire pas la ligne pour annoncer artificiellement plus de
sécurité. Un attaquant pourrait choisir d'autres paramètres ou compromis
temps/mémoire ; ce coût doit être réoptimisé dans son modèle propre.

Deux limites sont asymétriques ou particulièrement sensibles :

- Les coefficients finis de réduction employés par les auteurs sont ajustés
  jusqu'à β=1024. **Les deux points R1 sont extrapolés** au-delà, contrairement
  aux deux points du témoin.
- Dans le diagnostic H09 à paramètres fixés, la hausse de variance normale
  qui fait atteindre le budget 0,05 est de 1,735222 % / 0,078078 % pour le
  témoin LWE/MLWE, et de 1,412782 % / 0,173146 % pour R1. Ces faibles tolérances
  ne sont pas des mesures de la variance réelle. Les seuls moments supposés
  donnent, par Cantelli et union, la borne plafonnée **1 dans les quatre cas**.

Ainsi, la queue rare et le score vrai ne sont pas certifiés par la petite
dimension, une moyenne empirique ou une kurtosis proche de la normale. Le
consolidateur conserve `score_corrected_attack_cost = null` : aucun facteur
issu des décodeurs concrets ou de H10–H13 n'est soustrait au coût idéal.
Les [diagnostics H09](TRANSFERT_SCORE_Q7681.md) et le
[bilan H13](BORNES_N32_ET_MOTEUR.md) restent les références de portée.

Les travaux primaires récents sur
[les covariances de score](https://eprint.iacr.org/2026/1048) et
[une analyse prouvable du dual FFT](https://eprint.iacr.org/2026/2166)
ont été revérifiés sur leurs notices le 25 octobre 2026. Ils motivent cette
séparation. Leurs coûts ne sont pas calculés pour R1 dans cette étape ;
une amélioration relative à leur référence ne se retranche pas à MATZOV.

## 5. Plafond générique commun et questions non chiffrées

Le rang accru ne change pas la taille du message aléatoire d'encapsulation :
256 bits. Pour les deux constructions, un attaquant peut essayer des messages
candidats, reconstruire l'encapsulation déterministe à partir de la clé
publique et comparer le chiffré au défi public. Le message correspondant
permet de retrouver le secret partagé honnête.

Dans le modèle de recherche idéal, cela donne une attaque générique
d'exposant 256 en classique et 128 en requêtes quantiques cohérentes, avant
les coûts de circuit et les facteurs constants. **Ce sont des plafonds
génériques de recherche, pas des niveaux de sécurité prouvés**, ni des
catégories NIST, ni des budgets de portes physiques. Le modèle quantique
requiert une réalisation réversible cohérente de la vérification. Les
versions multi-cibles et les pertes de réduction ne sont pas quantifiées
par ce tableau. Une grande marge LWE peut être utile ; elle ne transforme
pas 1536 coefficients en 1536 bits de sécurité globale.

Les voies suivantes restent explicitement non chiffrées pour R1 :

| Voie | État permettant la décision |
|---|---|
| IND-CCA et comportement de rejet | À traiter pour la construction R1 exacte ; aucun coût LWE ci-dessus ne remplace ce travail |
| Oracle d'échec, temps, fautes et encodages | Aucun oracle accordé dans la comparaison ; à vérifier sur les binaires et API distribués |
| Dual quantique QRS | [Notice primaire](https://eprint.iacr.org/2026/979) vérifiée ; accès cohérent et référence de coût propres, pas d'exécution R1 |
| Crible quantique à trois tuples | Régime de mémoire distinct du modèle BCSS23 ; pas de remplacement isolé de pente |
| Fast Slicer, analyses récentes hors version figée, prépublications du 20 octobre | Pas de chiffre R1 intégré tant que leur hypothèse, leur réussite et leur comptage ne sont pas rapprochés du contrat |

La [veille](VEILLE_ATTAQUES_2026.md) conserve les références et les limites
d'accès. Cette consolidation n'est pas présentée comme une revue exhaustive
des publications parues après le gel de l'estimateur. Les baisses annoncées
sur d'autres paramètres ne servent pas de correctif forfaitaire.

## 6. Reproduction, contrôles et décision de développement

Depuis la racine NIST, avec Python 3.11 ou ultérieur :

```powershell
.\.tools\research-venv\Scripts\python.exe research/compare_attacks_common.py --output artifacts/generated/r1-common-attacks-nouveau
.\.tools\research-venv\Scripts\python.exe research/compare_attacks_common.py --verify artifacts/generated/r1-common-attacks-nouveau
.\.tools\research-venv\Scripts\python.exe -m unittest discover -s research -p test_compare_attacks_common.py -v
```

Sous Linux, remplacer le chemin Python par `python3` ou le runtime local.
Le dossier de sortie doit être nouveau ; le programme ne remplace aucun
instantané. Il n'importe pas Sage, ne lance aucun processus WSL, n'exécute
aucun code amont et ne touche pas au fuzzing.

Les cinq tests ciblés empêchent une soustraction entre classique et
quantique, la substitution d'un budget/cible/oracle, le choix silencieux
d'un doublon meilleur, la confusion octets/vecteurs et le rattachement d'un
diagnostic à d'autres paramètres. Le contrôle des sorties recalcule les
30 paires et les quatre volumes mémoire depuis les données figées. Les
vérificateurs historiques restent nécessaires pour rejouer les modèles
numériques et leurs contre-vérifications ; ce nouveau programme n'est pas
une seconde implémentation d'un estimateur.

La première sortie locale a été conservée avec son consolidateur avant
l'ajout du contrôle explicite des manifestes. La sortie `final/` est celle
à utiliser. Les empreintes des fichiers sources figés, du consolidateur
normalisé LF et du résultat sont conservées dans sa provenance.

L'étape apporte une **comparaison exploitable à contrats déclarés**. Elle
permet de poursuivre le durcissement et l'optimisation de R1, de garder la
référence 1024 comme témoin et d'écarter une revendication numérique globale
prématurée. Les trois verrous qui changeraient cette dernière décision sont
précis : un argument IND-CCA pour R1, un lien contrôlé entre le certificat
de correction et le programme, et des attaques réestimées avec réussite,
queues et ressources effectivement justifiées. La prolongation automatique
des petites listes ou des moments n'est pas requise pour améliorer le moteur.
