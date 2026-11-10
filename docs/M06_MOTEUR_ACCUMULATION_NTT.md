# M06 — moteur à produits scalaires accumulés dans la NTT

10 novembre 2026. Le point de départ est le commit local
`693c6a305b5143b9b00b912353bbae153cad4e4f`. Le jalon développe le moteur
`KEM1536-DEV-Q7681-R1` sans modifier ses paramètres, sa sérialisation ou
ses domaines de hachage. Le [protocole](PROTOCOLE_M06_MOTEUR.md) distingue
les mesures, les contrôles de correction et l'argument de sécurité.

## Changement du moteur

Les coefficients et leurs transformées sont portés par deux types
distincts, propriétaires de tableaux fixes `Zeroizing`. KeyGen transforme
les six polynômes secrets une fois. Le chiffrement fait de même pour les
six polynômes d'aléa. Les six produits d'une ligne sont accumulés dans le
domaine NTT, puis une seule inverse écrit dans la destination détenue.
Le déchiffrement accumule aussi son produit scalaire avant soustraction.

Chaque produit est canonique et chaque addition est réduite ; la somme
intermédiaire est au plus 15360, strictement inférieure à 2q=15362. Les
anciens produits isolés restent uniquement sous `cfg(test)`. Les trois
nouvelles méthodes et `transform` sont préservés comme sites de revue
machine. Aucun cache secret persistant, SIMD ou bloc `unsafe` n'est ajouté.

| Opération | Transformations antérieures | Transformations M06 |
|---|---:|---:|
| KeyGen | 108 | 48 |
| Encaps | 126 | 55 |
| Decaps, réencapsulation incluse | 144 | 68 |

Un compteur local au thread, absent de la production, vérifie ces nombres.
Le cas de rejet non canonique du test exige également 68 transformations
et retrouve exactement le fallback attendu. Ce compte n'est pas une
preuve d'égalité temporelle de tous les chiffrés.

## Correction et programme

Les produits scalaires de six termes sont confrontés à la convolution
générique indépendante dans vingt familles. Les tests traitent les signes
négacycliques, les bords canoniques, une accumulation traversant q, la
réutilisation après clear et la conservation de la source de l'inverse.

Les exécutables de recherche Windows et Linux retrouvent l'ensemble des
sorties figées M01/M02 : 1000 vecteurs, 10000 rejets, 10000 mutations et
20000 entrées de format par système. Il s'agit d'un rejeu intégral des
octets de référence déjà confrontés à Python, sans nouvelle mesure
empirique d'un taux rare de décapsulation.

Le [pont certificat/programme](LIEN_CERTIFICAT_PROGRAMME_R1.md) est adapté
à la réalisation M06. Le premier contrôle global a correctement refusé
les anciens repères M04. La contre-revue a ensuite identifié une ancre
globale trop faible entre deux sites d'addition ; chacun est désormais
couvert séparément avec son inverse. Les tests mutants ciblent chaque
site. Le certificat rationnel run-004 et ses quantificateurs sont inchangés.
Les contrôles textuels complètent les tests et la revue, sans constituer
une preuve sémantique Rust ou une vérification du compilateur.

## Mesures et coût mémoire

Les [mesures comparatives](M06_MESURES_ET_DURCISSEMENT.md) conservent
60000 observations, cinq séries alternées et tous les extrêmes. Sur la
machine enregistrée, les rapports de médianes référence/M06 sont
1,79 pour KeyGen, 1,87 pour Encaps et 1,76 pour Decaps.

Deux processus RSS distincts donnent 2048 KiB chacun. Les frames LLVM
statiques augmentent : KeyGen 7352→11464 octets, PKE Encrypt 11320→12872,
Decaps 7560→9096. Ce coût est une contrepartie de la réutilisation locale.
Il ne donne pas à lui seul un pic dynamique de pile et ne doit pas être
masqué par le résultat RSS commun.

Un diagnostic temporel séparé conserve 16000 observations par système,
8 clés fraîches, 5 classes et 400 observations par cellule. Les maxima
|t| sont 1,559 sous Windows et 1,658 sous Linux, sans franchissement du
seuil 4,5. Aucune observation n'est retirée. Le panneau n'a ni contrôle
de multiplicité ni garantie de puissance contre toutes les fuites ; il
ne démontre pas le temps constant. Mesures comparatives et temporelles
précèdent les builds lourds et le fuzzing des contrôleurs de cette passe.
L'activité générale de l'hôte et sa fréquence ne sont pas isolées.

## Binaires et reconstruction

Les quatre binaires de recherche/livraison Windows/Linux sont désassemblés
intégralement. Les inventaires distinguent tout le code, le filtre lexical
du cœur et sa fermeture d'appels directs. Dans les builds de recherche,
un nom LLVM manglé de PKE Encrypt échappe au filtre lexical ; la fermeture
et la revue ciblée le prennent bien en compte.

La [contre-revue M06](M06_REVUE_INDEPENDANTE.md) vérifie les quatre helpers
sans division, la copie inverse de 512 octets vers le propriétaire et huit
emplacements ciblés des nouveaux buffers. Les effacements sont cherchés
dans les appelants détenant ces buffers. Les registres, copies, spills,
unwind, chemins exceptionnels et bibliothèques système ne reçoivent pas
de preuve globale. Les anciens constats de M04 ne sont pas transférés.

Une première capture de sources omettait les données publiques incluses
par le témoin 1024. Une deuxième capture, faite **avant de nouveaux builds**,
inclut les littéraux Rust include_str/include_bytes, dont les six JSON
ACVP et leur manifeste. Les cibles de compilation sont séparées, les
sources communes identiques, les verrous et les versions conservés.

Les trois exécutables Linux des deux builds sont identiques en octets.
Les trois Windows ne diffèrent que dans deux champs de l'en-tête PE :
l'horodatage COFF, offset 136, et le checksum, offset 216, quatre octets
chacun. Un contrôle masque **uniquement ces champs dans une copie de
comparaison**. Il refuse un changement de code ou de données ailleurs.
Les binaires bruts sont conservés et ne sont jamais réécrits pour obtenir
une égalité artificielle. Ces builds d'un même hôte ne sont pas une
reproduction indépendante par un tiers. Les sources des dépendances et
la chaîne complète restent à récupérer selon les verrous et prérequis.

`results/engine/m06-001` conserve sources, reçus des deux builds, binaires,
désassemblages, revues NTT, régressions, diagnostic et pont certificat.
Le vérificateur recalcule les inventaires du **désassemblage archivé** ;
ce rejeu ne lance pas un nouveau désassemblage et ne prouve pas un CFG
indirect complet.

```powershell
.\.tools\research-venv\Scripts\python.exe -B research/verify_m06.py
.\.tools\research-venv\Scripts\python.exe -B research/run_m06_measurements.py verify --output results/engine/m06-measurements-001
.\.tools\research-venv\Scripts\python.exe -B research/rejection_security_m06.py --verify results/security/m06-rejection-001
```

## Rejet implicite et limites de sécurité

Le [volet J](REJET_IMPLICITE_R1_M06.md), figé et contre-relu séparément,
borne le secret préfixe idéal : ε_J≤min(1,q/2^256) en ROM et
ε_J≤min(1,2q/2^128) en QROM pour D>0 ; l'écart est nul pour D=0.
z doit être uniforme et indépendant, l'interface indexée classique et
les ressources de la réduction correctement comptées. La constante 2
est rattachée au théorème O2H primaire et à la correction SXY2021.

À q=D=2^64, les majorants sont 2^-192 et 2^-63. Le second ne certifie
pas l'allocation illustrative M05 2^-130. Il mesure la force limitée de
cette réduction, sans démontrer une attaque atteignant cette valeur.
Le gain de vitesse du moteur n'augmente pas un nombre de bits de sécurité.
Le PKE à graines, les primitives Keccak concrètes, l'argument IND-CCA
complet, la revue externe et C01 restent ouverts.

Les campagnes instrumentées M06 et leurs reçus sont détaillés dans la
note de mesures ; leurs secondes CPU et leur couverture sont propres à
ce code. Aucun budget historique n'est ajouté à celui de M06. Les paquets
M04 restent historiques et ne livrent pas les nouveaux exécutables. Les
modifications de cette passe restent locales, sans push implicite.

Le reçu final d'intégration est dans
`results/engine/m06-verification-001` : sept contrôles réussis, 154 tests
Python Windows et 25 tests M06 ciblés Linux, avec reçus Rust/Clippy/fmt et
auto-test du binaire habituel. Le check global antérieur réussi à 144
tests et son échec initial sur les repères périmés restent conservés.
Les ajouts ultérieurs sont couverts par les contrôles finaux ; aucun
nouveau check intégral Linux n'est présumé.
