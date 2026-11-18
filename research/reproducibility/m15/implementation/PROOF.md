# Conformité arithmétique — obligations universelles et certificat NTT

Lot M15 sélectionné pour le rejeu reproductible sous Windows x64. Les sources
du moteur restent inchangées. Le présent volet ajoute des résultats sur des
composants précis ; ce n'est pas une preuve de conformité intégrale du KEM,
de sa compilation ou de son effacement. Les instructions de rejeu et le
statut du lot figurent dans [README.md](README.md).

## 1. Traduction des corps source

`source_model.py` lit les corps effectifs de reduce_once, quotient, product,
reduce_wide, compress et decompress, ainsi que leurs constantes. Il refuse
toute syntaxe hors du sous-ensemble accepté. Les instructions let sont
traduites dans l'ordre ; les fonctions appelées sont développées depuis
les mêmes sources. Les types des paramètres et des résultats sont contrôlés,
ainsi que l'égalité des deux constantes Q et les imports des fonctions
arithmétiques dans le module de compression.

Un u_w est représenté par un entier dans [0,2^w). Un cast unsigned calcule
le résidu modulo2^w ; wrapping_add/sub aussi. Une conversion from est un
élargissement vérifié. Les décalages droits sont les quotients entiers
positifs par une puissance de2, les gauches conservent leurs bits bas.
Chaque décalage doit être strictement inférieur à la largeur. Chaque
opération ordinaire +,-,* produit une obligation d'absence de dépassement.
Chaque division a un diviseur strictement positif. Le masque bas de compress
est interprété comme un résidu modulo sa puissance de2.

Les littéraux décalés non suffixés ne sont acceptés ici que dans les corps
de compression reconnus, où leur contexte est u32. usize est64 sur l'ABI
Windows x64 capturée. Il ne s'agit pas d'un parseur Rust complet, d'une
traduction MIR, ni d'une preuve formelle du compilateur. La fidélité de ce
petit traducteur est une partie déclarée de la base de confiance et fait
l'objet d'une revue interne et de mutations sémantiques.

Pour chaque précondition P et propriété C, le programme soumet P et non C
au solveur. UNSAT établit la clôture universelle P implique C dans cette
sémantique. Les préconditions sont elles-mêmes testées SAT ; aucune preuve
vacuement vraie n'est créditée. La propriété C comprend l'absence de tous
les dépassements non enveloppants, donc l'écart debug/release n'est pas
ignoré dans le domaine traité.

## 2. Contrats acquis

Les31 obligations couvrent :

- reduce_once : chaque entier32bits inférieur à2q retourne x moduloq,
  dans l'intervalle canonique ;
- quotient : tous les entiers32bits retournent floor(x/q) ;
- reduce_wide : tous les entiers64bits retournent x moduloq ; cette
  fonction est réservée aux tests/vecteurs de recherche dans le moteur ;
- product : toutes les paires de coefficients canoniques donnent le
  produit moduloq et restent canoniques ;
- compress/decompress : pour chacun des13 largeurs1..13, tous les
  coefficients du domaine possèdent exactement l'arrondi et la réduction
  de la spécification, et leur résultat respecte son domaine.

Le produit se prouve par composition explicite : pour a,b canoniques,
0<=a*b<=(q-1)^2 est établi. Le terme a*b est ensuite remplacé dans le corps
traduit de product par un x arbitraire dans cet intervalle ; aucune variable
originale ne peut subsister. Le solveur démontre la réduction entière pour
tout cet intervalle, plus grand que l'ensemble des produits réalisables.
La substitution n'est donc pas une hypothèse de multiplication correcte.

Les SMT-LIB, les preuves émises par Z3, les durées, les empreintes du
traducteur et les identités du solveur restent dans `acquisition-005/`.
Le rejeu reconstitue les obligations depuis les sources, compare leurs AST
typés aux assertions SMT capturées et refait UNSAT. Les noms locaux générés
par le sérialiseur ne sont pas considérés comme une divergence sémantique ;
les octets originaux sont toujours vérifiés par leur empreinte.
Les objets de preuve ne sont pas vérifiés par un second noyau indépendant :
Z3 et le traducteur restreint sont des dépendances de confiance déclarées.
Une absence d'erreur ou un timeout ne compte jamais comme UNSAT.

## 3. Certificat algébrique NTT, pour tout polynôme

Le module `ntt_certificate.py` contrôle un gabarit source exact pour le
réseau public transform, la construction des tables et les trois méthodes
forward_into, inverse_into et multiply_add_assign. Le gabarit complet refuse
une instruction supplémentaire ou modifiée ; les commentaires/espaces sont
sans effet. La correspondance de ce gabarit à son interprétation demeure
une liaison de traduction relue en interne, distincte des preuves SMT des
corps simples.

Chaque sortie du réseau est représentée par son vecteur de256 coefficients
formels sur F_q. Chaque papillon met à jour deux vecteurs par addition et
multiplication par une constante publique. Par induction sur les opérations,
ils désignent la fonction linéaire du réseau sur **toutes** les entrées.
La conservation du domaine canonique découle des contrats arithmétiques :
les sommes/différences corrigées restent dans [0,2q), les produits dans
[0,(q-1)^2]. Les indices du réseau sont publics et bornés par ses boucles.

Le vérificateur établit q premier, les ordres exacts des racines et les
inverses publics. Il compare les131072 coefficients formels des matrices
avant/arrière aux formules :

    F[k,j] = psi^j * omega^(k*j)
    G[j,k] = n^-1 * psi^(-j) * omega^(-k*j)

Les256 sommes d'orthogonalité sont n pour la classe0 et0 ailleurs.
Donc (GF)[i,j] = n^-1*psi^(j-i)*sum_k omega^(k*(j-i)) est delta_i,j.
Ceci démontre l'inversion pour tout vecteur, pas seulement pour une liste
de polynômes d'essai. Enfin chaque r_k=psi*omega^k satisfait r_k^n=-1.
L'évaluation en r_k est donc un morphisme de F_q[X]/(X^n+1). Combinée à
l'inversion, la multiplication point à point suivie de l'inverse réalise
le produit négacyclique pour tous les polynômes canoniques. L'accumulation
préserve cette égalité par linéarité, sans dépendre du nombre de termes.

Ce résultat algébrique a une partie de preuve mathématique générale et une
partie de certificat fini complet sur le réseau fixe. Il ne doit pas être
présenté comme une preuve machine de toute la sémantique Rust/LLVM, ni comme
une inférence de généralité depuis des essais aléatoires. L'identité de
std::hint::black_box sur sa valeur est utilisée ; aucune propriété temporelle
ou d'effacement n'en est déduite.

## 4. Portée de décision

Les mutants portant sur un bit de correction, la réciproque et l'arrondi
admettent des contre-exemples ; les changements de syntaxe hors sous-ensemble
et de gabarit NTT sont refusés. Les préconditions sont nécessaires et ne sont
pas étendues silencieusement aux entrées invalides. Il n'est déduit aucune
faille de production de ces variantes synthétiques de test.

Aucune correction du code actuel n'est requise par les obligations acquises.
Le choix de conserver R1 est distinct d'un gel final des paramètres. Les
parseurs complets, toute la sérialisation, le contrat d'aléa, l'ensemble PKE/KEM,
les dépendances, l'ABI et la compilation ne sont pas formellement prouvés ici.
Le volet renforce la liaison au programme ; C01 reste une obligation de
sécurité cryptographique distincte.

Le lot retient `acquisition-005/` et `ntt-certificate-002.json`. Les notes de
révision conservées décrivent aussi des acquisitions antérieures ; leurs
fichiers et journaux historiques restent conservés ailleurs et ne sont pas
nécessaires au rejeu de cette sélection. Le solveur et ses attributions sont
documentés dans [THIRD_PARTY.md](THIRD_PARTY.md).
