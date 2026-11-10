# M05 — Bornes conditionnelles de sécurité pour R1

26 octobre 2026. Ce travail prolonge
[l'argument R1](ARGUMENT_SECURITE_R1.md) par un couplage des bruits expansés,
un comptage explicite des requêtes et des majorants calculables ROM/QROM.
Le moteur R1 et ses formats restent inchangés.

Les résultats nouveaux sont les suivants :

1. Dans le modèle d'oracles indépendants, le certificat de correction se
   transfère aux bruits **expansés par une graine de 256 bits**, en moyenne
   sur les oracles et les clés, pour le pire message. La collision entre
   graine de clé et graine de chiffrement est traitée exactement.
2. Le budget ROM compte les deux coordonnées de G512 ainsi que les appels
   implicites de l'encapsulation et de la décapsulation. La formule
   conserve un avantage CPA propre au PKE à graines comme inconnue.
3. Le théorème 22 de Ge–Yang–Yu–Yu permet un majorant QROM conditionnel
   pour la **transformation implicite utilisée par R1**. Il laisse un
   avantage OW du PKE et un avantage de PRF de rejet à établir.
4. Un calculateur rationnel déduit les exigences exactes sur ces inconnues
   pour une cible donnée. Les tests comprennent une énumération exhaustive
   des tables d'un petit oracle et les lois CBD concernées.

Il s'agit d'un résultat dans des modèles idéalisés, avec des obligations
quantifiées. Aucune borne complète sur les fonctions Keccak concrètes ni
fermeture du critère C01 n'en est déduite.

## 1. Construction, adversaire et conventions

Le profil est `KEM1536-DEV-Q7681-R1`, dans
`Z_7681[X]/(X^256+1)`, de rang 6. Les secrets et erreurs utilisent CBD(3),
u est exact et v est compressé sur 5 bits. Le message et le secret partagé
ont chacun 256 bits. Posons `M=2^256` pour la taille de l'espace message.

Le jeu considéré est mono-utilisateur, avec une clé produite honnêtement,
un défi et des requêtes classiques de décapsulation différentes de la
chaîne défi. Le QROM autorise des requêtes quantiques aux fonctions
publiques. L'import de clés arbitraires, les fautes et les fuites physiques
relèvent d'autres contrats. La comparaison complète avec la réencapsulation
donne la rigidité du PKE dérandomisé exigée par la transformation.

Les conventions d'avantage sont fixées pour éviter de confondre :

- `ε_CPA` et `Adv_CCA` : biais absolu `|Pr[gagner]−1/2|`, au plus 1/2 ;
- `ε_OW` : probabilité de retrouver le message défi, au plus 1 ;
- `ε_J` : écart de probabilités distinguant la PRF de rejet d'une fonction
  aléatoire, au plus 1. Si une référence définit la PRF par un biais de
  devinette, ce dernier doit être doublé pour majorer cet écart.

Les oracles de base sont regroupés sous Ψ : génération KG, bruit N,
matrice A et hachage de clé publique H. Les domaines sont ceux de la
[spécification](SPECIFICATION_DEV_Q7681_R1.md). L'oracle de dérivation G512
fournit deux coordonnées indépendantes idéales, F pour les coins et K
pour la clé. Le rejet est `f_z(c)=J(z,c)`, avec z uniforme indépendant.

Les domaines disjoints permettent une décomposition de l'oracle idéal.
L'implémentation Keccak n'est pas remplacée ici par une fonction
statistiquement indépendante démontrée. Une requête en superposition sur
plusieurs domaines n'est pas traitée gratuitement : sa simulation est
explicitée au §4.

## 2. Transfert du certificat aux bruits expansés dans le modèle RO

Le certificat rationnel de
[run-004](../results/j2/run-004/correctness-certificate.json) borne

`Pr[∃i : |(eᵀr−sᵀe1+e2)_i|≥1800] ≤ δ_cert`.

Il suppose les lois CBD idéales indépendantes pour les tirages distincts.
Sa valeur exacte est une fraction ; son affichage logarithmique recalculé
est environ **−310,08596919854**. Le décodeur et la compression sont reliés
à ce seuil dans [le rattachement au programme](LIEN_CERTIFICAT_PROGRAMME_R1.md).

Fixons une réalisation Ψ des oracles et une clé honnête κ, issue de la
graine de bruit σ. Le chiffrement de base tire un rseed uniforme, puis
évalue N sur les nonces 0..12. Pour cette clé et cet oracle fixés, posons

`β(κ,Ψ)=Pr_rseed[∃i : |B_i|≥1800]`, avec `B=eᵀr−sᵀe1+e2`.

L'enveloppe de quantification est déterministe, dans `[-120,120]`, et
l'implication d'échec vaut pour chaque message. On a donc, point par point,

`max_m Pr_rseed[Dec(Enc(m;rseed))≠m | κ,Ψ] ≤ β(κ,Ψ)`.

Prenons ensuite l'espérance sur Ψ et les clés. KG et N ont des domaines
indépendants dans le modèle ; la valeur σ peut être non uniformément
distribuée pour un KG fixé, sans invalider la suite. rseed est frais et
uniforme, donc `Pr[rseed=σ]=1/M`.

- Si `rseed≠σ`, les douze adresses N de génération et les treize adresses
  N de chiffrement sont distinctes. En moyenne sur l'oracle N, leurs bits
  sont indépendants et uniformes : le certificat CBD s'applique.
- Si `rseed=σ`, les mêmes nonces donnent **r=s et e1=e**. Les produits
  s'annulent dans l'anneau commutatif : `B=e2`. Chaque coefficient de e2
  est entre −3 et 3, très loin du seuil 1800. Ce cas ne contribue pas à
  l'événement d'échec majoré.

On obtient le raffinement suivant :

`δ_RO := E_Ψ E_κ[max_m Pr_rseed[échec | κ,Ψ,m]]`

`δ_RO ≤ (1−1/M) δ_cert ≤ δ_cert`.

Cette borne porte sur la moyenne des oracles et des clés du pire message.
Elle ne dit pas que `δ_Ψ≤δ_cert` pour chaque oracle fixé, ni que chaque clé
possède cette borne. La collision σ=rseed est bénigne pour cette
correction ; sa révélation peut néanmoins dévoiler le secret dans un jeu
de confidentialité. Cet aspect reste inclus dans l'avantage du PKE.

La dérivation KEM des coins à partir du message donne à l'adversaire une
possibilité de recherche. Les facteurs de requêtes des transformations
suivantes traitent cette recherche ; le seul taux honnête n'y suffit pas.

## 3. ROM : budget et majorant conservateur

Notons g le nombre de requêtes publiques SHA3-512 de l'adversaire et j un
majorant de ses requêtes publiques SHAKE256. Ces budgets peuvent compter
tous les domaines, ce qui majore ceux de G et de J qui sont pertinents.
Notons D le nombre de décapsulations classiques. Une encapsulation défi
effectue un appel G512 ; chaque décapsulation effectue G512 et J, y compris
pour les sorties non sélectionnées.

Les deux coordonnées de G512 doivent être comptées séparément :

`Q_F = g+D+1`, `Q_(K,J)=g+j+2D+1`,

`Q_RO = 2g+j+3D+2`.

HHK adopte explicitement une convention incluant les appels implicites de
l'expérience (§2.1–2.2, p.8–9 de la version 2017). Le tableau global ROM
du §3.3, p.21, donne pour la variante implicite à clé issue du message un
terme `(2Q_RO+D)δ` et un terme `3Q_RO/M`. Son erratum de 2021 ajoute la
rigidité et corrige les comptes individuels ; il indique que les résultats
globaux ROM de ce tableau sont préservés.
[Texte primaire HHK](https://people.inf.ethz.ch/dhofheinz/pdf/conf/tcc/HofheinzHK17.pdf),
[erratum primaire](https://eprint.iacr.org/2017/604.pdf).

### Convention CPA : prudence sur une incohérence locale

Le tableau imprime un coefficient 3 devant l'avantage CPA. Toutefois, le
lemme 2.3 du texte 2017, repris au lemme 1.1.6 de la thèse, affiche la
conversion OW≤CPA+1/M avec une définition CPA en biais. Cette conversion
locale nécessite une vérification : pour le chiffrement transparent c=m,
OW vaut 1 et le biais CPA maximal vaut 1/2. La conversion standard donne
`OW≤2*CPA_bias+1/M`. L'autre terme de jeu du théorème 3.2 porte lui aussi
un facteur 2 sur le biais ; réparer cette conversion dans ce raisonnement
donne un coefficient 4 plutôt que 3.

Nous retenons une marge conservatrice supplémentaire, **6ε_CPA**, qui
couvre cette réparation et la lecture du coefficient 3 avec un avantage
CPA normalisé à deux fois le biais. Le calculateur n'attribue pas ce
coefficient 6 à HHK. Ce diagnostic local et le contrôle final des constantes
restent documentés ; le résultat global publié n'est pas déclaré réfuté.
La [thèse référencée par l'erratum](https://doi.org/10.13154/294-7758) a été
récupérée intégralement et ses sections pertinentes ont été relues.

Le majorant conditionnel évalué est ainsi

**`Adv_CCA_ROM ≤ min(1/2, 6ε_CPA + (2Q_RO+D)δ_RO + 3Q_RO/M)`**.

Ici ε_CPA concerne le **PKE à graines**, avec ses oracles publics
auxiliaires et les ressources de la réduction. Pour chaque Ψ fixé, on
applique la structure de la transformation à ce PKE auxiliaire ; la borne
est ensuite moyennée sur Ψ. Le terme de correction étant linéaire, le
raffinement du §2 peut y être substitué. Les appels publics à N/KG/A/H et
le travail de leur simulation restent dans ε_CPA et le temps de réduction.

L'argument à deux hybrides `MLWE_(6,6)` puis `MLWE_(7,6)` existe pour le
PKE à bruits frais et matrice uniforme entière. Le remplacement par la
matrice à graine publique et par les bruits expansés doit encore relier
son coût à ε_CPA. Notre calculateur ne fait pas cette substitution
automatiquement, ni celle d'un coût BKZ par une probabilité d'avantage.

Pour une cible de biais τ, l'exigence suffisante sur ε_CPA vaut exactement

`ε_CPA ≤ [τ − (2Q_RO+D)δ_RO − 3Q_RO/M]/6`,

si le numérateur est positif ou nul. Sinon cette borne ne certifie pas la
cible, même en mettant son terme CPA à zéro ; cela ne démontre pas une
attaque qui atteint ce biais.

## 4. QROM : théorème implicite applicable et coût des domaines

La figure 7 de Ge–Yang–Yu–Yu est la transformation implicite avec
`c=Enc(pk,m;F(m))`, `K=G(m)` et rejet `f_z(c)`. Le **théorème 22**, p.96,
porte directement sur cette transformation à correction au pire cas ; il
n'est pas réservé à FOAC. Il fournit

`Adv_CCA ≤ ε_J + 2(Q_F+Q_K)√ε_OW + 16(Q_F+1)^2 δ_wc`.

Les décapsulations sont classiques. L'adversaire de PRF reçoit au plus D
requêtes à la fonction secrètement indexée. La remarque 6, p.97, explique
le terme de correction quadratique utilisé ici. Les figures ACWC et les
théorèmes 21/23 de ce même article concernent des constructions différentes
et ne sont pas appliqués à R1.
[Source primaire GYY, ePrint 2025/1641](https://eprint.iacr.org/2025/1641).

Fixons `h0=H(ek)` pour la clé honnête. Une requête G512 peut être en
superposition sur des contextes h différents. Pour la simuler sans
supposer un accès contrôlé gratuit, on calcule réversiblement le drapeau
public `h=h0`, calcule F dans un temporaire, effectue le XOR contrôlé puis
désévalue le temporaire. Cela coûte au plus **deux requêtes F** ; la même
construction utilise deux requêtes K. Un oracle auxiliaire indépendant
traite le reste du domaine. h0 dépend des oracles de base et de la clé,
sans dépendre de F/K, ce qui préserve la distribution de leur restriction.

Les appels internes, dont le contexte est connu, nécessitent une seule
requête à chaque coordonnée. Le budget conservateur évalué devient

`Q_F^Q = Q_K^Q = 2g+D+1`.

Cette simulation compte aussi le cas où g majore des requêtes globales
SHA3-512 en superposition entre KG et G. Les appels supplémentaires aux
oracles auxiliaires ont un coût et restent dans les ressources des jeux.

Après fixation puis moyenne des oracles de base, la concavité de la racine
donne `E[√ε_OW,Ψ]≤√E[ε_OW,Ψ]`. On obtient le majorant conditionnel

**`Adv_CCA_QROM ≤ min(1/2, ε_J + 2(Q_F^Q+Q_K^Q)√ε_OW + 16(Q_F^Q+1)^2δ_RO)`**.

Deux inconnues importantes subsistent :

- ε_OW est une **probabilité de récupération du message** du PKE à
  graines avec accès quantique aux oracles auxiliaires. Elle n'est ni le
  biais CPA, ni une puissance de deux obtenue en inversant un coût réseau.
- ε_J est la sécurité de `J(z,c)` contre un adversaire quantique qui a des
  accès classiques à la fonction indexée par z, **et** des accès quantiques
  à SHAKE public, y compris ses domaines N/J. La séparation des domaines
  ne permet pas de lui attribuer la valeur zéro. Une sécurité de PRF
  seulement classique ne répondrait pas à ce jeu.

Si l'on réserve un budget p pour ε_J et note
`L=τ−p−16(Q_F^Q+1)^2δ_RO`, l'obligation suffisante est

`ε_J≤p` et `ε_OW≤[L/(2(Q_F^Q+Q_K^Q))]^2`, pour `L≥0`.

Le calcul est rationnel exact. Pour l'évaluation d'une racine générale,
le programme emploie un intervalle dyadique justifié par des inégalités
entières, plutôt qu'un arrondi flottant supposé majorant.

## 5. Valeurs connues et lecture correcte des exigences

La table donne les logarithmes en base deux des **composantes connues**,
en posant `g=j=D=2^b`. Les valeurs affichées sont arrondies ; les
comparaisons et obligations du calculateur utilisent les fractions exactes.

| b | Correction ROM | Devinette message ROM | Correction QROM, avec dispatch cohérent |
|---:|---:|---:|---:|
| 16 | −290,385523 | −235,830068 | −270,916015 |
| 32 | −274,385529 | −219,830075 | −238,916044 |
| 64 | −242,385529 | −187,830075 | −174,916044 |
| 96 | −210,385529 | −155,830075 | −110,916044 |
| 128 | −178,385529 | −123,830075 | −46,916044 |

Ces lignes ne fixent pas les avantages CPA, OW ou PRF. Pour illustrer
l'inversion, avec `g=j=D=2^64`, une cible `τ=2^-128` et une allocation PRF
`p=2^-130`, le théorème QROM demanderait approximativement
`ε_OW≤2^-392`. Or le meilleur avantage OW considéré comme borne sur tous
les adversaires est au moins `2^-256`, par simple devinette d'un message.
Cette voie de réduction ne certifie donc pas cette cible avec ces budgets.
C'est une limite du majorant utilisé, pas une attaque contre R1.

De plus, un biais demandé `2^-128` après `2^64` requêtes est une exigence
différente d'un facteur de travail `Time/Adv≥2^128`. La qualification en
« bits de sécurité » demande les unités de temps/portes, mémoire,
parallélisme et probabilité de succès. Le programme conserve ces notions
séparées. Une plus grande dimension MLWE ne supprime pas l'espace message
de 256 bits ni les graines de 256 bits.

## 6. Apport et portée des travaux récents

Hövelmanns–Hülsing–Majenz séparent la recherche d'échecs exploitant la clé
publique (FFP-NG) de celle qui ne connaît pas la clé cible (FFP-NK). Leur
théorème 10, version arXiv v1 p.31–32, donne un lien entre ces jeux. Nous
conservons cette distinction pour les futures analyses d'oracles d'échec,
sans attribuer une valeur numérique manquante à l'un des jeux.
[HHM, version v1 consultée](https://arxiv.org/abs/2203.10182v1).

Majenz–Sisinni fournissent une réduction de MLWE à FFP-NG pour une famille
subgaussienne, avec des hypothèses asymptotiques explicites. Leur schéma
module est simplifié et omet la compression ; le théorème 4.3 et la
limitation p.27 ne donnent pas un majorant fini directement applicable à
R1 à n=256. Les constantes de croissance, le seuil n0 et le terme
négligeable doivent être instanciés ; q=7681 n'y suffit pas.
[MS, ePrint 2025/1997](https://eprint.iacr.org/2025/1997).

Un raccord structurel fini peut cependant être contrôlé : CBD(3) est
exactement la somme indépendante de CBD(1) et CBD(2). Avec X de loi CBD(1)
et Y de loi CBD(2), `E[X | X+Y=z]=z/3`. Le test vérifie cette identité
rationnellement sur tout son support, en accord avec la proposition A.1.
La compression v, les graines réutilisées et les paramètres finis restent
des obligations distinctes avant toute transposition de la réduction MS.

## 7. Reproduction, preuves et limites restantes

```powershell
.\.tools\research-venv\Scripts\python.exe -m unittest discover -s research -p test_r1_security_bounds.py -v
.\.tools\research-venv\Scripts\python.exe research/r1_security_bounds.py
.\.tools\research-venv\Scripts\python.exe research/r1_security_bounds.py --verify results/security/m05-cca-001
```

L'instantané nouveau `results/security/m05-cca-001` conserve les budgets,
leur provenance et les sources propres nécessaires au rejeu. Les fichiers
historiques restent inchangés. Les PDF externes restent dans des caches
ignorés et ne sont pas redistribués ; `source-anchors.json` enregistre URL,
version, pages lues et empreintes.

Les sept tests couvrent les compteurs implicites et ceux du dispatch quantique,
l'inversion exacte des exigences, les racines par entiers, la fraction du
certificat, les lois CBD et l'énumération de **729 tables pondérées** d'un
oracle scalaire à q=17. Ce dernier test contrôle explicitement le maximum
sur messages avant l'espérance, et montre que certaines paires
oracle/clé ont une enveloppe supérieure à la moyenne. Il s'agit d'un test
mathématique réduit, pas d'un second moteur R1 ni d'un taux mesuré R1.

Le passage restant vers une garantie globale doit relier ε_CPA/ε_OW aux
attaques du PKE à graines, borner ε_J dans le jeu quantique exact,
confirmer les constantes formelles ROM et examiner les conséquences des
primitives concrètes. Les résultats M05 rendent ces obligations précises
et mesurables, tout en conservant l'ouverture de C01.

## Sources relues et versions

| Source | Version et pages pertinentes | SHA-256 du PDF consulté |
|---|---|---|
| HHK | 26 septembre 2017, définitions p.7–9 et transformation p.10–21 ; erratum primaire du 2 novembre 2021 consulté par son texte indexé, PDF corrigé complet inaccessible | `33412e6927c288f40384d594fd21915dce0a755487489a0a5f7c1961a63df290` |
| Höv21 | Couverture 9 décembre 2020, dépôt bibliographique 2021 ; définitions p.26, sections 2.1.1/2.1.3/2.1.4 p.61–86 | `06fd15e5930057285c9c0101b2517b64df03a7e52169475365f7c050ff569ce9` |
| GYY25 | PDF produit le 30 septembre 2025, 97 pages ; figure 7 p.15–16, définition 4 p.49, théorème 22 et remarque 6 p.96–97 | `408b2f6f880658b4026e19393ef2d6cd764255f823b0a5ec28538e40f14d34ff` |
| MS25 | PDF produit le 25 octobre 2025, 31 pages ; figures 3.2/4.2, théorème 4.3 p.25–27 et annexe A p.30–31 | `5bab9b2ca4b8a73e6c48ae05a2f5d6d2f14ae57b5558e0d3b3c775177b30a4e8` |
| HHM22 | arXiv:2203.10182v1, 18 mars 2022, 52 pages ; section 6 et théorème 10 | `8ae9bc66b45d58c8ce055bae6978440211c532566b395dd03f8e8e682bb09a12` |

La copie de la thèse a été récupérée auprès de la
[Bibliothèque nationale allemande](https://d-nb.info/1227710364/34). Les
PDF GYY/MS ont été récupérés sur les copies du miroir ePrint
`eprint.iacr.asia`, avec les empreintes ci-dessus ; les liens des notices
primaires restent ceux du dépôt ePrint d'origine. La date de fabrication
du PDF sert à identifier le fichier lu, sans être confondue avec une date
de validation externe du projet.
