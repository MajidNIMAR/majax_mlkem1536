# M09 — tables publiques de twiddles NTT

16 novembre 2026. Périmètre : optimisation interne compatible avec R1,
sur x86-64 Windows GNU et Ubuntu 22.04/WSL, Rust 1.91.1. M08 reste figé.

## Hypothèse et protocole avant candidat

La référence M08 calcule 1024 butterflies par transformée (8 × 128) et
recalcule le prochain twiddle public par un produit modulaire à chacune.
Une table publique de 255 puissances par direction suffit à toutes les
étapes. Les pré-calculer à la compilation retire ces 1024 produits,
sans changer les réductions des valeurs secrètes, les permutations,
les domaines du KEM ou les comptes 48/55/68 de transformations.

La capture indépendante `artifacts/generated/m09-poly-001/baseline-source`
précède toute mutation des trois fichiers du cœur. Ses 44 entrées incluent
la fermeture Rust, les inclusions extérieures et les deux probes M08.
Le manifeste SHA-256 est
`e49c9709e78be01539f908bb16fef5b3cf087dc0e5d3256049213fdb711ec691`.
Le candidat isolé conserve toutes ces entrées sauf engine_poly.rs ; le
candidat M09 final du programme principal sera qualifié séparément.

Avant modification, mesurer la référence sur les deux hôtes : forward,
inverse, multiply_add, et les quatre opérations KEM. Les micro-opérations
emploient uniquement des coefficients publics synthétiques, 32 appels par
observation, 500 observations et 50 échauffements par opération/série.
Les opérations KEM utilisent le harnais M07 inchangé, 250 observations et
50 échauffements. Comparaison : cinq séries AB/BA, ordre des opérations
tournant, CPU logique 10. Toutes les observations sont conservées ; aucune
exclusion. Les compilations peuvent partager les caches mais utilisent
des cibles distinctes. L'isolation globale de l'hôte n'est pas garantie.

Budgets fixés avant candidat : médiane forward et inverse ≤ 0,90 fois la
référence sur chaque hôte ; médiane de chacune des quatre opérations KEM
≤ 1,05 et p95 ≤ 1,20. multiply_add, non modifié, sert de témoin avec
médiane ≤ 1,10 et p95 ≤ 1,25. La taille des deux tables ne doit pas dépasser
1024 octets publics au total (255 × 2 × 2 = 1020 attendus). Aucun nouveau
buffer secret, aucune allocation et aucune récursion dans transform.
Les frames et .rodata des objets réels seront conservées ; une taille
statique n'est pas une borne du pic dynamique de pile. La qualification
globale M09 porte séparément sur la mémoire du KEM final.

La table est contrôlée indépendamment par exposants modulo q, en plus des
convolutions de l'oracle générique et des vecteurs historiques. Une forme
machine propre est requise : accès aux tables par seuls indices publics,
pas de division nouvellement introduite sur coefficients. Cette revue
bornée ne constitue pas une preuve universelle de temps constant,
d'effacement des registres/ABI, ni un audit externe.

## Résultats

Les 50 000 observations comparatives sont conservées : 30 000
micro-observations et 20 000 observations KEM, sans exclusion. Les
médianes par appel en microsecondes sont les suivantes.

| Hôte | Opération | M08 | Tables seules | Rapport candidat/référence |
|---|---|---:|---:|---:|
| Windows | forward | 6,428 | 4,241 | 0,660 |
| Windows | inverse | 6,447 | 4,266 | 0,662 |
| Windows | KeyGen | 488,8 | 384,6 | 0,787 |
| Windows | Encaps | 539,4 | 419,1 | 0,777 |
| Windows | Decaps valide | 664,1 | 518,6 | 0,781 |
| Windows | Decaps rejeté | 664,35 | 516,4 | 0,777 |
| Linux | forward | 6,427 | 4,317 | 0,672 |
| Linux | inverse | 6,423 | 4,323 | 0,673 |
| Linux | KeyGen | 504,071 | 403,994 | 0,801 |
| Linux | Encaps | 550,271 | 440,717 | 0,801 |
| Linux | Decaps valide | 680,359 | 535,386 | 0,787 |
| Linux | Decaps rejeté | 680,491 | 530,102 | 0,779 |

Les huit budgets KEM et les quatre budgets forward/inverse passent. Le
témoin multiply_add reste à 250 ns sur Windows ; sur Linux, sa médiane
passe de 247,594 à 277,219 ns, soit **+11,965 %**, au-delà du seuil de
10 %. Son p95 passe de 317,969 à 358,094 ns (+12,619 %), sous le seuil
de 25 %. Le corps de cette opération n'a pas été modifié, mais sa
position dans l'image et les conditions d'exécution peuvent compter.
Aucune cause unique n'est établie. **Cette campagne isolée n'est donc
pas intégralement acceptée.** Elle n'est pas remplacée par une répétition
choisie ; la décision sur le moteur M09 complet appartient à son propre
protocole fixé avant ses nouvelles mesures.

Le profilage initial Windows a précédé le candidat. Le profilage Linux
prévu avant modification n'a pas été chronométré dans cet ordre, à cause
du démarrage WSL et du temps de compilation ; sa capture de source M08
est néanmoins antérieure et immuable. Les mesures comparatives Linux
respectent les cinq séries AB/BA et les seuils fixés avant candidat.
Cette déviation de séquence est conservée explicitement. L'hôte n'était
pas dédié ; aucun intervalle statistique ou gain universel n'est revendiqué.

Les huit tests arithmétiques isolés passent sur chaque OS, dont le
contrôle indépendant des 510 twiddles par exposants, les convolutions
génériques, les limites des produits et les produits scalaires à six termes.
La qualification globale M09 couvre séparément les corpus KEM historiques.

Les deux tables exactes de 510 octets apparaissent chacune une fois dans
chaque micro-image candidate. L'ensemble fait 1020 octets, dans le budget
de 1024. La section entière .rdata Windows augmente de 1120 octets virtuels
(1024 octets bruts après alignement) ; .rodata Linux augmente de 1000 octets.
Ces sections comprennent d'autres constantes et alignements que les tables.

Le compilateur vectorise les butterflies SSE2. La frame LLVM de transform
dans le micro-ELF passe de **88 à 184 octets** (+96). Sur Windows, le
prologue réserve 72 puis 328 octets locaux (+256), avec les mêmes huit
push de registres et neuf sauvegardes XMM supplémentaires dans le candidat.
Les autres frames ELF forward/inverse/multiply_add restent 0/8/0 octets.
Ce constat statique ne prouve pas le pic dynamique du KEM. Deux probes M08
inchangés sont reconstruits contre la capture de référence, 108 observations
mémoire par OS, pour permettre la comparaison avec le moteur M09 final.

La revue ciblée de transform dans les deux micro-images ne voit pas de
division entière et retrouve les adresses de tables à indices publics.
Les sauvegardes locales examinées concernent pointeurs/indices publics ;
les sauvegardes d'entrée XMM Windows préservent les valeurs antérieures de
l'appelant, dont la provenance n'est pas garantie. Ce constat ne ferme
pas l'obligation registres/ABI et ne remplace pas la revue des images livrées.

Le cœur arithmétique candidat est SHA-256
`c22f53f544e99f1029e3da81472599c2c113b65ebc6bc414f1cf4558534f8304`.
La capsule `results/engine/m09-poly-001` conserve les sources, recettes,
binaires, données brutes, désassemblages, sections, frames et le résultat
négatif. Son lecteur est purement documentaire : il recalcule les grilles,
statistiques, empreintes et octets des tables, sans compiler ni relancer
de mesure.

```powershell
.tools/research-venv/Scripts/python.exe -B research/m09_poly_evidence.py verify
```
