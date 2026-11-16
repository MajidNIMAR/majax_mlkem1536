# M09 — variante scalaire après rejet de la vectorisation

16 novembre 2026. Addendum fixé avant mutation du candidat scalaire.

La variante à tables de `m09-poly-001` et le moteur typé
`m09-final-001` ne sont pas promus. La revue Windows constate une nouvelle
copie de coefficient par sauvegarde ABI XMM de transform. Leurs données
et paquets restent figés avec la décision négative.

Un seul prototype correctif est autorisé ici : conserver les 255 twiddles
publics par direction et placer `std::hint::black_box(twiddle)` sur la
valeur publique de chaque butterfly, afin d'empêcher l'auto-vectorisation
observée. Aucun domaine, format, paramètre, compte de transformées ou
opération mathématique ne change. Le candidat reprend les contrats et
le cycle de vie typés du moteur final-001. La barrière n'est ni une
preuve universelle de temps constant ni une garantie LLVM à elle seule.

Avant compilation globale, construire un micro-consommateur Windows et
Linux et inspecter transform : aucune sauvegarde XMM callee-save nouvelle,
aucune nouvelle sauvegarde de coefficient secret hors propriétaire,
aucune division entière. La barrière peut stocker le twiddle public sur
la pile ; sa provenance doit être conservée dans la revue.

La référence reste le snapshot M08 immuable et ses binaires micro/KEM
de `m09-poly-001`. Le candidat aura un nouveau snapshot dans
`artifacts/generated/m09-poly-002`. Le manifeste de préenregistrement
lie ce texte et les captures avant mutation. Cibles séparées sous
`target/m09-poly-002`; Rust1.91.1 et caches/outils partagés déclarés.

Comparaison finie sur CPU10, quatre séries AB/BA, 250 observations KEM
par opération/version/série et 50 échauffements. Micro : 500 observations
par opération/version/série, 32 appels par observation, 50 échauffements.
Toutes les observations sont conservées, sans exclusion ni répétition
sélectionnée. L'hôte n'est pas isolé. Le témoin multiply_add est publié
comme diagnostic, sans prétendre le budget de la première campagne satisfait.

Budgets préalables : chaque opération KEM médiane ≤1,05 et p95 ≤1,20 fois
la référence ; gain médian ≥5 % sur au moins une opération KEM par OS.
Les micro-latences sont exploratoires, sans condition supplémentaire.
La qualification globale ultérieure conserve la limite mémoire par cas
de +1024 octets de maximum observé, allocations identiques et tables
publiques ≤1024 octets. Elle aura ses propres images et preuves ; cette
étude préalable ne vaut pas livraison ou fermeture du durcissement.

## Résultat du prototype unique

Les **40 000 observations** prévues sont conservées (24 000 micro et
16 000 KEM), sans exclusion. Les huit budgets KEM passent ; l'objectif
de gain d'au moins 5 % est atteint sur chaque OS.

| Hôte | Opération | Médiane M08 (µs) | Médiane scalaire typé (µs) | Rapport médiane | Rapport p95 |
|---|---|---:|---:|---:|---:|
| Windows | KeyGen | 488,8 | 420,5 | 0,8603 | 1,0044 |
| Windows | Encaps | 538,9 | 458,2 | 0,8503 | 0,7641 |
| Windows | Decaps valide | 663,7 | 565,6 | 0,8522 | 0,8858 |
| Windows | Decaps rejeté | 666,2 | 565,3 | 0,8485 | 0,6769 |
| Linux | KeyGen | 505,590 | 438,939 | 0,8682 | 1,1459 |
| Linux | Encaps | 554,766 | 477,964 | 0,8616 | 0,9058 |
| Linux | Decaps valide | 692,073 | 621,526 | 0,8981 | 1,1750 |
| Linux | Decaps rejeté | 691,785 | 605,432 | 0,8752 | 0,9202 |

Les p95 Linux KeyGen et Decaps valide augmentent de 14,6 % et 17,5 %,
sous le plafond de 20 %. Ce résultat reste visible. Les médianes
forward/inverse diminuent d'environ 22 % sous Windows et de 20–21 %
sous Linux ; multiply_add reste un diagnostic distinct. Aucune
significativité statistique ou amélioration universelle n'est déduite.

La micro-revue relue par un second agent retrouve transform sans registre
XMM/YMM/ZMM ni division entière sur les deux OS. La nouvelle écriture
de deux octets sur pile provient du twiddle public chargé dans la table.
Les coefficients restent dans les GPR puis reviennent au propriétaire.
La réservation locale Windows est de 88 octets (72 pour M08) ; la frame
LLVM Linux est de 104 octets (88 pour M08). Les images finales complètes
doivent toujours être revues pour leurs propres formes machine.

Le premier processus Linux est sorti avec code0 et une grille complète,
mais WSL a écrit l'avertissement précis d'échec de session systemd
utilisateur sur stderr. Le contrôleur initial exigeait stderr vide et
s'est arrêté après avoir conservé ce processus. Un adaptateur documenté
classe uniquement cet avertissement exact, réutilise ce premier reçu et
ses données sans modification, puis exécute les quinze cellules Linux
manquantes du même plan. Les contrôleurs avant/après et la demande de
reprise sont conservés ; aucune cellule n'a été rééchantillonnée.

Le moteur arithmétique scalaire est SHA-256
`3de875c98b9dfd2d511d3774d263da24fdcfe03e917a90bbb6bcadd540a175b0`.
La capsule `results/engine/m09-poly-002` conserve les nouvelles sources,
quatre nouvelles images et les observations, en identifiant la réutilisation
exacte des images M08 de référence. Son lecteur purement documentaire
rejoue les grilles, statistiques, ordre AB/BA, reprise, tables publiques
et contrôles d'instructions ; cinq tests de refus/contrôle réel passent.

```powershell
.tools/research-venv/Scripts/python.exe -B research/m09_poly_scalar_evidence.py --verify-archive results/engine/m09-poly-002
```
