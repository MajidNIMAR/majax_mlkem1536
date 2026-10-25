# Contrat algorithmique initial du candidat 1536

Ce contrat précise J0 du cahier des charges. Il fixe une base reproductible pour les expériences P0 ; la sélection cryptographique du profil appartient à J2.

## Paramètres et source des opérations

Le profil est `KEM1536-EXP-P0`, version 0.1, défini dans `profiles/kem1536-p0.toml`. Il impose n=256, k=6, q=3329, eta1=eta2=2, du=11 et dv=5. Le rang 6 constitue l’écart de paramétrage étudié par rapport à la famille standardisée.

Les fonctions de conversion, l’arrondi, l’échantillonnage, les produits et la NTT suivent la copie figée de FIPS 203. Les deux clarifications examinées dans `ERRATA_FIPS203.md` s’appliquent à sa lecture. Les conventions de Kyber antérieures à ML-KEM ne doivent pas être substituées aux fonctions de cette base.

## Entropie et séparation

La génération tire deux graines indépendantes d et z de 32 octets. L’encapsulation tire m de 32 octets. Le chemin d’application doit employer l’aléa cryptographique du système et propager une indisponibilité de cet aléa comme un échec.

La génération utilise `G(d || 0x06)` pour séparer le rang. Pour l’échantillonnage de la matrice, les indices sont des octets de valeur 0 à 5. Les séquences de compteurs PRF sont 0 à 11 en génération et 0 à 12 en encapsulation. Chaque position doit être utilisée conformément à l’ordre de la base algorithmique.

Les graines synthétiques des tests doivent rester dans une interface distincte. Les identifiants de profils et les versions doivent être vérifiés par les types et les enveloppes d’application. Une future variante de même rang doit spécifier sa séparation et proscrire la réutilisation de graines privées entre profils.

## Objets et interface

| Objet brut P0 | Taille en octets | Construction |
|---|---:|---|
| ek | 2336 | Vecteur t en représentation NTT puis graine publique rho |
| dk développé | 4704 | Vecteur s en représentation NTT, ek, H(ek), z |
| c | 2272 | Vecteur u compressé puis polynôme v compressé |
| K | 32 | Secret partagé du KEM |

Les offsets exacts figurent dans le cahier des charges. Les encodages bruts ne contiennent pas le nom du profil. Aucune permutation des coefficients ou convention de rangement différente ne doit apparaître à une frontière sérialisée sans changement de version.

L’API d’application doit distinguer les types de clé d’encapsulation, clé de décapsulation, chiffré et secret partagé. Elle doit exposer trois opérations : `KeyGen`, `Encaps` et `Decaps`. Les secrets ne doivent pas être inclus dans une implémentation de journalisation ou dans les erreurs.

## Erreurs et rejet implicite

Les catégories d’erreur sont une longueur invalide, une clé publique non canonique, une clé privée importée incohérente, un profil non pris en charge ou une indisponibilité de l’aléa. Une correction silencieuse de clé publique est interdite.

Pour un chiffré correctement dimensionné qui échoue au contrôle de réencapsulation, Decaps sélectionne le secret de remplacement défini par la base algorithmique. L’appelant reçoit un secret de même type et de même longueur, sans indicateur révélant ce rejet. Cette sélection ne doit pas dépendre d’un branchement observable sur le résultat secret du contrôle.

L’import d’une clé développée vérifie les longueurs, la validité de la partie publique et son empreinte. Il ne prouve pas qu’une clé arbitraire a été générée correctement. Une clé issue des graines internes et une clé importée doivent donc conserver une provenance distinguable.

## Critères d’évolution

Les données et analyses doivent nommer explicitement P0. Toute évolution des paramètres crée un nouveau profil avec ses propres vecteurs et calculs. Une optimisation n’altère pas le profil si elle conserve exactement les résultats pour les mêmes entrées déterministes et fait l’objet des contrôles requis.

Le témoin ML-KEM-1024 est une dépendance de comparaison séparée. Ses résultats ne constituent pas des résultats du rang 6. Les premiers calculs J2 du 24 octobre 2026 montrent que P0 ne satisfait pas C05 dans le modèle étudié. Ce contrat reste celui du point de départ historique ; les pistes de révision figurent dans `RAPPORT_RECHERCHE.md` et ne le modifient pas implicitement.

