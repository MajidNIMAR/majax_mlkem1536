# Mise à jour des attaques — état au 24 octobre 2026

Cette revue complète l'étude historique `run-001`. Elle identifie les résultats pertinents pour le candidat à n=256, k=6, q=3329 ou 7681 et CBD(2)/CBD(3). Elle n'est pas une garantie d'exhaustivité. « Repéré » signifie que la notice ou le texte indiqué a été consulté ; « exécuté » est réservé aux calculs conservés avec leur provenance. Une publication récente n'est pas nécessairement incorporée au dernier commit d'un estimateur.

## Résultats à prendre en compte

| Référence primaire et version repérée | Nature | Conséquence pour notre étude |
|---|---|---|
| [Carrier, Meyer-Hilfiger, Shen, Tillich — variante de MATZOV, CRYPTO 2025](https://eprint.iacr.org/2022/1750), révision du 11 juin 2025 | Dual avec décodage par codes | Compléter la simple sortie MATZOV. Le numéro ePrint 2022 ne doit pas masquer la révision et publication 2025. |
| [Karenin et al. — Fast Slicer, ASIACRYPT 2025](https://eprint.iacr.org/2025/1910), révision du 27 octobre 2025 | Hybride primal, Batch-CVP | Les gains pratiques sur de petites instances ne se transposent pas automatiquement au rang 6 ; étudier le modèle et ses coûts. |
| [Ducas, Pulles — Accurate Score Prediction, JoC](https://link.springer.com/article/10.1007/s00145-025-09560-7), publié le 20 novembre 2025, volume 2026 | Validité du score dual | Une estimation MATZOV ne constitue pas à elle seule une analyse validée des faux positifs et faux négatifs. |
| [Hou, Jiang, Ogilvie — Careful with the Ring!, CRYPTO 2026](https://doi.org/10.1007/978-3-032-35377-1_15) ; [version (a) 2026/279](https://eprint.iacr.org/2026/279), révisée le 4 octobre ; [version (b) 2026/366](https://eprint.iacr.org/2026/366), révisée le 30 août | Hybrides utilisant les rotations de l'anneau | Distinguer MLWE et son plongement LWE. Pour notre projet, le degré de l'anneau est **256**, et non 1536. |
| [Ling, Yan, Zhao — Quantum Rejection Sampling](https://eprint.iacr.org/2026/979), révision du 26 mai 2026 | Dual quantique et échantillonnage | Les améliorations sont relatives à un cadre dual prouvable et à un accès quantique cohérent spécifié. Ne pas soustraire leur gain à un coût MATZOV d'un autre modèle. |
| [Cai, Liu, Wang, Lu — Thorns in Polynomial Convolution](https://eprint.iacr.org/2026/1022), révision du 19 juillet 2026 | Corrélations du bruit et attaques par échec | Examiner la loi jointe et les événements conditionnés. Notre borne d'union n'exige pas l'indépendance entre coefficients de sortie ; les hypothèses sur l'arrondi restent à examiner. |
| [Li, Zheng — Unified Dual Attack Analyses](https://eprint.iacr.org/2026/1048), révision du 14 octobre 2026 | Covariance du score dual | Revoir les hypothèses de variance du score avant de conclure sur une probabilité de succès. Ce travail ne remplace pas directement la formule de bruit du déchiffrement. |
| [Li, Wang, Wang — Provable Correctness of MATZOV-style FFT](https://eprint.iacr.org/2026/2166), reçu le 23 septembre 2026 | Analyse prouvable d'un cadre FFT dual | Comparer avec sa propre référence de coûts. Une réduction d'un coût prouvable plus élevé n'est pas la même chose qu'une amélioration du meilleur coût heuristique. |
| [Engelberts et al. — Improved Quantum 3-Tuple Sieving, CRYPTO 2026](https://arxiv.org/abs/2510.08473v3), version du 7 juillet 2026 | Compromis temps/mémoire quantique | Le modèle à trois tuples a un régime de mémoire distinct. Changer seulement la pente de temps d'un échantillonneur à deux tuples serait incohérent. |
| [Guo, Nabokov, Johansson — Hybrid Adaptive-LDPC, USENIX Security 2026](https://www.usenix.org/conference/usenixsecurity26/presentation/guo-qian), août 2026 | Exploitation d'un oracle d'échec imparfait | Une excellente correction honnête ne protège pas d'une fuite exploitable sur des chiffrés choisis. L'absence d'oracle doit faire partie des exigences d'implémentation. |
| [Raya et al. — CoNAN](https://eprint.iacr.org/2026/1041), mai 2026 | Exploitation de structures algébriques | Les pertes annoncées pour certaines autres algèbres ne s'appliquent pas par défaut à notre anneau cyclotomique. Vérifier les hypothèses avant tout transfert. |
| [LightSec 2026 — Cross-information lattice attack on ML-KEM](https://lightsec2026.com/), conférence du 11 octobre ; [annonce des auteurs industriels](https://www.sealsq.com/investors/news-releases/sealsq-presents-peer-reviewed-research-on-attack-and-countermeasures-on-ml-kem-key-generation-at-lightsec), 13 octobre | Fuites lors de l'encodage en génération | Article et résultats détaillés à obtenir avant quantification. La notice de conférence et l'annonce ne démontrent pas une attaque applicable à notre future implémentation. |

Deux prépublications très récentes sont également signalées : [Qu et al., 2026/2117](https://eprint.iacr.org/2026/2117), datée du 20 septembre, et [Bashiri, 2026/2565](https://eprint.iacr.org/2026/2565), datée du **20 octobre 2026**. Leurs notices ont été consultées sur [le miroir ePrint pour 2117](https://eprint.iacr.asia/2026/2117) et [pour 2565](https://eprint.iacr.asia/2026/2565) ; l'accès direct aux deux notices originales a renvoyé HTTP 403 dans cet environnement. Elles restent des entrées à vérifier sur texte intégral, sans nombre repris dans notre comparaison calculée.

## Modèles quantiques : correction de la comparaison

Le tableau historique reste utile pour retracer le travail, mais son coefficient quantique de 0,265 n'est pas le meilleur exposant asymptotique de crible à deux tuples connu lors de cette revue. [Bonnetain, Chailloux, Schrottenloher, Shen, EUROCRYPT 2023](https://eprint.iacr.org/2022/676) donnent 0,2563, avec les hypothèses quantiques et de mémoire de leur algorithme.

La nouvelle sensibilité utilise explicitement `2^(0,2563 β)`. Elle ne compte pas les facteurs sous-exponentiels, les portes physiques, la profondeur ou le coût d'une mémoire quantiquement accessible. Elle est séparée du modèle classique MATZOV à coûts plus détaillés. Le modèle 2026 à trois tuples annonce une pente de temps 0,2846 avec une pente de mémoire 0,1887 ; il améliore un régime de mémoire plus faible, sans battre le temps du régime à deux tuples disposant de davantage de mémoire. Nous ne le présentons pas comme un coût complet LWE intégré.

Les familles d'attaques, modèles de réduction et modèles de score sont des choix différents. Le nom `MATZOV-classical` du calcul décrit le modèle de réduction utilisé et ne signifie pas que les critiques sur toutes les variantes de l'attaque duale ont été résolues.

## Reproduction des attaques sur anneau

Les sources de [TabOg/mlwe-hybrids](https://github.com/TabOg/mlwe-hybrids) sont figées au commit `a92f335665eef69927d2d8f49832bd595a6dac32`. Le sous-module d'estimation de l'article est figé à `6019056011d10d7e9c30a0d5da2d2f729fbc2eec`. Le panneau de comparaison communautaire récent utilise séparément `f31b86fe490ab11abb4a69efa13007583791e10a`, daté du 22 octobre 2026. Ces deux versions ne sont pas fusionnées silencieusement.

Le code primal avec rotations est principalement conçu pour les secrets creux. Toute sortie sur CBD(2)/CBD(3) est à examiner dans ce cadre ; elle ne remplace pas l'adaptation du dual avec rotations étudié pour Kyber dans l'article.

Le sous-module dual de l'article est `TabOg/CodedDualAttack@e2104ca50a293ed09b8fcec703cd2b143d21bee8`. L'inspection révèle une borne supérieure de recherche `beta0_sup = 1000` et un pilote principal spécialisé pour q=3329 et les paramètres Kyber. Notre rang 6 nécessitait déjà β supérieur à 1000 dans l'étude historique. **Ce pilote ne peut donc pas être transposé sans adaptation et contrôle des bornes.** Les résultats texte publiés ne sont pas réétiquetés comme nos calculs. Les fichiers pickle et objets natifs fournis dans ce dépôt ne sont pas chargés pour obtenir des résultats.

## Corrélations : une vérification locale utile

`research/joint_noise_check.py` énumère exactement le produit de deux polynômes CBD(1) de degré inférieur à 4 modulo X^4+1. Il s'agit d'un petit modèle pédagogique distinct du KEM. Les 65536 issues élémentaires pondérées donnent :

- covariance des deux premiers coefficients : 0 ; covariance de leurs carrés : 1/2 ;
- probabilité que chacun dépasse le seuil absolu 2 : 245/2048 ;
- probabilité jointe réelle : 35/1024, différente du produit des marginales 60025/4194304 ;
- probabilité réelle d'au moins un des deux événements : 105/512, inférieure à la borne d'union 245/1024.

Cet exemple confirme localement qu'une covariance nulle n'est pas l'indépendance. Il confirme aussi pourquoi on peut conserver une borne d'union sans multiplier les probabilités de succès des coefficients. Il ne démontre pas la justesse des hypothèses d'arrondi de `run-001`, ne chiffre pas le DFR réel du rang 6 et ne transfère pas directement un résultat gaussien de l'article Thorns à nos CBD.

## Conséquences sur le développement

Avant tout gel, les estimations doivent porter sur les mêmes paramètres, distributions, budgets d'échantillons et nombres de cibles. Deux budgets sont distingués dans les nouveaux calculs : `m=256k` pour la clé publique et `m=256(k+1)` comme comparaison étendue donnant davantage d'échantillons au modèle. Ce second budget n'est pas l'affirmation que toutes les composantes d'un chiffré réel sont des échantillons LWE sans perturbation.

Le futur chemin de décapsulation doit maintenir le rejet implicite et éviter tout résultat observable révélant l'égalité au contrôle de réencapsulation. Les conversions et encodages de secrets, les comparaisons, le choix du secret de remplacement, les accès mémoire et le code machine produit doivent faire l'objet d'une évaluation sur les cibles réellement supportées. La variable de bruit d'un échange honnête ne doit pas servir de justification contre un oracle de chiffrés malveillants.

La sélection de q=7681, η=3 reste ouverte. Un tableau modernisé et une revue bibliographique ne constituent pas un audit, ni une couverture complète des nouvelles attaques. Le rapport courant indique précisément les calculs exécutés, les échecs d'outils et les adaptations encore nécessaires.

## Calculs maintenant conservés

`results/j2/run-002/` contient 120 évaluations, 118 coûts retournés et les deux erreurs BKW de P0. Les hybrides primaux et duaux du panneau communautaire sont exécutés dans les modèles déclarés. Les huit sorties du primal avec rotations sur CBD denses restent exploratoires et ne démontrent pas l'effet du dual avec rotations sur notre rang 6. Les autres travaux du registre ne sont pas déclarés intégrés à un estimateur simplement parce qu'ils sont recensés ici.

Les coûts de réduction MATZOV et la sensibilité asymptotique BCSS23 restent séparés. Les huit reprises d'export Arora–GB conservent leur première tentative, avec un cœur de calcul inchangé. Le [rapport](RAPPORT_RECHERCHE.md) présente les minima observés et leurs limites.

## Vérification ciblée du backend témoin

Le [signalement RustCrypto KEMs #389](https://github.com/RustCrypto/KEMs/issues/389), ouvert le 28 septembre 2026 et commenté par les mainteneurs les 28–29 septembre, concerne l'API dépréciée d'import des clés développées : représentations non canoniques, capacités d'export différentes et possibilité de panic lors d'un export vers une graine absente. Le rapporteur ne constate pas de divergence cryptographique dans ses essais et ne revendique pas une non-conformité à FIPS 203.

Notre harnais utilise cette API seulement pour les clés publiques de test ACVP, afin de comparer le format développé officiel. Il n'appelle pas l'export vers une graine après cet import. L'API n'est pas exposée comme une interface d'application du rang 6. Le backend reste figé pour le témoin ; ce signalement est consigné comme limite d'API à examiner avant toute réutilisation applicative, sans être présenté comme une attaque cassant ML-KEM ni comme un correctif déjà appliqué en amont.

## Complément sur la justification de la correction

Le [travail sur les dépendances de u](DEPENDANCES_ARRONDI_U.md) ajoute une source primaire de septembre 2026 sur la correction avec dépendances, distincte des attaques recensées ici. `run-004` conserve nos vérifications de petit anneau et un témoin de correction avec u exact, sans indépendance des arrondis. Sa borne ne constitue pas une estimation d'attaque et ne ferme pas les questions de codes/rotations, de scores ou de mémoire ci-dessus.

## Audit ciblé des intégrandes du dual avec rotations

Le [complément d'utilité](UTILITE_COMPRESSION.md) documente l'inspection du code des auteurs au commit 7b7e8000071b5379048af92e5b49a84881f7e8f8, distinct du sous-module e2104 précédemment repéré. Dans find_relative_threshold, l'appel ligne 124 utilise nfft avec dlat alors que le préfacteur ligne 125 est beta1. Cette observation confirme le contenu du [signalement identitymapping](https://github.com/identitymapping/CodedDualAttack), qui propose beta1. Le contrôle local de normalisation soutient l'incohérence ; ni la correction globale, ni son effet sur notre scénario ne sont validés. Les sources exactes et empreintes sont conservées dans references/coded-dual-audit ; aucun code externe n'est exécuté. Les coûts run-002 sont indépendants de ce fichier dual. L'adaptation au rang 6, q=7681 et CBD3 reste ouverte.

## Adaptation exécutée du dual avec codes

Le [jalon run-008](DUAL_CODES_ROTATIONS.md) utilise le code e2104 et sa dépendance de réduction propre. Cette version possède déjà l'intégrale pondérée correcte en beta1 pour dlat, contrairement à la version 7b7e8000 du signalement précédent. Six points publiés sont reproduits, puis 1043 évaluations d'un modèle GV idéal sont conservées avec quatre contre-vérifications à haute précision. Cela ne constitue pas une reproduction complète des scores révisés ou d'un décodeur polaire à q=7681. Les points de refus de probabilité, les limites de recherche et l'extrapolation des coefficients de réduction au-delà de 1024 restent visibles. Les chiffres run-002 ne sont pas remplacés ni ajustés forfaitairement.

## Contribution CBD et contrôle des covariances — run-011

La consultation primaire de [Ducas et Pulles, Accurate Score Prediction for
Dual-Sieve Attacks](https://link.springer.com/article/10.1007/s00145-025-09560-7)
et de la notice de [Li et Zheng, Unified Dual Attack Analyses:
Covariance-Based Score Distribution Prediction for LWE](https://eprint.iacr.org/2026/1048),
révisée le 14 octobre 2026, précise le contexte des limites d'heuristiques de
score et des analyses par covariance. Les métadonnées et l'étendue consultée
sont conservées dans `references/decoder-score-2026/sources.json`.

[Notre étude](SCORES_DECODEUR.md) calcule une contribution cosinus du résidu
de code sous secret CBD idéal et ses covariances à secret partagé. Elle ne
reproduit pas les scores complets de ces articles. Les six lois exhaustives,
huit petites banques et 114 contrôles numériques valident les calculs dans
ce périmètre ; ils ne valident pas les queues des listes exponentielles du
dual-sieve. Aucun coût antérieur n'est corrigé forfaitairement à partir des
écarts empiriques observés.
