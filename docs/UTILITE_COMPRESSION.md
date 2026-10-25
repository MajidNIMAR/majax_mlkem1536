# Utilité de H01/H02 et confrontation aux modèles d'attaque

Étude du 24 octobre 2026, conservée dans [run-007](../results/j2/run-007/comparison.json). L'objectif est de juger les gains à exigence de correction commune, puis de préciser ce que les estimations d'attaque existantes permettent effectivement de comparer.

## Comparaison à exigence commune

Les trois familles conservent n=256,k=6,q=7681,η1=η2=3. Les masques sont publics et fixes. Les bornes concernent la correction honnête moyenne sur les clés dans le modèle des primitives CBD indépendantes, sans indépendance des arrondis. Les exposants suivants ne sont pas des niveaux de sécurité.

| Exigence de borne | u exact : octets / exposant obtenu | H01 : octets / exposant obtenu | H02 : octets / exposant obtenu |
|---|---:|---:|---:|
| ≤2^-174,8 (C05) | 2592 / −200,803593 | 2581 / −175,734559 | 2567 / −175,665600 |
| ≤2^-200 | 2592 / −200,803593 | 2592 / −200,803593 | 2583 / −200,795235 |
| ≤2^-225 | 2624 / −273,725338 | 2606 / −226,508378 | 2598 / −226,021014 |

Tailles avec flux u continu. Chaque ligne impose le même seuil ; les exposants obtenus ne sont pas nécessairement égaux, notamment à cause des sauts de précision de v. Le témoin simple bénéficie parfois d'une marge supplémentaire substantielle, à conserver dans la comparaison.

Une grille de 500 inclinaisons rationnelles, huit valeurs de dv et des pas correspondant à un octet propose les candidats. Les neuf propositions retenues sont recalculées en rationnels et leurs seuils décidés en entiers : pour un exposant a/b, `N^b*2^a≤D^b`. La recherche numérique n'est pas un certificat d'optimalité globale. Les cas H01 qui reviennent au témoin simple sont conservés comme résultats sans gain.

À C05, H02 gagne 14/2581≈0,542 % sur H01, 25/2592≈0,965 % sur le contrôle simple et 89/2656≈3,351 % sur le témoin initial dv=5. Ces trois références répondent à des questions différentes. À l'exigence 2^-200, H02 (164 paires,dv=4) ne gagne que 9/2592≈0,347 %. À 2^-225, il gagne 8/2606≈0,307 % sur H01 et 26/2624≈0,991 % sur u exact, dont la borne est alors bien plus forte que le seuil demandé.

## Confrontation au panneau existant

`modern_worker.py` construit les paramètres à partir de n*k,q,CBD(η), du budget d'échantillons et du modèle de coût. La compression de u/v n'est pas une entrée. La clé publique reste identique : les trois formats correspondent exactement aux mêmes trente évaluations `q7681-eta3` de run-002. Le nouvel instantané enregistre les indices, hypothèses et coûts d'origine, sans présenter leur réemploi comme de nouveaux calculs.

Dans les six familles de réseaux du panneau communautaire, le minimum est dual_hybrid : log2(rop)=383,772563 pour MATZOV classique et 325,958069 dans la sensibilité de réduction asymptotique BCSS23. Les budgets clé (1536) et étendu (1792) donnent ici le même minimum. L'estimation autorise une mémoire exponentielle sans plafond, une cible et aucun oracle. La sensibilité BCSS23 n'optimise pas quantiquement toutes les étapes. Ces nombres ne sont pas un niveau global du KEM. BKW/Arora–GB et les deux diagnostics primaux avec rotations restent identifiés séparément, ces derniers exploratoires sur CBD dense.

L'absence d'écart ne démontre pas l'absence d'effet cryptanalytique de H02. Pour une attaque sur un chiffré, H01 produit une précision hétérogène connue ; H02 une erreur vectorielle couplée et une grille décalée. Le résidu e1+δu ne peut pas être remplacé sans justification par une nouvelle CBD indépendante : δu dépend des entrées et peut dépendre de e1,y,A. Le budget « étendu » ne prouve pas que le chiffré fournit 1792 échantillons LWE propres. Il faut distinguer récupération de la clé, récupération du secret éphémère et sécurité du KEM complet.

Restent nécessaires : distributions conditionnelles du chiffré, dual avec codes/rotations et scores révisés, mémoire bornée et coûts quantiques complets, transformation CCA et oracles d'échec/fuite. Une faible probabilité d'échec honnête ne justifie pas la résistance à un chiffré malveillant ou à un canal auxiliaire. Un quantificateur public déterministe peut être analysé comme post-traitement du chiffré complet en contexte passif approprié ; cela ne remplace pas une preuve CCA de la nouvelle interface.

## Audit ciblé du code dual avec rotations

Les copies documentaires et empreintes sont dans [references/coded-dual-audit](../references/coded-dual-audit/sources.json). Aucun code externe, objet natif ou pickle n'est exécuté. Deux versions distinctes sont conservées :

- `e2104ca...`, sous-module précédemment repéré : pilote q=3329, alpha=2 sauf n=512, recherche `beta0_sup=1000`. Ces choix nécessitent une adaptation. Cette version ne contient pas `rot_utilitaries.py`.
- `7b7e8000071b5379048af92e5b49a84881f7e8f8`, version du [code des auteurs](https://github.com/TabOg/CodedDualAttack/blob/7b7e8000071b5379048af92e5b49a84881f7e8f8/OptimizeCodedDualAttack/rot_utilitaries.py) visée par un [signalement reproductible](https://github.com/identitymapping/CodedDualAttack) : dans `find_relative_threshold`, ligne 124, l'intégrande reçoit nfft alors que la ligne 125 multiplie son intégrale par beta1. La variante temporaire voisine emploie beta1 avec dlat. Le signalement propose de remplacer nfft par beta1 dans cet appel.

Le contrôle algébrique de normalisation renforce l'observation : lorsque le facteur exponentiel tend vers 1, cette partie vaut beta1/nfft avec l'appel actuel, contre 1 avec beta1. C'est un diagnostic local de cohérence, pas une reproduction de l'article, une validation globale de la correction proposée ou un nouveau coût d'attaque. L'effet sur notre scénario n'est pas chiffré. Aucun coût de run-002 ne repose sur ce fichier dual avec rotations ; les diagnostics de rotations existants utilisent un autre outil primal.

## Décision de recherche

Conserver H02 : son support joint améliore la borne et son gain subsiste à plusieurs seuils. Ce résultat limité, reproductible et accompagné de contrôles est utile pour le futur article. L'existence d'antécédents généraux et l'absence de preuve de primauté restent explicites.

Pour un moteur, les gains inférieurs à 1 % ne justifient pas à eux seuls l'encodeur supplémentaire, le format plus complexe et son évaluation en temps constant. Maintenir le témoin simple comme contrôle et H01/H02 comme variantes expérimentales ; ne sélectionner aucun profil. Le coût d'exécution et l'utilité réseau réelle restent non mesurés. La priorité reste de terminer J2 avant l'implémentation du rang 6.
