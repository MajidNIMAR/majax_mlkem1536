# J2 — Diagnostic prioritaire de la décapsulation de P0

Étape du 24 octobre 2026, demandée avant la sélection des paramètres. Les six
scénarios et leur provenance sont conservés dans
[`results/j2/run-003`](../results/j2/run-003/). Aucun profil de remplacement
n'est choisi. Les instantanés précédents restent inchangés.

## Question et périmètre

P0 garde n=256, k=6, q=3329, η1=η2=2, du=11, dv=5. Il s'agit de comprendre son
défaut de correction avant de chercher à le corriger. Le seuil C05 reste
2^-174,8. C'est un objectif du cahier des charges, choisi à partir du tableau 1
de [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf), et non un
seuil déduit de la dimension 1536.

L'étude isole les deux erreurs de compression à bruit et module inchangés et
compare les rangs 4, 5 et 6. Le rang 5 est uniquement un diagnostic du mécanisme
d'accumulation du bruit. Il ne constitue pas un changement d'objectif.

## 1. Origine du bruit

Le résidu étudié reste

`E = eᵀy − sᵀ(e1 + δu) + e2 + δv`.

Dans le modèle indépendant initial, les contributions à la variance d'un
coefficient de P0 sont :

| Terme | Variance | Part de la variance totale |
|---|---:|---:|
| eᵀy | 1536 | 33,639 % |
| sᵀe1 | 1536 | 33,639 % |
| sᵀδu | 591,053169 | 12,944 % |
| e2 | 1 | 0,022 % |
| δv | 902,041210 | 19,755 % |
| Total | 4566,094379 | 100 % |

La variance intrinsèque, sans aucune erreur de compression, vaut donc 3073.
Au rang 4, avec les mêmes bruits, elle vaut 2049. L'augmentation du rang ajoute
des produits de coefficients, tandis que la marge du décodeur à q=3329 reste
inchangée. Les parts de variance n'attribuent pas les probabilités d'événements
rares aux différents termes : les queues sont calculées séparément.

Le calcul emploie le **second moment** de δu :
`Var(s δu) = Var(s) × E[δu²]`, car s est centré et indépendant de δu dans le
modèle. L'arrondi entier à q impair n'est pas parfaitement centré : à du=11,
`E[δu] = 1/3329` et `E[δu²] = 1281/3329`.
Omettre le carré de cette petite moyenne aurait rendu la décomposition
inexacte. La somme des cinq contributions est vérifiée rationnellement contre
la variance du moteur exact de `run-001`.

## 2. Isoler la compression

Les logarithmes ci-dessous concernent le modèle indépendant de `run-001`.
La borne inférieure est l'événement d'échec d'un coefficient pour un message
aux bits uniformes. La borne supérieure est la borne d'union sur les 256
coefficients. Elles encadrent la probabilité totale dans ce modèle ; aucune
indépendance entre les coefficients de sortie n'est requise.

| Scénario à q=3329, η1=η2=2 | du / dv | log2 borne inférieure | log2 borne supérieure |
|---|---|---:|---:|
| Témoin, k=4 | 11 / 5 | −183,073851 | −175,073851 |
| Diagnostic k=5 | 11 / 5 | −149,478863 | −141,478863 |
| P0, k=6 | 11 / 5 | −126,440399 | −118,440399 |
| P0, u sans perte | 12 / 5 | −149,400971 | −141,400971 |
| P0, v sans perte | 11 / 12 | −138,072783 | −130,072783 |
| P0, u et v sans perte | 12 / 12 | −163,832785 | −155,832785 |

Les quatre scénarios déjà présents dans `run-001` reproduisent exactement les
enregistrements rationnels précédents, y compris leurs empreintes de rapports
numérateur/dénominateur. Les deux nouveaux scénarios complètent le diagnostic.

Dans le scénario sans perte, 12 bits désigne ici une transmission restituant
exactement les coefficients modulo 3329. Le calcul étend la formule d'arrondi
pour vérifier cette restitution ; il ne prétend pas que FIPS 203 définit une
compression Compress_12 dans son API, dont la compression est définie pour d<12.

**Conclusion conditionnelle :** les quatre combinaisons étudiées de maintien ou
suppression des erreurs de compression échouent à C05. Même sans aucune erreur
de compression, la borne inférieure dépasse le seuil : une borne d'union trop
large ne peut donc pas expliquer à elle seule ce rejet. Ce résultat n'est pas
un théorème interdisant toute construction de compression ou de réconciliation
différente à q=3329.

## 3. Retirer l'hypothèse d'indépendance de l'arrondi final v

Pour q=3329, dv=5, le parcours exhaustif des résidus donne toujours
`−52 ≤ δv ≤ 52`. Cette borne est déterministe : elle ne nécessite pas que le
résidu avant compression soit uniforme.

Posons `T = eᵀy − sᵀ(e1 + δu) + e2`. Pour chaque bit, le décodeur est correct
sur un intervalle périodique `[L,U]` modulo q après retrait du bit encodé.
Si δv peut prendre toute valeur de `[a,b]` :

- une correction est possible seulement si T appartient à `[L−b,U−a]` modulo q ;
- une correction est garantie si T appartient à `[L−a,U−b]` modulo q.

Le complément du premier ensemble donne une borne inférieure d'échec, même
lorsque δv choisit sa valeur en fonction de T, de la clé et du bit. Le
complément du second donne une borne supérieure. Autoriser toutes les valeurs
entières de l'intervalle élargit les choix possibles de l'arrondi réel ; cela
conserve le sens des deux bornes. Le code refuse les amplitudes trop grandes
pour la dérivation par intervalles employée ici.

Les masses sont comptées avec des entiers sur le support complet de T, sans
approximation gaussienne ni troncature. Une énumération exhaustive sur de petits
modules vérifie les choix adaptatifs extrêmes, les deux bits, l'arrondi
asymétrique, plusieurs périodes et le cas sans erreur. Une seconde inclusion
exacte vérifie que les marginales indépendantes de `run-001` sont à l'intérieur
des intervalles obtenus.

Pour P0, la borne inférieure sur l'échec total est ainsi :

- **2^-155,091982** pour un message aux bits uniformes ;
- **2^-155,183698** comme borne valable pour tout message fixé.

Ces deux bornes dépassent 2^-174,8. Le rejet de P0 ne dépend donc pas de
l'indépendance supposée de δv, **à condition de conserver les hypothèses de
distribution de T**, notamment l'arrondi δu uniforme et indépendant et les
variables CBD indépendantes. Ce n'est pas une preuve de transfert de ces lois
à un KEM réel.

Ce contrôle plus prudent ne certifie pas automatiquement un scénario lorsqu'il
ne le rejette pas. Pour le témoin k=4, par exemple, la borne supérieure sans
indépendance de δv est seulement 2^-170,120098 : cet encadrement ne suffit pas
à lui seul à établir C05. Il ne réfute pas non plus l'analyse publiée du témoin.
Pour u sans perte et v conservé, l'encadrement est également insuffisant pour
trancher sans hypothèse supplémentaire sur v.

## 4. Décision et conditions de clôture de J2

Le diagnostic de P0 est renforcé. Son profil et son contrat restent des bases
historiques reproductibles. Aucune implémentation du KEM de rang 6 ne commence
sur la base de ce profil.

La priorité suivante de correction est d'étudier les dépendances de δu et de
δv dans les scénarios de réparation, ainsi que la variabilité entre clés et
l'effet du nombre d'utilisations. Le scénario q=7681, η=3 de `run-001` conserve
son résultat conditionnel ; il n'est pas choisi par ce diagnostic. Une
simulation ordinaire ne mesurera pas directement une queue de l'ordre de
2^-175 ou plus petite.

Pour clore la faisabilité, il faut réunir :

| Point à établir | État après ce diagnostic |
|---|---|
| Comprendre le rejet de P0 et isoler la compression | Réalisé dans les modèles précisés ci-dessus |
| Justifier les lois et leurs dépendances pour un scénario de réparation | Ouvert |
| Établir une correction compatible avec C05 pour ce scénario | Résultats conditionnels disponibles ; justification à compléter |
| Comparer la résistance aux attaques récentes et les ressources requises | Étude moderne disponible ; codes/rotations, scores et mémoire à compléter |
| Documenter C01 à C06 et décider de la faisabilité | Ouvert ; aucun nouveau profil figé |

La sélection finale des paramètres et les étapes d'implémentation, de mesure,
de revue et de publication suivent cette conclusion de faisabilité. Les
comparaisons exploratoires de paramètres restent des outils de J2.

## Reproduction

```powershell
python -m unittest discover -s research -p test_decapsulation_diagnostic.py
python research/verify_decapsulation_results.py
python research/run_decapsulation.py --output artifacts/generated/diagnostic-nouveau
.\scripts\dev.ps1 check
```

Le répertoire de sortie doit être nouveau ou vide ; les fichiers sont créés
exclusivement, sans écrasement. Pour une nouvelle étude scientifique conservée,
choisir un nouvel identifiant après `run-003`. L'exécution ne nécessite ni Sage
ni dépendance Python supplémentaire. Le vérificateur contrôle les empreintes
des huit entrées et de la sortie, quatre accords exacts avec `run-001`, les
identités de variance et les rejets conditionnels documentés.
