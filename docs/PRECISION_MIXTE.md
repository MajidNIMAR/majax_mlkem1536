# J2 — H01 : précision mixte et borne indépendante des arrondis

Expérience du 24 octobre 2026, conservée dans
[`run-005`](../results/j2/run-005/). Elle met à l'épreuve la première piste du
[registre des hypothèses](REGISTRE_HYPOTHESES.md). Le module, le rang et les
lois de bruit restent n=256,k=6,q=7681,η1=η2=3. Il ne s'agit pas d'un nouveau
profil sélectionné ni d'une implémentation du KEM.

## Hypothèse et contrôles

Le témoin avec u exact et dv=5 de `run-004` occuperait 2656 octets. H01 cherche
à réduire cette longueur avec une répartition publique de précisions, tout en
conservant une borne C05 qui n'utilise pas l'indépendance des arrondis.

Deux leviers sont distingués : diminuer la précision de v avec u encore exact,
puis répartir des précisions différentes dans u. Le premier est un contrôle
indispensable pour attribuer correctement le gain au second.

## Dérivation de la borne

Pour un coefficient de sortie, écrire le résidu avant arrondi v sous la forme

`T = Σ E_i*Y_i − Σ S_i*(F_i + Δ_i) + E2`,

avec 1536 termes dans chaque somme. Les primitives E,Y,S,F,E2 suivent les lois
CBD3 indépendantes du modèle. Les signes négacycliques peuvent être absorbés
dans les variables symétriques. Les Δ_i peuvent dépendre arbitrairement de ces
primitives et de la matrice.

Chaque précision impose un support déterministe :

| Précision de u | Nombre de bits | Borne sur la valeur absolue de Δ_i |
|---|---:|---:|
| Compression scalaire | 11 | 2 |
| Compression scalaire | 12 | 1 |
| Transmission exacte | 13 | 0 |

Le parcours exhaustif des 7681 résidus vérifie ces supports. L'inégalité

`−S_i*Δ_i ≤ r_i*|S_i|`

est valable pour chaque réalisation, même si Δ_i dépend de S_i. D'où

`T ≤ W+ = Σ E_i*Y_i + Σ (−S_i*F_i + r_i*|S_i|) + E2`.

De même, −T admet une autre variable majorante W−. Les symétries des CBD
donnent aux deux majorantes la même loi. **W+ n'est pas centrée et sa loi n'est
pas supposée symétrique.** Le facteur deux ci-dessous vient des deux
majorations de même loi, pas d'une hypothèse de symétrie de W+.

Pour z>1 rationnel, poser

`P(z)=E[z^(E*Y)]`, `D_r(z)=E[z^(-S*F+r*|S|)]`, `C(z)=E[z^E2]`.

Si m_r désigne le nombre de termes de support r et h le seuil de queue
suffisant après prise en compte du pire arrondi v, Markov et l'union sur les
256 sorties donnent

`Pr[échec message] ≤ 2*256*P(z)^1536*C(z)*Π_r D_r(z)^m_r / z^h`.

La borne est plafonnée à 1. Aucune indépendance des erreurs Δ_i ou de l'arrondi
v n'est requise. La matrice s'annule algébriquement avant cette majoration.
Les seules indépendances probabilistes utilisées sont celles des primitives
CBD idéales. La portée reste une correction honnête moyenne sur les clés,
pour un message fixé indépendamment des clés.

## Répartitions publiques et grille

La famille par blocs étudie les 28 répartitions de six polynômes entiers entre
11,12 et 13 bits. Les huit valeurs de dv sont 2,3,4,5,6,7,8 et 13, soit
224 configurations rapportées.

Une seconde famille répartit m coefficients sur 12 bits et les autres sur
13 bits. Le masque public est défini, pour 0≤i<1536, par

`precision(i)=12 si floor((i+1)*m/1536)>floor(i*m/1536), sinon 13`.

Il contient exactement m positions compressées et les répartit entre les six
polynômes avec un écart d'au plus un. Chaque sortie négacyclique permute les
positions secrètes : elle conserve le nombre de termes de chaque support.
La même MGF marginale s'applique donc aux 256 sorties, sans supposer leur
indépendance. Les m retenus sont multiples de huit pour des longueurs entières
en octets. Le masque est fixé par le scénario, sans décision adaptative.

Pour proposer les inclinaisons z et les nombres de coefficients, le balayage
emploie 500 rationnels de 1001/1000 à 3/2, avec des scores numériques. Il
rapporte ensuite, pour chaque dv, une frontière de coefficients et le pas
suivant de huit coefficients. **Chaque configuration rapportée et chaque
acceptation sont recalculées en rationnels.** Le flottant ne décide jamais
une certification C05.

Les bornes choisies utilisent des comparaisons entières : pour p=N/D,
`p≤2^-174,8` équivaut à `2^874*N^5≤D^5`. Le meilleur certificat trouvé conserve
ses MGF et son rapport final en hexadécimal. Les scores de présélection sont
conservés séparément et identifiés comme tels. Il n'est revendiqué ni optimum
global sur tous les quantificateurs ni exploration certifiée de tous les z.

## Une propriété utile de la méthode

Cauchy–Schwarz appliqué aux poids positifs du MGF donne, pour tout z>1,

`D_1(z)^2 ≤ D_0(z)*D_2(z)`.

Dans cette majoration, remplacer une paire de précisions (11,13) par (12,12)
conserve 24 bits et ne dégrade pas la borne. Cela oriente la recherche vers
des pertes de précision légères réparties, plutôt que concentrées sur quelques
coefficients. Ce résultat concerne cette méthode de majoration ; il ne
compare pas à lui seul les vrais taux d'échec des quantificateurs.

## Résultats conservés

Le balayage conserve 4000 propositions numériques identifiées comme telles,
puis **240 configurations recalculées exactement** : 224 répartitions par
blocs et 16 points de frontière/pas suivant entre coefficients. Parmi ces
configurations, 25 reçoivent un certificat C05 dans le modèle et 215 ne sont
pas certifiées par cette méthode.

| Point de comparaison | Précision de u | dv | Chiffré théorique | log2 borne supérieure rationnelle |
|---|---|---:|---:|---:|
| Témoin u exact, inclinaison optimisée sur la grille | 1536 coefficients exacts | 5 | 2656 octets | −313,820921 |
| Contrôle : réduction de v seule | 1536 coefficients exacts | 3 | 2592 octets | −200,803593 |
| Plus court certificat trouvé | 88 coefficients sur 12 bits, 1448 exacts | 3 | 2581 octets | −175,734559 |
| Pas suivant testé, non certifié par la borne | 96 coefficients sur 12 bits, 1440 exacts | 3 | 2580 octets | −173,551044 |

Le certificat de référence à z=13/10 reproduit exactement celui de `run-004`,
de logarithme −310,085969. L'amélioration à −313,820921 sur la première ligne
vient seulement d'une autre inclinaison de Chernoff, sans changement de format.
La borne de queues exacte de `run-004`, −319,633504, reste plus fine ; elle
n'est pas réétiquetée comme une borne de cette nouvelle méthode.

Le gain total du point à 2581 octets est de **75 octets**, environ **2,82 %**
du témoin. L'attribution est **64 octets pour la réduction de v**, puis
**11 octets supplémentaires pour la précision mixte de u**, soit environ
0,42 % du contrôle à 2592 octets. Les deux contributions ne sont pas confondues.

Le masque de 88 coefficients répartit les positions sur 12 bits en
`[14,15,15,14,15,15]` par polynôme. Le reste est transmis exactement. Le format
doit être connu publiquement : les longueurs calculées n'ajoutent pas un
masque transmis par chiffré ni une enveloppe de protocole.

Ce point de frontière ne garde qu'environ **0,935 bit** de marge dans le
logarithme de la borne face à C05. Le contrôle à 2592 octets conserve environ
26 bits de marge. Ils servent à étudier le compromis taille/correction ; le
point le plus court n'est pas une recommandation de profil.

La contre-vérification `verify_mixed_certificate_bits.py`, sans import du
moteur arithmétique du projet, reconstruit les MGF à partir des 64 chaînes de
bits CBD3 et des 4096 couples élémentaires. Elle vérifie aussi les supports
d'arrondi et la région sûre, puis retrouve **le même rapport rationnel final**
que le certificat principal. Ses fichiers et sa provenance ont été ajoutés
avant le premier gel Git, sans modifier les sorties initiales du run.

## Portée et décision

Un échec de la certification signifie que cette borne est insuffisante, pas
que la configuration échoue réellement à C05. Les formats compacts étudiés
dans `run-001` avec hypothèses d'arrondi indépendantes ne sont pas invalidés
par cette méthode plus prudente.

Le schéma de précision doit être lié à un éventuel futur profil, à sa
sérialisation et au contrôle complet de réencapsulation. Son choix ne doit
pas dépendre d'une clé, du message ou d'un retour de décapsulation. Les
comparaisons d'attaques, le traitement des entrées invalides, l'analyse CCA et
les mesures de temps restent nécessaires avant toute sélection.

## Reproduction

```powershell
python -m unittest discover -s research -p test_mixed_precision.py
python research/verify_mixed_precision_results.py
python research/verify_mixed_certificate_bits.py
python research/run_mixed_precision.py --output artifacts/generated/mixed-precision-nouveau
.\scripts\dev.ps1 check
```

Les sorties existantes ne sont pas écrasées. La reproduction complète réévalue
les bornes rationnelles ; le contrôle courant vérifie les empreintes et rejoue
le meilleur certificat ainsi que le témoin de `run-004`.
