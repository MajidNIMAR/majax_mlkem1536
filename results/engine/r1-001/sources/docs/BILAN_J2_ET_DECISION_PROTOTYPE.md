# Bilan J2 et décision de développement expérimental

25 octobre 2026. L'utilisateur demande d'avancer autant que possible sur
le moteur sans attendre sa validation, avec mises à jour régulières du
rapport. Cette instruction autorise le développement expérimental en
parallèle des questions J2 restantes. Elle remplace la séquence antérieure
qui différait toute implémentation du rang 6 jusqu'à la clôture complète
de J2. Les conditions de validation du candidat ne sont pas abaissées.

## Décision opérationnelle

Développer le profil d'essai **KEM1536-DEV-Q7681-R1** : n=256, k=6,
q=7681, η1=η2=3, u exact et v sur 5 bits. Le témoin simple run-004
dispose déjà d'un certificat de correction dans le modèle CBD indépendant.
Les variantes à faible marge restent conservées ; elles ne sont pas
nécessaires au premier parcours du moteur.

Ce profil est une base de développement versionnée, sans sélection finale
du candidat, clôture J2, validation J3 ou revendication d'IND-CCA établie.
Les commandes et formats doivent nommer ce profil. P0 reste historique.

## Exigences et limites de passage

| Exigence | Bilan | Conséquence de développement |
|---|---|---|
| C01 : IND-CCA | Transformation avec dérivation, réencapsulation et rejet implicite à spécifier ; preuve pour cette construction modifiée encore ouverte | Implémenter et comparer les chemins, sans annoncer une preuve héritée de ML-KEM |
| C02 : attaques | Comparaisons et limites conservées dans run-001 à run-020 ; modèles idéaux de scores/codes/réduction encore conditionnels | Aucun niveau global annoncé ; consolider les budgets et les attaques sur échecs avant gel |
| C03 : limites symétriques | Graines et secret partagé de 32 octets | Ne pas convertir 1536 coefficients en 1536 bits de sécurité ; documenter les plafonds selon les modèles, sans extrapolation linéaire |
| C04/C05 : correction | P0 rejeté ; témoin simple q7681/η3/u exact/dv5 certifié dans le modèle CBD ; certificats run-004 conservés | Employer le témoin simple comme base, vérifier que l'implémentation reproduit ses opérations et distributions |
| C06 : compromis | Comparaisons à seuils communs run-007, faibles marges des formats plus compacts | Privilégier la lisibilité et la marge du témoin pour le développement, sans sélection finale de paramètres |

Le certificat existant suppose les lois CBD idéales et les conditions de
primitives documentées. Les sorties SHAKE concrètes sont liées à ces
hypothèses cryptographiques ; les essais ne prouvent pas le taux rare.

## Travail engagé sans nouvelle validation humaine

1. Figer la spécification d'essai et les formats propres au profil.
2. Développer encodages canoniques, arrondis, SHA3/SHAKE, échantillonnages,
   cœur PKE puis KeyGen/Encaps/Decaps, avec aléa système pour l'application.
3. Construire une seconde réalisation Python indépendante du cœur Rust,
   confronter les sorties déterministes, formats et rejets.
4. Fournir une commande de vérification et des essais longs séparés,
   conserver les vecteurs synthétiques et le rapport d'exécution.
5. Poursuivre le durcissement et les critères J3/J4 à partir des écarts
   observés ; ne pas engager de déploiement ou publication sans demande.

Les propriétés temporelles, l'effacement complet des temporaires,
le fuzzing, la portabilité Linux et les seuils longs restent à mesurer.
Une API fonctionnelle ne suffit pas à valider ces propriétés. Chaque
résultat doit indiquer la réalisation, le nombre de cas et ses limites.
