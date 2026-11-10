# M05 — protocole de sécurité et de comparaison

26 octobre 2026. Autorisation : réaliser les points 1 et 2 de la réponse
précédente, actualiser le rapport et créer un commit local. Le travail se
déroule dans NIST. Il ne modifie pas le profil R1 et ne publie rien à distance.

## Question et point de départ

La base de production est le commit `f54d92e`, avec arithmétique M04,
`KEM1536-DEV-Q7681-R1`, n=256, k=6, q=7681, CBD(3), u exact sur 13 bits,
v sur 5 bits et secret partagé de 32 octets. Les archives M01–M04 et J2
restent figées. Le dossier scientifique M04 est conservé dans
`results/security/m04-001`.

Deux questions sont examinées :

1. Quels termes d'une borne IND-CCA pour cette construction exacte peuvent
   être établis, instanciés ou vérifiés, dans les modèles classique et
   quantique d'oracles aléatoires ?
2. Comment situer ses problèmes cryptanalytiques face aux projets publics
   proches, avec des distributions, budgets d'échantillons et ressources
   déclarés et comparables ?

L'objectif ne constitue pas une hypothèse de supériorité. Un résultat
défavorable, un modèle non applicable ou une obligation non résolue est un
résultat à conserver.

## Volet 1 : critères et limites

- Identifier la version, les pages et les conditions des théorèmes
  primaires utilisés, y compris leurs errata accessibles.
- Distinguer le PKE idéal à bruits frais, la transformation FO dans son
  modèle d'oracles et le programme utilisant SHA3/SHAKE.
- Conserver la définition de correction déjà établie : moyenne sur les
  clés honnêtes du pire message pour chaque clé, dans le modèle idéal.
- Compter séparément les requêtes de hachage, d'expansion et de
  décapsulation ; ne pas substituer un nombre d'échanges honnêtes à un
  budget adversarial.
- Fournir un calcul reproductible des termes numériques effectivement
  justifiés. Un coût ou avantage encore inconnu doit rester explicite.
- Ne pas transformer une réduction classique en résultat quantique par
  simple remplacement de coûts, ni en preuve pour Keccak concret.
- Ne pas annoncer une fermeture de C01 ou du QROM si une transition ou une
  hypothèse du théorème demeure non établie.

## Volet 2 : comparateurs et contrat commun

Le panel principal comprend R1, le témoin ML-KEM-1024, Aigis-Enc mode 4,
Kyber historique au commit `ca375e3e3391360a863efd4122b14e396c994dde`, et
KINDI-512-3-2-1. Le profil académique Kyber1536 à q=3329 peut compléter le
panel, avec son statut de modèle distinct d'un moteur public livré.

Chaque entrée doit préciser l'anneau, la dimension du secret, le module,
les distributions exactes des secrets et des erreurs, la représentation
publique, la compression, la cible et les échantillons effectivement
disponibles. La bibliothèque kyber-py ne crée pas un nouveau jeu de
paramètres par sa seule paramétrabilité.

Les estimations utilisent une version figée de l'outil, le même modèle de
coût au sein d'une paire, un attaquant mono-cible sans oracle de fuite et
des limites d'exécution explicites. Les échecs et délais dépassés restent
dans les résultats. Les coûts classiques, sensibilités quantiques, mémoire
et probabilités de réussite demeurent distincts.

Une clé publique comprimée ne donne pas automatiquement une instance LWE
exacte à erreur indépendante. Tout calcul sur le problème non comprimé ou
sur un bruit de remplacement doit être marqué comme proxy et ne peut
servir seul à classer les KEM publiés. Les calculs sur une instance augmentée
du chiffré exigent une justification distincte de ceux sur la clé publique.

## Reproduction et clôture

Les nouveaux résultats, sources de calcul et manifestes sont enregistrés
sous de nouveaux identifiants M05. Les textes tiers dont la redistribution
n'est pas établie restent dans un cache ignoré ; leurs URL, versions et
empreintes sont consignées. Les résultats historiques ne sont pas réécrits.

Les scripts nouveaux doivent avoir des contrôles portant sur les erreurs
mathématiques et de contrat pertinentes, puis être intégrés à `check`.
La revue contradictoire doit précéder les conclusions du rapport.
L'achèvement de l'étude M05 ne signifie pas que toutes les obligations de
sécurité sont fermées. Le bilan final doit indiquer séparément les résultats
obtenus, les limites restantes et l'identifiant du commit créé.
