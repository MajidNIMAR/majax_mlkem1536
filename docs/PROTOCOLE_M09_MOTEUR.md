# M09 : contrats, propriétaires secrets, sécurité et optimisation

Décision du 16 novembre 2026. Les cinq chantiers demandés sont exécutés
dans NIST sur PC Windows et Linux x86-64. Android et l'intégration dans
Messenger restent différés. M08, ses sources capturées, ses contrôles et
ses résultats restent immuables ; M09 est une nouvelle réalisation de R1.

Référence avant modification : HEAD local `2c2bacf`, cœur M08 b39c2fdf…,
engine_poly ffe7b50d… et secret_box 08d6ba7a…. La fermeture de compilation
est capturée sous `artifacts/generated/m09-poly-001/baseline-source`.
Le manifeste initial SHA-256 est
`e49c9709e78be01539f908bb16fef5b3cf087dc0e5d3256049213fdb711ec691`.

## 1. Contrats et chemins d'échec

Les graines de bruit deviennent des vues typées de 32 octets, avec rôles
distincts pour KeyGen et le chiffrement. Leur représentation ne possède
ni clone ni affichage de secret. Les indices de lignes restent publics ;
les nonces sont construits à partir de rôles explicites (s, e, r, e1, e2).
Les domaines et les octets R1 ne changent pas.

Le remplissage d'entropie écrit dans un propriétaire déjà créé par
l'opération. KeyGen et Encaps partagent leur chemin réel avec une
injection privée de fournisseur utilisée en test. Tester tous les préfixes
de remplissage partiel (0..64 et 0..32), un unique appel de taille exacte,
la propagation de l'erreur sans résultat et l'absence de transformée NTT
avant succès. Les API publiques continuent à utiliser exclusivement l'OS.

## 2. Cycle des secrets

Décoder le message directement dans le propriétaire de Decaps, sans le
retour rempli de recover_message puis pke_decrypt. Retirer Clone du
stockage générique de secrets ; le clone explicite du chiffré reste permis.
Conserver l'absence d'unsafe en production, les propriétaires Zeroizing,
le rejet implicite et l'ordre de validation des imports. Examiner les
images finales CLI et consommateur par défaut sur les deux OS, en
distinguant inventaire d'instructions et preuve d'effacement/temps constant.

## 3. Argument de sécurité

Produire une avancée vérifiable sur un sous-terme C01 avec modèle,
hypothèses, calcul indépendant et contre-exemples aux extensions abusives.
Ne pas convertir des estimations BKZ en preuve IND-CCA ni le ROM en QROM.
Le choix R1 n'est pas remplacé sans justification complète de correction,
attaques, formats et ressources.

## 4. Optimisation mesurée

Mesurer la référence avant candidat. Évaluer le pré-calcul public des
facteurs NTT : budget et protocole propre fixés avant son acquisition.
Distinguer candidat arithmétique isolé et candidat M09 final incluant les
contrats. Conserver les résultats négatifs, les séries brutes et les coûts
de tables publiques. Les 48/55/68 transformées, l'anneau et les vecteurs
restent identiques ; aucun cache secret persistant n'est admis.

## 5. Qualification et revue indépendante

Rejouer les corpus déterministes et l'oracle indépendant, les échecs
d'entropie, les imports, les contrôles complets fmt/Clippy/Rust/Python et
les certificats. Capturer les sources et les binaires nouveaux sans
remplacer les paquets M08. Le pont certificat doit reconnaître une
nouvelle réalisation et conserver les branches historiques.

Préparer un dossier de revue externe avec périmètre, empreintes,
procédure de reproduction, questions et obligations ouvertes. Une revue
interne ou un inventaire automatique ne vaut pas audit par un tiers.
La publication GitHub suit seulement les résultats constatés ; les
campagnes M08 ne deviennent pas des campagnes M09. Le rapport et le
journal sont mis à jour au fil des résultats. Toute qualification longue
non réalisée est nommée comme travail restant.
