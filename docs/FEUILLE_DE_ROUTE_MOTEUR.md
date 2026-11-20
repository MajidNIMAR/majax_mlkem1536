# Du dossier de faisabilité au moteur KEM

**Repères au 20 novembre 2026.** `M` numérote des chantiers : M10 est la
référence du moteur livré, M15 le lot historique de preuves publiques
rejoué en CI, M23 la dernière qualification numérotée du moteur et M28 la
dernière recherche C01 numérotée. Les études C01 ci-dessous suivent M28
sans nouveau numéro. Elles ne ferment pas C01 et ne changent pas le statut
expérimental de R1.

**20 novembre 2026 — trois obligations du R1 fixé.** Le nouveau lemme
structurel et la décomposition conditionnelle CCA → CPA précisent la
suite du travail : (1) borner le jeu passif de clé de défi du R1 exact
avec ses fonctions fixées, à partir de prémisses indépendantes ;
(2) construire et analyser un extracteur en ligne efficace pour les
chiffrés acceptés après choix adaptatif ; (3) borner la correction des
témoins ainsi produits sous les distributions réelles. Le coût de la
réduction, la terminaison de KeyGen et le cas quantique doivent être
intégrés avant tout chiffre global. Les deux erreurs adaptatives et
l'avantage passif sont aujourd'hui **symboliques** ; la décomposition
ne ferme pas C01. Une voie de construction distincte restera à examiner
si ces obligations ne reçoivent pas d'argument indépendant applicable.

**20 novembre 2026 — prochaine porte C01.** Les nouveaux raccords du jeu
classique idéal traitent le saut de clé et Decaps adaptative, puis ramènent
la résistance restante à deux distributions Module-LWE du PKE R1. Avant
d'adopter une borne de sécurité, il faut chiffrer ou justifier ces deux
avantages au budget **après réduction**, avec préparation, requêtes,
temps et mémoire. Il faut ensuite construire un argument propre aux
fonctions SHA3/SHAKE et Keccak-f fixées du programme, ou décider d'une
construction séparée dont cette preuve est possible. Les tests finis
des fonctions fixées servent au contrôle de conformité, pas à la fermeture
de cette porte. Le contrôle source/binaire et une revue extérieure restent
des travaux d'assurance distincts. **C01 concret demeure ouvert ; R1 est
expérimental.** Voir le rapport et la note d'état C01.

**Blocs 2 à 4 du programme C01 — décisions du 19 novembre 2026.** Le
calcul quantitatif du profil R1 est livré dans sa portée et le gel de
sécurité est suspendu (`BLOCK2_PARAMETER_FREEZE_HELD`). L'examen des
constructions R2 sélectionnées s'arrête avant code
(`R2_SELECTED_CANDIDATES_NOT_VIABLE_YET`) : preuve, paramètres,
formats, rattachement au module six par 256 et coût ne sont pas réunis
pour un moteur choisi. Le contrôle fonctionnel frais du R1 et le mandat
de revue extérieure sont préparés (`BLOCK4_PREPARED_PARTIAL`) ; la revue
elle-même et le moteur final restent à faire. Les trois dossiers sont
locaux sous `artifacts/retained/` ; C01 concret demeure ouvert.

**Porte de reprise :** sélectionner et faire contre-lire une construction
avec un jeu de sécurité exact, des hypothèses et une réduction chiffrée,
des paramètres admissibles, une correction démontrée, des formats
canoniques et un budget temps/mémoire. Ensuite seulement développer ou
adapter le cœur Rust, la référence indépendante et les images à cette
construction, puis soumettre le paquet exact à une revue extérieure.
La piste R1 demande une nouvelle preuve propre au programme fixe ; les
routes génériques examinées au bloc 1 ne sont pas réutilisables comme
argument complet.

**Bloc 1 du nouveau programme C01 — décision sur les routes de preuve R1,
19 novembre 2026.** L'analyse et les contre-lectures ont écarté des
justifications génériques de la clé défi et une famille de simulations
adaptatives pour le jeu exact à fonctions fixes. Aucune réduction
IND-CCA complète n'a été construite. Le verdict borné
`R1_SELECTED_ROUTES_NO_GO` concerne ces routes seulement ; R1 n'est
pas déclaré vulnérable. Le dossier détaillé est conservé localement sous
`artifacts/retained/r1-c01-block1-001/`.

**Décision suivante :** une nouvelle route R1 devra traiter l'interaction
du programme exact et de ses primitives fixes ainsi que Decaps adaptative,
avec hypothèses indépendantes et ressources complètes. L'autre piste
est une construction distincte dont les paramètres, formats et preuves
seront établis avant implémentation. Aucune optimisation isolée ne ferme
les raccords de sécurité identifiés. **C01 concret reste ouvert** ; le
moteur R1, ses formats et ses binaires canoniques sont inchangés.

**M24 à M28 — cinq blocs C01 traités le 19 novembre 2026 dans leurs
portées.** M24 a fixé le jeu R1 à fonctions fixes et les transitions de
preuve manquantes. M25 a recomposé une famille de coûts ciblée à dimensions
natives sous un modèle simplifié, sans borne du PKE réel. M26 a établi un
saut conditionnel pour le rejet et la carte de six rôles. M27 a composé les
résultats avec inconnues explicites. M28 conserve R1 expérimental et ouvre
une fiche de construction R2 séparée, sans code R2 ni preuve de R1. Les
capsules sont locales sous `artifacts/retained/m24-concrete-game-001/` à
`m28-architecture-decision-001/` ; **C01 concret reste ouvert**.

**Cible scientifique R1 conservée :** construire une réduction indépendante
du défi à fonctions fixes et une route de réponses adaptatives ne dépendant
pas de la possession du secret PKE, avec leurs budgets complets. Le bloc 1
ci-dessus a arrêté les routes génériques sélectionnées, pas cet objectif.
Une nouvelle estimation ou optimisation du moteur seule ne ferme pas cette obligation.
La voie R2 nécessite d'abord paramètres, preuve quantique et formats propres
avant toute implémentation ou revendication « 1536 ».

**M20 à M23 — quatre briques exécutées et contre-vérifiées le 19 novembre
2026.** M20 établit `M20_COMPLETE_SCOPED_DEFAULT` : deux chemins source et
deux constructions propres donnent des images Windows GNU identiques sur le
même PC. M21 établit `M21_COMPLETE_SCOPED` : 176 entrées synthétiques sont
mesurées dans une seule image Linux instrumentée, avec 18 issues exercées sur
24 issues LLVM mappées dans les fichiers R1 actifs. M22 établit
`M22_COMPLETE_SCOPED` : des témoins binaires et diagnostics sont liés aux
images PE et ELF PC exactes. M23 établit `M23_COMPLETE_SCOPED` : une image
release Linux AArch64 est construite et passe son profil et ses diagnostics
sous QEMU utilisateur. Les capsules et revues locales sont dans
`artifacts/retained/m20-source-root-repro-001/` à
`artifacts/retained/m23-aarch64-port-001/`, avec M21 et M22 sous leurs noms
propres. Elles ne sont pas publiées dans le dépôt Git.

**Prochains travaux distincts :** tester la reproductibilité entre machines ;
étudier les chemins non exercés sous des protocoles séparés ; qualifier des
images sur les cibles physiques retenues ; poursuivre l'argument de sécurité
concret C01 avec une revue cryptographique extérieure. Les progrès M20–M23
ne valent ni preuve générale de temps constant ou d'effacement, ni validation
Android, ni sécurité concrète fermée. R1 reste expérimental, C01 ouvert.
Le cœur, les paramètres, formats et API sont inchangés ; aucune nouvelle CI
ou publication GitHub n'est créditée.

**M19 — deux objectifs PC acquis dans leur portée, `M19_COMPLETE_SCOPED`,
19 novembre 2026.** Le
réglage suivi de l'édition de liens Windows GNU rend les deux nouvelles
paires CLI et banc identiques octet à octet sur la même machine et la chaîne
épinglée. Les contrôles fonctionnels et Rust passent après intégration.
Quatre harnais Linux livrent des compteurs de branches LLVM authentiques et
recomptables, avec couverture partielle dans leurs images instrumentées.
Les reçus et erreurs de méthode sont conservés dans
`artifacts/retained/m19-engine-next-001/`. Ces résultats ont motivé les
cycles M20–M23 sur les constructions, les chemins instrumentés, les images
finales et la première cible Linux AArch64 émulée.
Ces résultats ne ferment pas C01 concret et ne donnent pas de garantie
générale de temps constant ou d'effacement ; R1 reste expérimental.

**M18 — six étapes PC exécutées, résultat partiel, 19 novembre 2026.** La
référence R1, les contrats fonctionnels, les images Windows/Ubuntu, la
décision de correction, les régressions/mesures et la contre-revue disposent
de reçus vérifiables dans `artifacts/retained/m18-engine-qualification-001/`.
Les contrôles fonctionnels et Rust passent ; quatre campagnes ASan atteignent
leurs budgets. Les lignes LLVM sont mesurées par harnais. L'égalité brute des
constructions Windows échoue et les branches LLVM ne sont pas acquises, d'où
`M18_PARTIAL`. La décision `NO_CORE_CHANGE_JUSTIFIED` conserve le moteur,
les paramètres et formats sans crédit de durcissement. Les prochains travaux
logiciels sont la reproductibilité brute Windows, la couverture de branches
sur une chaîne adaptée et une revue d'images plus complète des chemins et
propriétés sensibles. Ces progrès demeurent distincts de l'argument de
sécurité concret C01, toujours ouvert ; R1 demeure expérimental.

**Parties 3.2–3.5 — résultats sélectionnés, 19 novembre 2026.** Les quatre
sous-livrables sont constitués dans leurs portées : cible et construction R1
inchangée, chaîne IND-CCA conditionnelle du modèle QROM/RC1, calcul exact de
ce modèle et liaison contrôlée au code/binaire. Les vérifications fonctionnelles
et la contre-revue ne transforment pas cet argument en preuve pour les fonctions
SHA3/SHAKE fixes. Le bloc 3 reste ouvert quant à son objectif scientifique,
C01 concret ouvert et R1 expérimental. Le prochain progrès décisif exige
un raccord cryptographique indépendant pour le jeu fixe, ou une construction
R2 spécifiée séparément si ce niveau de preuve devient le critère retenu.
Les détails sont dans `artifacts/retained/r1-block3-completion-001/`.

**Bloc 3.1 — faisabilité du raccord IND-CCA aux fonctions fixes, 19 novembre
2026.** Le cycle privé `artifacts/retained/r1-fo-feasibility-001/` examine
trois familles de preuve pour le R1 inchangé. Le protocole, la carte complète
des appels du programme, un lemme de simulation conditionnel, des contrôles
logiques et une confrontation aux constructions publiées sont constitués.
Aucune route complète non circulaire n'est acceptée dans ce périmètre ; il
ne s'agit ni d'une impossibilité générale ni d'un constat d'attaque.
**Prochain point de décision :** fixer le niveau de preuve recherché pour R1
et, si une preuve en modèle standard est exigée, spécifier séparément une
construction candidate avant tout changement du moteur. C01 concret reste
ouvert et R1 expérimental. Le résultat du bloc 2 reste conditionnel dans
son modèle déclaré ; aucune nouvelle CI ou publication n'est créditée.

**État courant des quatre blocs — 19 novembre 2026.**

| Bloc | Statut | Conclusion actuelle |
|---|---|---|
| 1 — Résistance aux paramètres réels | Livrable natif ciblé achevé | Calculs globaux et certificats exacts obtenus ; comparaison conditionnelle inconclusive, recherche plus large à poursuivre |
| 2 — Calcul de sécurité dans le modèle élargi | Clos dans le modèle conditionnel déclaré | Composition et borne finale contrôlées ; cible satisfaite sous les hypothèses déclarées |
| 3 — Raccord au KEM concret | Sous-livrables 3.1–3.5 traités ; objectif scientifique ouvert | Argument QROM/RC1 conditionnel et programme reliés dans leurs portées ; aucune preuve IND-CCA aux fonctions fixes retenue |
| 4 — Qualification du programme et des images | Partiel | Garanties obtenues dans les périmètres examinés ; qualification plus large à poursuivre |

Le nouveau lot privé du bloc 3 apporte un contrat du programme entier, une
relecture indépendante des traces KEM conservées et un sous-argument de
correction pour les fonctions fixes. La contre-revue le valide dans ce
périmètre, après clarification de la population des clés. La composition
de sécurité du KEM concret, ses hypothèses numériques et C01 restent ouverts.
Le moteur et le clone public sont inchangés.

La clôture du bloc 2 formalise un résultat déjà acquis. Elle n'adopte pas
la vérité numérique des hypothèses et n'établit pas le transfert aux
primitives fixes. Les capsules historiques restent inchangées. R1 demeure
expérimental et C01 concret ouvert ; aucun nouveau test ou résultat de CI
n'est crédité à cette décision.

**Quatre blocs mis en œuvre et vérifiés dans leurs portées.** Les nouveaux
calculs natifs, la composition chiffrée élargie, la branche PKE concrète et la
qualification source/binaire ont leurs livrables exécutables, acquisitions,
rejeux et revues. Les limites numériques, hypothèses primitives, contrats du
modèle et frontières des images restent explicites. L'achèvement de ce cycle
ne ferme pas tous les sujets scientifiques de chaque bloc.

La suite doit s'appuyer sur ces résultats précis et traiter les frontières
encore ouvertes, sans répéter les acquisitions déjà conservées. R1 reste
expérimental et C01 concret ouvert ; aucun changement de construction ou
du moteur n'est justifié par les contrôles retenus. Le travail détaillé est
privé dans NIST et la publication cc65426 est préservée.

**Publication vérifiée.** La synthèse ciblée est accessible sur main au commit
[`cc65426`](https://github.com/MajidNIMAR/mlkem-1536-core/commit/cc65426a44e0fdbf9647d6a22dbe33baf72d47c0).
Lecture anonyme exacte des documents, parent et référence distante contrôlés.
Publication documentaire uniquement ; données privées et moteur préservés,
aucune nouvelle CI créditée, R1 expérimental et C01 concret ouvert.

**Synthèse publique de l'étude ciblée.** La présentation du dépôt et la note
C01 exposent les nouveaux périmètres exécutables et idéalisés, avec leurs
limites. Les vérifications locales restent séparées de la CI publique et du
lot reproductible M15. Les instruments et résultats détaillés sont privés.
R1 demeure expérimental ; la qualification concrète C01 reste ouverte.

**Cycle ciblé de cryptanalyse et modèle idéal achevé en privé.** La chaîne
exécutable, les acquisitions, les ressources et les revues sont conservées
dans NIST. Les contrôles réduits ne sont pas extrapolés aux paramètres natifs
et les limites de calcul sont des résultats conservés. Le modèle couvre
désormais un transport cohérent d'interface et une préparation préclé
entièrement comptée, dans les hypothèses et ressources explicitement fixées.
Les anciennes capsules et leurs budgets restent historiques.

**Critère pour la suite.** Un progrès sur la qualification de dureté doit
venir d'un résultat natif de cryptanalyse effectivement obtenu et qualifié,
ou d'une composition de ressources plus large entièrement facturée et
vérifiée. Ajouter des petits tests ou répéter une grille d'estimateur ne
remplace pas ce résultat. Les détails de décision restent dans le rapport
privé du cycle. Aucun changement du moteur n'est retenu à ce stade ; R1
reste expérimental, sans clôture concrète C01, ni nouvelle CI/publication.

**Publication M17/C01 vérifiée.** Le commit
[`4d3e1b5`](https://github.com/MajidNIMAR/mlkem-1536-core/commit/4d3e1b5b45d9be5b7b55c35b1dacb97d016c3ffe)
est publié sur main. Le README, SECURITY, la note de portée et les synthèses
du rapport présentent les résultats et leurs limites. La référence distante,
l'API et les octets de quatre documents accessibles anonymement sont contrôlés.
Le nom, le titre, la description courte et les autres réglages du dépôt sont
inchangés. Les archives privées et les entrées exécutables restent préservées.
Cette publication documentaire ne crédite aucune nouvelle CI ; le code reste
celui du53d501de testé dans le run44223949348. R1 demeure expérimental,
avec argument conditionnel établi dans son modèle et qualification concrète
encore ouverte.

**Présentation publique M17 et C01.** Le README, la [note de portée
actualisée](ETAT_RECHERCHE_C01.md) et SECURITY décrivent les nouveaux résultats
et distinguent l'argument conditionnel QROM/RC1 de la qualification concrète
encore ouverte. R1 reste expérimental. Cette mise à jour documentaire conserve
le moteur, ses paramètres, ses formats, les workflows et le lot reproductible
M15. Les programmes, acquisitions et revues détaillés M17/C01 restent privés.
Les comptes de validation locaux ne sont pas une nouvelle suite CI publique.
La référence du code testé demeure le commit53d501de et la CI44223949348.

**C01 — argument conditionnel IND-CCA consolidé et vérifié dans sa portée.**
Le travail ciblé réunit désormais l'énoncé exact de R1, les raccords de
réduction, la correction, les oracles et leurs ressources dans un dossier
unique. La relecture interne n'identifie pas de lemme supplémentaire manquant
pour le modèle quantique idéalisé précisément déclaré. Les deux hypothèses
natives peuvent se ramener à une seule hypothèse MLWE, dans un budget augmenté
dont le coût complet est payé. Le repère numérique conservé est satisfait
conditionnellement ; la condition suffisante est moins forte que le choix
historique. Ce repère ne revendique pas un niveau global en bits.

Le dossier explicatif demandé par le C01 original est constitué comme
argument sous hypothèses. La vérité numérique de l'hypothèse de dureté et la
qualification des fonctions SHA3/SHAKE fixes restent non établies. Le statut
plus fort de qualification entièrement concrète de R1 demeure donc ouvert.
Cette distinction est explicite ; les anciens états et archives ne sont pas
réécrits. Les garanties de programme, temps constant, effacement, audit et
production restent des sujets séparés.

La sélection finale réussit neuf contrôles ciblés et 42 tests distincts,
sans omission ; les reprises de revue ne gonflent pas ce compte. R1 reste
expérimental. Aucun changement du cœur, des paramètres ou du binaire n'est
retenu par ce travail ; les détails restent privés dans NIST, les rapports
PC sont à jour et la publication GitHub précédente est préservée.

**M17 — dix périmètres développés et relus dans leurs portées.** Le cycle
local ajoute des décisions avec matrice visible, des sondes adaptatives, des
filtres quantitatifs pour les deux jeux natifs, un traitement conjoint des
fonctions fixes et des populations, des cartes de ressources, une lecture
sémantique de fonctions Rust, des contrôles d'images PC et une composition
reproductible. La validation sélectionnée comporte **18 travaux réussis et
217 tests ciblés sans omission** ; les reprises de revue ne gonflent pas ce
compte. Les versions initiales et corrections d'instruments sont conservées.

Ces résultats restent propres aux classes, modèles et images déclarés. Ils
ne qualifient ni toute la classe adversariale du KEM concret, ni toutes les
fonctions compilées. Les hypothèses natives, le transfert de famille fixe et
les obligations générales de C01 restent ouverts ou conditionnels. R1 est
conservé pour la recherche, avec gel final différé. Aucun résultat retenu ne
justifie actuellement de modifier ses paramètres ou son moteur ; les sources,
le binaire canonique et les archives antérieures gardent leurs octets.

Le rapport, le journal et la feuille de route sont actualisés sur le PC.
Les détails M17 demeurent locaux et privés ; la publication M16 et le lot
reproductible public M15 sont préservés. Ces validations ne constituent ni
une nouvelle CI GitHub, ni un audit extérieur, ni une qualification NIST ou
une autorisation de production Messenger.


Décision du 25 octobre 2026, à la demande de l'utilisateur : l'objectif
central est un moteur cryptographique ouvert à six polynômes de 256
coefficients. Chaque étude doit servir une décision pour sa construction.
Le futur article décrit ce travail et ses limites ; son écriture ne
remplace pas le développement du moteur.

**M16, 18 novembre 2026 — cinq paliers développés et relus localement.**
Le cycle ajoute une calibration exacte de famille restreinte, des constructions
pour les flux semés, des contrats fonctionnels PKE/FO et des obligations de
chemins sur les images PC. Les cinq volets disposent de sélections rejouées,
de revues croisées et de 113 tests ciblés sans omission. Leurs conclusions
restent dans les modèles et populations déclarés ; les détails sont privés.
Le lot arithmétique M15 demeure public et vérifié dans sa CI dédiée.

La composition M16 conserve explicitement les obligations de classe entière,
transfert des fonctions fixes, correction adaptative et ressources complètes.
C01 n'est pas clos, le gel final est différé et R1 reste la base de recherche.
Aucun résultat ne justifie actuellement un changement du moteur ; ses sources
et son binaire conservent leurs octets. La suite doit viser les obligations
scientifiques identifiées, en gardant distincts correction du programme,
assurance des images et argument de sécurité. Messenger reste interdit.

**M15, 17 novembre 2026 — cinq périmètres approfondis.** La cryptanalyse
ciblée, le traitement des primitives fixes, la correction par clé, la
comparaison commune et la conformité sémantique disposent de nouveaux
livrables exécutables et d'arguments relus. Les preuves et calculs détaillés
restent privés. Les résultats sont acquis dans leurs périmètres déclarés ;
la crédibilité quantitative et le passage au moteur concret restent des
travaux scientifiques ouverts. Aucun changement de construction n'est retenu
sans besoin établi. C01 et le gel final restent ouverts, sans autorisation
Messenger ; les sources et le binaire de référence conservent leurs octets.

**M14, 17 novembre 2026 — marge conditionnelle et ressources construites.**
Un nouveau lemme et une construction de simulation explicite remplacent
deux pistes contrefactuelles M13 dans leur portée déclarée. Leur comparaison
intégrée est acquise et revue localement ; le repère retenu présente une
marge sous hypothèses de travail. Le moteur livré reste inchangé. La suite
prioritaire porte sur la crédibilité des hypothèses aux ressources exactes,
le raccord aux primitives concrètes et la couverture de l'objectif final.
Ces trois obligations sont séparées du contrôle numérique déjà obtenu.
C01 reste ouvert ; aucune activation Messenger ni publication des détails.

**M13, 17 novembre 2026 — recul quantitatif.** Une grille d'hypothèses
indexées aux ressources, des inversions exactes et une analyse des
interactions fournissent une synthèse de décision interne. Les cas
équivalents et les conditions des scénarios sont conservés explicitement.
Cette étude oriente le travail sur les pertes de preuve, les ressources
des réductions et les hypothèses à évaluer ; elle ne sélectionne aucun
profil ni gain global de sécurité. C01 reste ouvert conformément à
l'objectif de ce cycle, sans changement du moteur livré.

**M12, 17 novembre 2026 — contrat et réduction extérieure.** Le nouveau
cycle relie une cible bornée déclarée, les ressources d'une construction
quantique extérieure, les hypothèses exactes du PKE et des analyses de
structure. Les versions finales conservent leurs corrections et les
acquisitions initiales. Le moteur R1 reste inchangé. La suite porte sur
la marge quantitative et la pertinence des hypothèses dans le cadre commun,
sans déduire une modification de paramètres d'une seule limite de preuve.
C01 et le gel final demeurent ouverts ; détails dans le dossier local M12.

**M11, 17 novembre 2026 — développement de sécurité interne.** Un premier
cycle des quatre travaux est exécuté : cartes de composition, recherche
contrainte, décision R1 et contrôles des obligations du programme. Les
preuves instrumentales, résultats et vérificateurs restent dans le dossier
local interne ; le rapport de recherche est actualisé. R1 demeure la
référence de développement. La suite scientifique porte sur la composition
complète et sa calibration aux ressources déclarées ; les résultats bornés
de ce cycle ne ferment pas C01 et n'autorisent pas la production Messenger.

**M10, 16 novembre 2026 — chantiers 1 à 4.** Le
[bilan courant](M10_MOTEUR_ET_QUALIFICATION.md) rassemble les raccords de
sécurité conditionnels, les 40 estimations nouvelles et la décision de
conserver R1 pour le développement. Le candidat 003 retire deux résidus
secrets observés sur les images PC examinées et passe les budgets de
latence et mémoire. Les quatre harnais de la campagne longue ont chacun
atteint 1 800 secondes CPU conservatrices après `INITED`. La couverture et
les 4 263 comparaisons déterministes Rust/Python sont acquises. La distribution
et le rejeu des 10 908 membres sont vérifiés. Le check global local passe
(514 tests Python sans ignoré, 313 entrées inchangées). La CI 43893183494
passe avec 514 tests par OS, sans ignoré, et les essais des originaux ;
la promotion Windows 002 est vérifiée après copie. C01 et le
gel cryptographique final ne sont pas déclarés clos. La revue extérieure,
chantier 5, demeure différée conformément à la demande de l'utilisateur.

**M09, 16 novembre 2026.** Les cinq chantiers sont exécutés dans le moteur :
contrats de graines et d'entropie, cycle des propriétaires secrets, sous-lemme
ROM précis, optimisation NTT mesurée et distribution/dossier de revue.
Le [bilan M09](M09_MOTEUR_CONTRATS_ET_QUALIFICATION.md) conserve le rejet du
candidat vectorisé et les résultats du candidat scalaire corrigé. Les formats
R1 sont inchangés ; C01 et l'audit extérieur restent ouverts. La clôture
du check complet et de la CI est acquise dans des reçus distincts :
439 tests Python exécutés par OS, sans test ignoré, CI 43806407492 ; aucun
temps des campagnes historiques n'est transféré. Android et Messenger demeurent différés.

Le [programme M04](PROGRAMME_AMELIORATION_M04.md) a été exécuté selon
l'ordre confirmé : trois travaux scientifiques, puis mémoire, NTT,
contrôles, distribution et comparaison directe. Le
[bilan M04](M04_MOTEUR_NTT_ET_CONTROLES.md) distingue les livraisons
obtenues des obligations IND-CCA concrètes et QROM encore ouvertes.

M06 poursuit le développement du cœur : transformées réutilisées,
accumulation NTT, contrôles des octets sur deux OS, mesures comparatives
et revue des propriétaires propre à ce code. Le
[protocole M06](PROTOCOLE_M06_MOTEUR.md), les
[mesures et leur coût mémoire](M06_MESURES_ET_DURCISSEMENT.md) et la
[contre-revue](M06_REVUE_INDEPENDANTE.md) identifient ce périmètre.
Le [rejet idéal](REJET_IMPLICITE_R1_M06.md) est désormais borné ; le PKE
à graines, les primitives concrètes et la marge de la réduction quantique
restent des travaux de C01. La hausse des frames a conduit aux mesures
instrumentées et à la réduction de mémoire M07, puis à sa livraison vérifiée.
M08 traite désormais les copies produites pendant l'import et élargit la
validation. Son [bilan livré](M08_IMPORTS_ET_VALIDATION.md) conserve les
mesures, la revue ciblée, la couverture, l'oracle, les paquets et la CI neuve
Windows/Ubuntu, avec les limites scientifiques et d'intégration explicites.

**Actualisation M01.** L'utilisateur demande ensuite d'avancer sur le
moteur sans attendre de nouvelle validation. Le [bilan opérationnel](BILAN_J2_ET_DECISION_PROTOTYPE.md)
autorise le prototype R1 en parallèle de J2. Les opérations et la seconde
réalisation sont maintenant disponibles ; le [guide du moteur](MOTEUR_KEM_R1.md)
consigne corpus, essais, commandes et limites. La décision ne sélectionne
pas un candidat final et ne valide aucun jalon encore ouvert.

## Livrables et état effectif

| Livrable | État | Critère vérifiable |
|---|---|---|
| Témoin ML-KEM-1024 | Implémenté séparément | Cas ACVP et échanges frais |
| Correction du rang 6 | P0 rejeté ; témoin q=7681/η=3/u exact/dv=5 certifié dans le modèle CBD | run-003/run-004, C04/C05 |
| Résistance estimée | Familles évaluées, hypothèses et limites du dual documentées | Bilan C02 à achever, sans niveau global acquis |
| Arithmétique polynomiale de référence | Première brique Rust disponible | Convolution indépendante, lois de l'anneau et signe X^256=−1 |
| Profil de développement du rang 6 | R1 spécifié comme base d'essai | Domaines/formats propres, sans sélection finale |
| KeyGen / Encaps / Decaps du rang 6 | Rust et référence Python disponibles | 1000 vecteurs concordants, 10000 échanges frais et rejets appariés |
| Durcissement et performances | M09 : contrats d'entropie, propriétaire final du message, NTT scalaire et revue ciblée des quatre images ; J4 ouvert | Corpus R1 inchangés, budgets finaux satisfaits et médianes 13,13–16,82 % plus basses contre M08 ; ni pile universelle, ni CT ou effacement global prouvés |
| Import de clés | M08 : quatre consommateurs API par défaut, 88576 sondes chacun | Formats/ordre des erreurs conservés ; les sondes ne couvrent pas tous les vecteurs et l'import ne certifie pas l'entropie |
| Distribution | Deux paquets M09 scalaires qualifiés en interne, originaux inventoriés, une répétition par hôte ; gel, check Windows, CI neuve Windows/Ubuntu et copie locale contrôlée acquis | Sources et licences ; Linux identique brut, Windows comparé hors timestamp COFF/checksum PE ; aucune reproduction par tiers revendiquée |

L'oracle générique dans Z_q[X]/(X^256+1) reste distinct du moteur.
Le cœur R1 emploie depuis [M02](DURCISSEMENT_MOTEUR_M02.md) une convolution
spécialisée en q=7681, des réciproques entières et des buffers fixes effacés.
Les corpus complets retrouvent les octets M01 sous Windows et Linux.
La NTT est réalisée depuis M04 et retrouve ces oracles. La preuve générale
de temps constant reste ouverte ; toute nouvelle optimisation doit garder
ces contrôles et sa propre revue de réalisation.

## Finir J2 avec un bilan de décision

Le bilan opérationnel reprend les exigences du cahier des charges une
par une. Il permet le codage exploratoire sur l'autorisation ultérieure
de l'utilisateur ; le dossier de validation de J2 reste à compléter.

| Exigence | Éléments déjà disponibles | Travail restant pour la décision |
|---|---|---|
| C01 : IND-CCA et hypothèses | Argument exact R1, raccords conditionnels M05, J idéal M06 et information latérale classique M08 | Avantages PKE à graines, indépendances du jeu visé, borne quantique plus serrée si nécessaire, primitives concrètes et constantes finales |
| C02 : comparaison des attaques | 30 paires strictes et quatre points dual/temps/mémoire/queue, veille conservée | Réoptimiser les compromis réellement réalisables et justifier les queues avant un niveau global |
| C03 : limites symétriques | Plafonds de recherche des graines/messages 256 bits écrits pour R1 | Quantifier les ressources et les effets multi-cibles dans un jeu choisi |
| C04/C05 : bruit et échecs | Rejet P0 ; certificat rationnel relié aux opérations et au pire message moyen-clé idéal | Transfert aux primitives concrètes et recherches adaptatives, pas de borne uniforme sur toute clé |
| C06 : compromis | Comparaisons à seuils communs run-007 | Consigner la décision, les tailles et les raisons de retenir ou écarter les variantes |

J2 n'exige pas de prétendre résoudre toutes les questions ouvertes de
cryptanalyse. Il exige un dossier explicite conforme à C01–C06. Une
question non résolue doit être classée pour sa conséquence sur le candidat
et le prototype, sans être automatiquement remplacée par une nouvelle
série d'expériences. Aucune conclusion de sécurité n'est présumée.

## Limite du volet H13

H13 borne les moments jusqu'à quatre à N=32 sur les listes figées, pour
déterminer ce que le témoin uniforme permet réellement de comparer.
Une fois ce résultat obtenu et contrôlé, arrêter cette extension : pas
de passage automatique à 64/128, pas de recherche automatique du sixième
moment. Les limites de queue et de dimension restent inscrites au bilan
C02, sans être effacées ni transformées en validation du modèle normal.

Le **bilan de développement J2 → J3** est désormais écrit et le prototype
est fonctionnel. M02 a traité la mémoire, l'arithmétique et une seconde
cible Linux/WSL, avec corpus malveillants et contrôle instrumenté.
M03 conserve les désassemblages intégraux et 60000 observations P01 ;
le fuzzing à couverture guidée de longue durée est lancé sur sa version
historique. M04 corrige M03-A01 et ajoute 532,44 s CPU instrumentées sur
la NTT, dont un complément de mutations API. Ces budgets restent séparés
de la campagne longue historique ; aucune revendication générale
d'effacement n'est ajoutée.
Le dossier cryptographique J2 continue
en parallèle, avec ses limites explicites.

## Ordre de construction du moteur

1. Arithmétique de référence et représentation canonique des polynômes.
   La convolution directe est disponible ; compléter les conversions
   et un oracle distinct avant les optimisations.
2. Encodages, compression/décompression et échantillonnages, selon le
   profil de développement qui sera consigné. Contrôler rejets, limites,
   séparation de domaine et compteurs ; réutiliser les primitives SHA3/SHAKE
   prévues au cahier des charges.
3. Parcours déterministes internes de référence, puis KeyGen, Encaps et
   Decaps de rang 6, selon l'autorisation expérimentale M01. Produire les vecteurs comparables
   entre les deux réalisations exigées par J3.
4. Interface d'application avec aléa système, types distincts, validation
   des entrées et rejet implicite. Les graines déterministes restent dans
   les interfaces de tests ; aucune clé d'application n'est importée.
5. Durcissement, mémoire et benchmarks des trois opérations, puis revue
   externe suivant le cahier des charges. Statut expérimental explicite.

Chaque étape de développement met à jour le journal et le rapport,
ajoute les vérifications utiles et livre du code exécutable ou un
critère de décision vérifiable. Aucun déploiement ou publication n'est
effectué implicitement.

## M07 — MAJAX R6, mémoire maîtrisée et livraison vérifiable

MAJAX R6 désigne le moteur expérimental de rang 6, soit six polynômes de
256 coefficients. Le profil d'essai reste `KEM1536-DEV-Q7681-R1`. Cette
section conserve les critères de sortie définis avant leur exécution.
Le [bilan M07](M07_MEMOIRE_ET_VALIDATION.md) consigne désormais les mesures,
les budgets satisfaits et les paquets vérifiés. Le contrôle complet Windows
passe à 227 tests Python. Les exécutants GitHub neufs Windows/Ubuntu passent
également, avec 227 tests chacun et essais natifs des deux paquets originaux ;
voir les [reçus de publication](../results/publication/r6-m07-001/).
Le jalon mémoire/livraison est clôturé dans ce périmètre ; le volet de sécurité
du point 5 conserve ses obligations ouvertes.

1. **Mesurer la mémoire réelle de M06.** Établir le pic dynamique de pile,
   les allocations et leurs tailles pour KeyGen, Encaps et Decaps valide
   ou rejetée, sous Windows et Linux. Consigner le compilateur, le harnais
   et ses limites. Les frames statiques LLVM et le RSS restent des mesures
   distinctes de ce pic.
2. **Comparer des espaces de travail détenus par l'opération.** Réemployer
   les buffers temporaires dans des propriétaires établis avant leur
   remplissage secret, avec durée de vie et effacement explicites. Évaluer
   le compromis pile/allocation sans cache secret persistant entre appels.
3. **Fixer les critères d'acceptation avant la comparaison.** Conserver
   exactement les octets R1 sur les corpus intégraux, les formats, domaines
   et comportements de rejet. Déclarer l'objectif mémoire et le budget de
   latence avant les mesures ; retenir une variante seulement si elle les
   respecte. Publier aussi les régressions et variantes écartées, avec les
   distributions de temps et les coûts mémoire effectivement observés.
4. **Contrôler les exécutables à livrer.** Effectuer les contrôles complets
   sur environnements neufs Windows/Ubuntu, reconstruire les paquets et
   rattacher chaque résultat au commit et aux SHA-256 réellement testés.
   Refaire la revue des copies, propriétaires et effacements sur ces mêmes
   binaires, y compris les chemins d'erreur examinés ; les constats par
   empreinte de M06 gardent leur propre périmètre. L'état distant de CI
   sera établi par les exécutions correspondantes, avec leurs journaux.
5. **Poursuivre le volet de sécurité séparément.** Le PKE à graines, les
   pertes et constantes du raccord FO, les primitives concrètes et une
   borne quantique de rejet plus serrée si nécessaire restent des travaux
   de C01. Les gains de mémoire ou de vitesse ne valident pas ces
   obligations, ni une preuve générale de temps constant ou d'effacement.

## M08 — imports directs et validation élargie, livré

Le [protocole M08](PROTOCOLE_M08_IMPORTS.md), les budgets et le plan sont
préenregistrés au commit `7ad5698`. Les captures gardent 46 entrées pour la
référence et 46 pour le candidat. Le cœur candidat `b39c2fdf…` conserve les
formats et domaines R1 ; les nouvelles acquisitions sont propres à cette
version et ne reçoivent aucun crédit des campagnes historiques.

1. **Contrôle d'import et compatibilité acquis.** Le validateur parcourt les
   encodages sans reconstruire de polynôme. Les corpus complets concordent
   sur Windows/Linux et les quatre consommateurs API passent leurs sondes.
   Les 300000 latences et 2880 observations mémoire satisfont 210 budgets.
2. **Revue ciblée scellée.** Les quatre consommateurs ont leurs images,
   inventaires physiques et 124 témoins adressés. Le retrait des copies
   de bits visées est qualifié sur les chemins examinés, avec les limites
   registres/ABI/PKE écrites. Les inventaires des CLI sont séparés.
3. **Campagne, couverture et rejeu acquis.** Les
   quatre harnais dépassent chacun 1800 secondes CPU nouvelles avec ASan
   et std reconstruite : 7256,67 secondes au total en 30 segments, sans
   défaut observé. L'union LLVM issue d'objets distincts sans std reconstruite
   couvre 438/604 lignes et 17/36 branches instrumentées ; les mappings nuls
   sont conservés. Les 3156 requêtes déterministes Rust/Python concordent,
   dont 433 sondes privées. L'interruption et la reprise de l'oracle sont
   tracées sans relancer ni créditer la campagne ou la couverture.
4. **Livraison, gel et intégration locale acquis.** Deux paquets livrent
   les originaux CLI inventoriés, avec une répétition comparée par hôte.
   Les notices du CLI et celles des neuf images diagnostiques sont vérifiées.
   Le gel
   conserve les 7520 fichiers et 428 répertoires ; son rejeu extrait passe.
   Le check Windows complet passe avec 352 tests Python, Rust/fmt/Clippy
   et rejeux. La CI neuve 43008567843 passe sur public b0491eb, avec 352
   tests Python par OS et des exécutions natives des originaux CLI/API.
   Le reçu r6-m08-001 distingue données rejouées et exécutions fraîches.
5. **C01 borné, sans clôture globale.** Le résultat figé M08 emploie une
   probabilité de devinette conditionnelle classique et des hypothèses
   d'indépendance explicites. La syntaxe de l'import ne démontre pas ces
   hypothèses ; le PKE à graines et les primitives concrètes restent ouverts.
