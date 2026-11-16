# Qualification du candidat M09 complet

Préenregistrement du 16 novembre 2026, avant capture et mesures du
candidat complet. La variante arithmétique isolée a déjà été mesurée :
son témoin multiply_add Linux dépasse le seuil de médiane de 10 % ;
elle n'est pas intégralement acceptée. Ce constat reste conservé. La
présente décision concerne le moteur KEM complet avec contrats, cycle
secret et tables publiques, dans ses images propres.

Référence : source M08 capturée avant tout changement M09 dans
`m09-poly-001/baseline-source`. Candidat complet : nouvelle capture par
`research/run_m09_qualification.py`. Aucun nouveau seuil n'est appliqué
rétroactivement aux microbenchmarks isolés.

Comparer les quatre opérations KEM avec le même programme M07 inchangé,
par cinq séries AB/BA de 500 observations et 100 échauffements. Un CPU
logique fixé (10), OS séparés, aucun filtrage ni rerun sélectionné. Les
outils/caches sont partagés ; fréquence et isolation globale non garanties.
Par opération et OS, médiane ≤1,05 fois la référence et p95 ≤1,20.
Pour retenir l'optimisation, au moins une médiane KEM doit gagner 5 % sur
chaque OS. Aucun gain général de multiply_add n'est revendiqué.

Mémoire : même probe M08 compilé à neuf sur référence et candidat, trois
répétitions × deux peintures × 18 opérations par OS. La pile touchée
maximale du candidat doit rester ≤ maximum référence +1024 octets pour
chacune des 14 opérations hors calibrations/noop. Les comptes de requêtes
d'allocation, les octets demandés et retenus ne doivent pas augmenter.
Les calibrations et la saturation doivent être validées. La profondeur
peinte n'est ni une borne universelle de pile, ni RSS ; 512 octets au
sommet ne sont pas peints. Les tables publiques ajoutent 1020 octets à la
source ; la hausse de frame transform Linux déjà observée (+96 octets
dans le microbinaire) reste visible dans le bilan.

Les vecteurs complets (1000), rejets (10000), mutations (10000) et
formats (20000) doivent réussir sur les deux images de recherche, avec
oracle Python gelé pour les mutations et égalité aux corpus historiques.
Le consommateur par défaut vérifie son propre import/exhaustion, et
le CLI par défaut ses 16 échanges/rejets et cinq refus de commandes
de recherche. Inventorier les quatre images originales CLI/consommateur.

Diagnostic temporel neuf : 8 clés × 5 classes × 400 observations par OS,
aucune exclusion. Rapporter tout franchissement de |t|≥4,5 ; un
franchissement exige une enquête et ne s'efface pas par rerun. Même
absence de signal ne démontre pas le temps constant.

La qualification comprend le check complet du projet et la CI fraîche
Windows/Ubuntu après publication du code. Le dossier externe distingue
les contrôles internes de l'audit tiers non réalisé. Aucune seconde
campagne longue ASan/LLVM M08 n'est attribuée à M09 ; les limites de
couverture de la nouvelle réalisation sont explicites.
