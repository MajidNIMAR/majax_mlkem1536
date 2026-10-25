# Publication du moteur sur GitHub

Le dépôt public est `MajidNIMAR/majax_mlkem1536`, distinct de
`MajidNIMAR/majax-mlkem1024-demo`. Il présente le développement expérimental
du moteur `KEM1536-DEV-Q7681-R1`, ses sources, sa spécification et les
résultats conservés. Il ne partage pas l'architecture opérationnelle de
Majax Messenger. La licence des contributions propres est Apache-2.0,
comme dans le démonstrateur 1024.

## Source de la publication

Le dossier local de recherche reste `NIST`. `research/export_publication.py`
exporte exclusivement les fichiers d'un commit Git dans un nouveau dossier
sous `artifacts/generated/publication/`. Les outils locaux, caches, clés
d'application, sorties vivantes et base Git locale ne sont pas exportés.
L'export refuse de remplacer un dossier existant.

`PUBLICATION_PROVENANCE.json`, ajouté à l'export, donne le commit local,
les exclusions et les SHA-256 de chaque fichier exporté. Le dépôt GitHub
commence par cet instantané public : les identifiants de commits historiques
cités dans les protocoles sont ceux de l'historique local, et ne constituent
pas des liens GitHub publics ou une preuve de préenregistrement public.
Les sources archivées et empreintes permettent d'examiner les résultats
conservés indépendamment de cet historique.

Les instructions locales `AGENTS.md` et trois copies de sources externes
sans licence de redistribution établie sont exclues. Les originaux de la
recherche locale et les instantanés figés ne sont pas modifiés. Les trois
copies externes se récupèrent directement chez leur auteur au moyen de
`research/fetch_reference_copies.py --fetch`, appelé par la préparation de
l'environnement de recherche. Leurs URLs de révision et empreintes restent
publiées. Le script n'exécute pas ces fichiers de référence.

## Vérification depuis une copie propre

Suivre les commandes Windows ou Linux du README. Le démarrage Rust suffit
à l'auto-test du moteur. Le contrôle complet nécessite aussi la préparation
Python/NumPy et des références externes. La CI réalise ces deux préparations
avant `dev check` sur Windows et Ubuntu.

La vérification locale de publication doit compiler les seuls fichiers
exportés dans une nouvelle cible, puis exécuter l'auto-test et le contrôle
complet. Si les outils et caches du poste sont réutilisés pour cette
vérification, le rapport doit le dire : ce n'est pas une installation à
neuf sur une autre machine. Les exécutants GitHub apportent un contrôle
supplémentaire depuis le dépôt public et son état effectif doit être lu.

La reproductibilité fonctionnelle des vecteurs ne démontre pas que deux
compilations produisent des binaires identiques octet par octet. Aucune
signature de release, certification, adoption externe ou clôture de la
campagne longue n'est annoncée par cette première publication.

## Vérification initiale conservée

La [preuve de publication initiale](../results/publication/initial-001/)
conserve les journaux complets et le manifeste des sources testées du commit
local e2e9bc9. Reconstruction release dans une cible neuve, auto-test de
16 échanges/16 rejets et contrôle complet terminés avec code 0. Les outils
et caches locaux ont été réutilisés. La copie finale ajoute les présentes
précisions documentaires et ces preuves sans modifier le moteur, les scripts,
les paramètres ou la CI testés. Le statut distant effectif se lit dans Actions.
