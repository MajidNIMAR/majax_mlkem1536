# Tests libFuzzer de R1

Workspace distinct réservé aux tests. `fixtures/cases.bin` concatène les
16 premiers cas synthétiques publics M01 : ek (2528), dk développé (5088),
chiffré (2656), secret (32), soit 10304 octets par cas. Aucune clé réelle.
Le moteur est importé **sans** research-vectors. Les sorties de fuzzing
vivantes vont dans artifacts/generated ; les corpus finaux sont archivés
avec un manifeste quand la campagne se termine.

Les oracles vérifient import/export, longueurs, déterminisme de Decaps,
échanges honnêtes et remplacement indépendant pour u non canonique.
Ils ne supposent pas que toute mutation canonique est rejetée. Les
entrées retenues seront aussi confrontées à Python pour le bilan final.

Les séquences d'API utilisent un sélecteur de clé puis au plus 16 opérations
de quatre octets (opération, offset little-endian, masque XOR). Les échanges
honnêtes utilisent l'aléa système : cette partie ne donne pas une trajectoire
strictement déterministe de couverture à partir de la seule graine libFuzzer.
