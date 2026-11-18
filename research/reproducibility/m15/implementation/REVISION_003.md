# Révision lexicale du contrôleur

La contre-revue a construit un faux corps de fonction commenté placé avant
un véritable corps modifié. La sélection du contrôleur initial recherchait
la signature avant le retrait des commentaires. Les sources de référence
ne contiennent pas ce piège, mais le contrat de refus des mutations était
incomplet. Le contre-exemple initial du relecteur reste conservé.

La version003 effectue désormais la sélection et le balancement d'accolades
sur un masque lexical qui conserve les positions et exclut commentaires,
chaînes normales/brutes et caractères. Les corps/constantes sont ensuite
interprétés dans le sous-ensemble déclaré. Les commentaires blocs restent
refusés dans ce sous-ensemble. Quatre mutations ciblées complètent les tests.

Les31 preuves sont acquises à nouveau dans acquisition-003, avec les
instruments exacts. Les acquisitions001/002 et leurs instruments restent
intacts. Cette correction touche l'outil de preuve privé, pas le moteur.
