# Rejeu des assertions, indépendant des noms locaux de sérialisation

Le relecteur a confirmé que les31 assertions capturées et reconstruites
ont des AST Z3 strictement égaux, bien que leurs sérialisations textuelles
diffèrent dans les noms des sous-expressions locales. L'ancien test
d'égalité de texte refusait donc un rejeu sémantiquement identique.

La version005 conserve le contrôle SHA256 des octets originaux, parse le
SMT-LIB, exige l'égalité structurelle typée de chaque assertion et refait
UNSAT sur les obligations reconstruites. Un changement de prédicat est
refusé même s'il est lui-même prouvable ; un alias local cosmétique est
accepté. Le lot005 capture les instruments finaux et refait les31preuves.

Les anciens lots et le journal d'échec du rejeu restent conservés. Il ne
s'agissait ni d'un contre-exemple arithmétique ni d'un défaut du moteur.
