# Révision de la liaison source

La revue interne a demandé deux contrôles supplémentaires de traduction :
l'égalité des Q locaux et la liaison d'import des fonctions arithmétiques.
Ils étaient vrais dans les sources capturées, mais une mutation future du
seul module KEM n'aurait pas été correctement interprétée ou refusée.

La version002 ajoute ces gardes, deux tests de mutation et la capture des
instruments dans l'acquisition. Elle refait les31 obligations universelles.
La première acquisition001 et les octets exacts de ses instruments sont
conservés. Les résultats ne décrivent aucun défaut du moteur, dont les
sources et le binaire n'ont pas changé. La version002 fait autorité.
