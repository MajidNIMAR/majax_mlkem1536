# Vecteurs de test

Les vecteurs du témoin ML-KEM-1024 et ceux du candidat 1536 seront conservés séparément. Pour chaque jeu, enregistrer la source, sa version ou son commit, l’empreinte du fichier, les conditions de licence et la commande de vérification.

Les vecteurs officiels importés sont conservés dans `nist-acvp/` avec le manifeste de provenance sous `references/`. Les six fichiers couvrent les jeux KeyGen FIPS203, encapDecap FIPS203 et encapDecap FIPS203-tr1. Ils contiennent aussi les autres paramètres standards, conservés pour préserver les fichiers originaux ; le témoin sélectionne uniquement ML-KEM-1024.

La sélection comprend 25 cas de génération, 50 d’encapsulation, 30 de décapsulation et 40 de contrôle des clés, soit 145 cas. Parmi les décapsulations, 15 sorties correspondent au secret de rejet implicite ; ce décompte est vérifié indépendamment en Python.

```powershell
.\scripts\dev.ps1 reference
```

Cette commande compare les sorties du témoin aux résultats attendus et exécute 32 parcours supplémentaires avec des clés fraîches. Les clés et graines présentes dans les fichiers ACVP sont des données publiques de test.

Les futurs vecteurs 1536 seront des vecteurs du projet, avec des graines de test publiques clairement identifiées.

