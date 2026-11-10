# Third-party material

The Apache-2.0 project license applies to original contributions. It does
not relicense the third-party material described below.

- Rust dependencies are downloaded through Cargo, rather than vendored.
  `Cargo.lock` preserves exact versions and registry checksums. The separate
  ML-KEM-1024 comparison uses RustCrypto `ml-kem 0.3.3`; its Apache-2.0 and
  MIT license texts are preserved in `references/`.
- NIST publications, errata and public ACVP test data have the source URLs
  and hashes recorded in `references/manifest.json`. The ACVP notice is in
  `vectors/nist-acvp/NIST-NOTICE.txt`.
- The archived article by Aurélie Duriez and Christophe Tommasini,
  *Dependency-Aware ROM/CBD Correctness Bounds for ML-KEM-768 at the
  Heuristic Failure Scale*, arXiv:2609.09983v1, is identified as CC BY 4.0
  in the original HTML. Attribution, source URL and hash are preserved in
  `references/correctness-2026/manifest.json`. The archived HTML is unchanged.
- Historical coded-dual source excerpts have no established redistribution
  license. The public export includes their URLs and hashes, but omits the
  three `references/coded-dual-audit/*.py.txt` files. Research setup retrieves
  them directly from their immutable upstream revisions and verifies their
  hashes. They are reference data, not the R1 engine or a Cargo dependency.
- The older `pq-crystals/security-estimates` tools likewise remain outside
  the public tree and are fetched into an ignored local cache. See
  `research/tools-manifest.json`.
- Other external numerical reference outputs retain the provenance recorded
  in their accompanying manifests. Their presence does not imply external
  review or endorsement of this project.

Copies of this project's own earlier sources inside `results/engine/` are
historical project contributions. Existing notices embedded in any source
or reference remain applicable.

## Original reference-implementation attribution

Le témoin utilise le paquet `ml-kem`, version 0.3.3, développé par les
RustCrypto Developers et distribué sous `Apache-2.0 OR MIT`. Son code n'est
pas présenté comme une création de ce projet. Les licences originales sont
conservées dans `references/RustCrypto-ml-kem-LICENSE-MIT` et
`references/RustCrypto-ml-kem-LICENSE-APACHE`. Le checksum du paquet est
inscrit dans `references/manifest.json` et vérifié contre `Cargo.lock`.

Les données ACVP proviennent du National Institute of Standards and
Technology, dépôt `usnistgov/ACVP-Server`, au commit
`975de31eb83d87039ec88934fdc47d8c312b892d`. Les six fichiers JSON sont
conservés sans modification. La section de licence du README de ce commit
est reproduite intégralement dans `vectors/nist-acvp/NIST-NOTICE.txt`.
Le PDF FIPS 203 et les errata proviennent des URLs officielles consignées
dans le manifeste. Les comparaisons sont hors ligne, sans session ACVP
de validation ni approbation du NIST.

Une future distribution de binaires devra conserver les notices requises
par l'ensemble des dépendances embarquées.
