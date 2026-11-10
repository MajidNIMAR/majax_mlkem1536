# Consommateur R1 : KEM, HKDF-SHA256 et AES-256-GCM

Exemple local autonome, avec son verrou Cargo, utilisant exclusivement l'API
publique R1 sans `research-vectors`. Il dérive une clé directionnelle liée
au profil, à la clé publique et au chiffré KEM. Il chiffre un seul message
par clé dérivée, avec un nonce de 96 bits fourni par le système, puis vérifie
six altérations : données, tag, contexte associé, nonce, encapsulation et clé
privée différente. Aucune clé ni aucun secret n'est imprimé ou écrit.

```powershell
cargo test --locked --manifest-path examples/r1-channel-demo/Cargo.toml
cargo run --locked --release --manifest-path examples/r1-channel-demo/Cargo.toml
```

La clé publique du destinataire est supposée authentifiée par l'application.
Le KEM ne prouve pas l'identité de l'émetteur : toute personne ayant cette
clé publique peut encapsuler. Cet exemple ne définit ni messagerie, ni
protection anti-rejeu, ni rotation de sessions, ni protocole de signature.
Il illustre une composition, pas une preuve de sécurité du KEM R1.

Les tableaux de clés dérivées utilisent `Zeroizing`, et le moteur AES est
compilé avec la fonction d'effacement de sa dépendance. Cela ne prouve pas
l'effacement de toutes les copies internes de HKDF, des registres ou du
compilateur. Les dépendances de cet exemple sont distinctes de celles du
moteur R1 livré. Les versions RustCrypto sont verrouillées :
[HKDF 0.13.0](https://docs.rs/hkdf/0.13.0/hkdf/),
[AES-GCM 0.11.1](https://docs.rs/aes-gcm/0.11.1/aes_gcm/).
