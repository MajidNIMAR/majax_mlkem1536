"""Explicit M09-to-M08 reviewed call-site correspondence, not a Rust proof.

Each substitution is required verbatim before the existing M08 semantics
anchors are applied. No historical source or expected result is rewritten.
"""
import re


def flat(text):
    return re.sub(r"\s+", "", text)


def correspondence(source):
    text = flat(source)
    anchors = [
        "struct KeygenNoise<'a>(&'a [u8; 32]);",
        "struct EncryptionCoins<'a>(&'a [u8; 32]);",
        '''fn seed_tail(material: &[u8; 64]) -> &[u8; 32] {
            material[32..].try_into().expect("fixed 32-byte seed view")
        }''',
        '''fn row_nonce(row: usize, offset: u8) -> u8 {
            assert!(row < RANK, "noise row outside the fixed rank");
            offset + row as u8
        }''',
        '''impl KeygenNoise<'_> {
            fn secret_row_into(&self, row: usize, out: &mut Poly) {
                noise_into(self.0, row_nonce(row, 0), out);
            }
            fn error_row_into(&self, row: usize, out: &mut Poly) {
                noise_into(self.0, row_nonce(row, RANK as u8), out);
            }
        }''',
        '''impl EncryptionCoins<'_> {
            fn random_row_into(&self, row: usize, out: &mut Poly) {
                noise_into(self.0, row_nonce(row, 0), out);
            }
            fn error_row_into(&self, row: usize, out: &mut Poly) {
                noise_into(self.0, row_nonce(row, RANK as u8), out);
            }
            fn scalar_error_into(&self, out: &mut Poly) {
                noise_into(self.0, (2 * RANK) as u8, out);
            }
        }''',
        '''fn recover_message_into(p: &Poly, m: &mut [u8; 32]) {
            m.fill(0);
            for (i, &x) in p.coefficients().iter().enumerate() {
                m[i / 8] |= (compress(x, 1) as u8) << (i % 8);
            }
        }''',
        '''fn fill_entropy_into<const N: usize>(bytes: &mut [u8; N],
            fill: impl FnOnce(&mut [u8]) -> Result<(), Error>,) -> Result<(), Error> {
            // Wipe even partial writes before propagating the provider's error.
            if let Err(error) = fill(bytes.as_mut()) {
                bytes.zeroize(); return Err(error);
            }
            Ok(())
        }''',
        '''pub fn keygen() -> Result<(EncapsulationKey, DecapsulationKey), Error> {
            keygen_with_entropy(|out| getrandom::fill(out).map_err(|_| Error::RandomnessUnavailable))
        }''',
        '''let mut seeds = Zeroizing::new([0; 64]);
            fill_entropy_into(&mut seeds, fill)?;
            Ok(keygen_internal(seeds[..32].try_into().expect("32 bytes"),
                seeds[32..].try_into().expect("32 bytes"),))''',
        '''pub fn encapsulate(ek: &EncapsulationKey) -> Result<(Ciphertext, SharedSecret), Error> {
            encapsulate_with_entropy(ek, |out| {
                getrandom::fill(out).map_err(|_| Error::RandomnessUnavailable)
            })
        }''',
        '''let mut m = Zeroizing::new([0; 32]);
            fill_entropy_into(&mut m, fill)?;
            Ok(encaps_internal(ek, &m))''',
        '''let mut m = Zeroizing::new([0; 32]);
            pke_decrypt_into(&dk.0[..VECTOR_BYTES], c, &mut m);''',
        '''pke_encrypt_into(ek, &m, &EncryptionCoins(seed_tail(&material)), &mut cp);''',
        '''let c = pke_encrypt(ek, m, &EncryptionCoins(seed_tail(&material)));''',
        '''impl Clone for Ciphertext {
            fn clone(&self) -> Self {
                let mut out = SecretBox::zero();
                out.copy_from_slice(&self.0[..]); Self(out)
            }
        }''',
    ]
    for fragment in anchors:
        if flat(fragment) not in text:
            raise ValueError("reviewed R1 source contract changed; M09 review required: " + flat(fragment))
    substitutions = (
        ("fn noise_into(seed: &[u8; 32], nonce: u8, out: &mut Poly)",
         "fn noise_into(seed: &[u8], nonce: u8, out: &mut Poly)"),
        ("let rho = &expanded[..32]; let sigma = KeygenNoise(seed_tail(&expanded));",
         "let (rho, sigma) = expanded.split_at(32);"),
        ("sigma.secret_row_into(i, &mut coefficient);", "noise_into(sigma, i as u8, &mut coefficient);"),
        ("sigma.error_row_into(i, &mut coefficient);", "noise_into(sigma, 6 + i as u8, &mut coefficient);"),
        ("fn pke_encrypt_into(ek: &[u8], m: &[u8; 32], seed: &EncryptionCoins<'_>, out: &mut [u8; CIPHERTEXT_BYTES],)",
         "fn pke_encrypt_into(ek: &[u8], m: &[u8; 32], seed: &[u8], out: &mut [u8; CIPHERTEXT_BYTES])"),
        ("seed.random_row_into(i, &mut coefficient);", "noise_into(seed, i as u8, &mut coefficient);"),
        ("seed.error_row_into(i, &mut coefficient);", "noise_into(seed, 6 + i as u8, &mut coefficient);"),
        ("seed.scalar_error_into(&mut coefficient);", "noise_into(seed, 12, &mut coefficient);"),
        ("fn pke_decrypt_into(sk: &[u8], c: &Ciphertext, message: &mut [u8; 32])",
         "fn pke_decrypt(sk: &[u8], c: &Ciphertext) -> Zeroizing<[u8; 32]>"),
        ("recover_message_into(&v, message);", "recover_message(&v)"),
    )
    for before, after in substitutions:
        before, after = flat(before), flat(after)
        if text.count(before) != 1:
            raise ValueError("reviewed R1 source contract changed; M09 correspondence missing/ambiguous: " + before)
        text = text.replace(before, after, 1)
    return text, len(anchors) + len(substitutions)
