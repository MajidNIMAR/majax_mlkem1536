//! Experimental R1 rank-six KEM. See docs/SPECIFICATION_DEV_Q7681_R1.md.
//! Functional reference, not a hardened or externally reviewed implementation.

use crate::engine_poly::{quotient, reduce_once, Polynomial as Poly, N as DEGREE};
use crate::secret_box::SecretBox;
use ctutils::{CtEq, CtSelect};
use sha3::{Digest, Sha3_256, Sha3_512};
use shake::{ExtendableOutput, Shake128, Shake256, Update, XofReader};
use zeroize::{Zeroize, Zeroizing};

pub const PROFILE: &str = "KEM1536-DEV-Q7681-R1";
pub const Q: u16 = 7681;
pub const RANK: usize = 6;
pub const PUBLIC_KEY_BYTES: usize = 2528;
pub const PRIVATE_KEY_BYTES: usize = 5088;
pub const CIPHERTEXT_BYTES: usize = 2656;
pub const SHARED_SECRET_BYTES: usize = 32;
const POLY_BYTES: usize = 416;
const VECTOR_BYTES: usize = RANK * POLY_BYTES;
const TAG: &[u8] = b"KEM1536-DEV-Q7681-R1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidLength,
    NoncanonicalEncoding,
    InconsistentPrivateKey,
    RandomnessUnavailable,
    SelfTestFailure,
}

#[derive(Clone)]
pub struct EncapsulationKey(Box<[u8; PUBLIC_KEY_BYTES]>);
pub struct DecapsulationKey(SecretBox<PRIVATE_KEY_BYTES>);
pub struct SharedSecret(Zeroizing<[u8; SHARED_SECRET_BYTES]>);
#[derive(Clone)]
pub struct Ciphertext(SecretBox<CIPHERTEXT_BYTES>);

impl EncapsulationKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PUBLIC_KEY_BYTES {
            return Err(Error::InvalidLength);
        }
        let mut checked = std::array::from_fn(|_| Poly::zero());
        decode_vector_into(&bytes[..VECTOR_BYTES], true, &mut checked)?;
        let mut key = Box::new([0; PUBLIC_KEY_BYTES]);
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}
impl DecapsulationKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PRIVATE_KEY_BYTES {
            return Err(Error::InvalidLength);
        }
        let mut checked = std::array::from_fn(|_| Poly::zero());
        decode_vector_into(&bytes[..VECTOR_BYTES], true, &mut checked)?;
        let ek =
            EncapsulationKey::from_bytes(&bytes[VECTOR_BYTES..VECTOR_BYTES + PUBLIC_KEY_BYTES])?;
        let offset = VECTOR_BYTES + PUBLIC_KEY_BYTES;
        if !bool::from(
            hash_public(ek.as_bytes())
                .as_slice()
                .ct_eq(&bytes[offset..offset + 32]),
        ) {
            return Err(Error::InconsistentPrivateKey);
        }
        let mut key = SecretBox::zero();
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }
    /// The returned expanded private encoding is wiped when its owner is dropped.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(vec![0; PRIVATE_KEY_BYTES]);
        out.copy_from_slice(&self.0[..]);
        out
    }
}
impl SharedSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn matches(&self, other: &Self) -> bool {
        bool::from(self.0.ct_eq(&other.0))
    }
}
impl Ciphertext {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != CIPHERTEXT_BYTES {
            return Err(Error::InvalidLength);
        }
        let mut c = SecretBox::zero();
        c.copy_from_slice(bytes);
        Ok(Self(c))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..]
    }
}

fn hash_public(ek: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, TAG);
    Digest::update(&mut h, b"H\0");
    Digest::update(&mut h, ek);
    h.finalize().into()
}
fn derive(label: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; 64]> {
    let mut h = Sha3_512::new();
    Digest::update(&mut h, TAG);
    Digest::update(&mut h, label);
    for p in parts {
        Digest::update(&mut h, p);
    }
    let mut digest = h.finalize();
    let mut out = Zeroizing::new([0; 64]);
    out.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
    out
}
fn xof<const L: usize>(label: &[u8], parts: &[&[u8]]) -> Zeroizing<[u8; L]> {
    let mut h = Shake256::default();
    h.update(TAG);
    h.update(label);
    for p in parts {
        h.update(p);
    }
    let mut out = Zeroizing::new([0; L]);
    h.finalize_xof().read(&mut out[..]);
    out
}
fn uniform(rho: &[u8], i: u8, j: u8) -> Poly {
    let mut h = Shake128::default();
    h.update(TAG);
    h.update(b"A\0");
    h.update(rho);
    h.update(&[i, j]);
    let mut reader = h.finalize_xof();
    let mut result = Poly::zero();
    result.fill_with(|_| loop {
        let mut pair = [0; 2];
        reader.read(&mut pair);
        let value = u16::from_le_bytes(pair) & 8191;
        if value < Q {
            break value;
        }
    });
    result // Public matrix coefficients only.
}
fn noise_into(seed: &[u8], nonce: u8, out: &mut Poly) {
    let bytes = xof::<192>(b"N\0", &[seed, &[nonce]]);
    out.fill_with(|j| {
        let bit = |k: usize| i32::from((bytes[k / 8] >> (k % 8)) & 1);
        let a = bit(6 * j) + bit(6 * j + 1) + bit(6 * j + 2);
        let b = bit(6 * j + 3) + bit(6 * j + 4) + bit(6 * j + 5);
        reduce_once((i32::from(Q) + a - b) as u32)
    });
}
fn pack_into(values: &[u16; DEGREE], width: usize, bytes: &mut [u8]) {
    bytes.fill(0);
    for (j, &value) in values.iter().enumerate() {
        for k in 0..width {
            let bit = j * width + k;
            bytes[bit / 8] |= (((value >> k) & 1) as u8) << (bit % 8);
        }
    }
}
#[cfg(any(test, feature = "research-vectors"))]
fn pack(values: &[u16; DEGREE], width: usize) -> Vec<u8> {
    let mut out = vec![0; DEGREE * width / 8];
    pack_into(values, width, &mut out);
    out
}
fn unpack_coefficient(bytes: &[u8], width: usize, j: usize) -> u16 {
    (0..width)
        .map(|k| {
            let bit = j * width + k;
            u16::from((bytes[bit / 8] >> (bit % 8)) & 1) << k
        })
        .sum()
}
#[cfg(test)]
fn unpack(bytes: &[u8], width: usize) -> [u16; DEGREE] {
    std::array::from_fn(|j| unpack_coefficient(bytes, width, j))
}
fn decode_vector_into(bytes: &[u8], strict: bool, result: &mut [Poly; RANK]) -> Result<(), Error> {
    if bytes.len() != VECTOR_BYTES {
        return Err(Error::InvalidLength);
    }
    let mut noncanonical = 0_u16;
    for (p, polynomial) in result.iter_mut().enumerate() {
        polynomial.fill_with(|j| {
            let v = unpack_coefficient(&bytes[p * POLY_BYTES..(p + 1) * POLY_BYTES], 13, j);
            // v is 13-bit (<2q). Scan all coefficients before the import decision.
            noncanonical |= ((u32::from(v).wrapping_sub(u32::from(Q)) >> 31) ^ 1) as u16;
            reduce_once(u32::from(v))
        });
    }
    if strict && noncanonical != 0 {
        return Err(Error::NoncanonicalEncoding);
    }
    Ok(())
}
fn encode_vector_into(vector: &[Poly; RANK], out: &mut [u8]) {
    for (i, p) in vector.iter().enumerate() {
        pack_into(
            p.coefficients(),
            13,
            &mut out[i * POLY_BYTES..(i + 1) * POLY_BYTES],
        );
    }
}
fn compress(x: u16, width: usize) -> u16 {
    (quotient((u32::from(x) << width) + u32::from(Q / 2)) & ((1 << width) - 1)) as u16
}
fn decompress(x: u16, width: usize) -> u16 {
    ((u32::from(x) * u32::from(Q) + (1 << (width - 1))) >> width) as u16
}
fn message_poly_into(message: &[u8; 32], out: &mut Poly) {
    out.fill_with(|i| decompress(u16::from((message[i / 8] >> (i % 8)) & 1), 1));
}
fn recover_message(p: &Poly) -> Zeroizing<[u8; 32]> {
    let mut m = Zeroizing::new([0; 32]);
    for (i, &x) in p.coefficients().iter().enumerate() {
        m[i / 8] |= (compress(x, 1) as u8) << (i % 8);
    }
    m
}
fn pke_keygen_into(d: &[u8; 32], s: &mut [Poly; RANK]) -> EncapsulationKey {
    let expanded = derive(b"KG\0", &[d, &[6]]);
    let (rho, sigma) = expanded.split_at(32);
    for (i, secret) in s.iter_mut().enumerate() {
        noise_into(sigma, i as u8, secret);
    }
    let mut t: [Poly; RANK] = std::array::from_fn(|_| Poly::zero());
    let mut product = Poly::zero();
    for (i, value) in t.iter_mut().enumerate() {
        noise_into(sigma, 6 + i as u8, value);
        for j in 0..6 {
            uniform(rho, i as u8, j).multiply_into(&s[j as usize], &mut product);
            value.add_assign(&product);
        }
    }
    let mut ek = Box::new([0; PUBLIC_KEY_BYTES]);
    encode_vector_into(&t, &mut ek[..VECTOR_BYTES]);
    ek[VECTOR_BYTES..].copy_from_slice(rho);
    EncapsulationKey(ek)
}
fn pke_encrypt_into(ek: &[u8], m: &[u8; 32], seed: &[u8], out: &mut [u8; CIPHERTEXT_BYTES]) {
    let mut t = std::array::from_fn(|_| Poly::zero());
    decode_vector_into(&ek[..VECTOR_BYTES], false, &mut t).expect("validated encapsulation key");
    let rho = &ek[VECTOR_BYTES..];
    let mut r: [Poly; RANK] = std::array::from_fn(|_| Poly::zero());
    for (i, randomness) in r.iter_mut().enumerate() {
        noise_into(seed, i as u8, randomness);
    }
    let mut u = std::array::from_fn(|_| Poly::zero());
    let mut product = Poly::zero();
    for (i, value) in u.iter_mut().enumerate() {
        noise_into(seed, 6 + i as u8, value);
        for j in 0..6 {
            uniform(rho, j, i as u8).multiply_into(&r[j as usize], &mut product);
            value.add_assign(&product);
        }
    }
    let mut v = Poly::zero();
    noise_into(seed, 12, &mut v);
    let mut message = Poly::zero();
    message_poly_into(m, &mut message);
    v.add_assign(&message);
    for i in 0..6 {
        t[i].multiply_into(&r[i], &mut product);
        v.add_assign(&product);
    }
    let mut compressed = Zeroizing::new([0; DEGREE]);
    for i in 0..DEGREE {
        compressed[i] = compress(v.coefficients()[i], 5);
    }
    encode_vector_into(&u, &mut out[..VECTOR_BYTES]);
    pack_into(&compressed, 5, &mut out[VECTOR_BYTES..]);
}
fn pke_encrypt(ek: &EncapsulationKey, m: &[u8; 32], seed: &[u8]) -> Ciphertext {
    let mut out = SecretBox::zero();
    pke_encrypt_into(ek.as_bytes(), m, seed, &mut out);
    Ciphertext(out)
}
fn pke_decrypt(sk: &[u8], c: &Ciphertext) -> Zeroizing<[u8; 32]> {
    let mut s = std::array::from_fn(|_| Poly::zero());
    decode_vector_into(sk, false, &mut s).expect("validated decapsulation key");
    // Noncanonical ciphertext coefficients are reduced internally; re-encryption
    // remains canonical and will force the implicit rejection path.
    let mut u = std::array::from_fn(|_| Poly::zero());
    decode_vector_into(&c.0[..VECTOR_BYTES], false, &mut u).expect("fixed ciphertext length");
    let mut v = Poly::zero();
    v.fill_with(|i| decompress(unpack_coefficient(&c.0[VECTOR_BYTES..], 5, i), 5));
    let mut product = Poly::zero();
    for i in 0..6 {
        s[i].multiply_into(&u[i], &mut product);
        v.subtract_assign(&product);
    }
    recover_message(&v)
}
fn keygen_internal(d: &[u8; 32], z: &[u8; 32]) -> (EncapsulationKey, DecapsulationKey) {
    let mut s = std::array::from_fn(|_| Poly::zero());
    let ek = pke_keygen_into(d, &mut s);
    let mut sk = SecretBox::zero();
    encode_vector_into(&s, &mut sk[..VECTOR_BYTES]);
    sk[VECTOR_BYTES..VECTOR_BYTES + PUBLIC_KEY_BYTES].copy_from_slice(ek.as_bytes());
    sk[VECTOR_BYTES + PUBLIC_KEY_BYTES..PRIVATE_KEY_BYTES - 32]
        .copy_from_slice(&hash_public(ek.as_bytes()));
    sk[PRIVATE_KEY_BYTES - 32..].copy_from_slice(z);
    (ek, DecapsulationKey(sk))
}
fn encaps_internal(ek: &EncapsulationKey, m: &[u8; 32]) -> (Ciphertext, SharedSecret) {
    let material = derive(b"G\0", &[m, &hash_public(ek.as_bytes())]);
    let c = pke_encrypt(ek, m, &material[32..]);
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&material[..32]);
    (c, SharedSecret(key))
}

/// OS randomness only. The deterministic test interface is disabled by default.
fn random_bytes<const N: usize>(
    fill: impl FnOnce(&mut [u8]) -> Result<(), Error>,
) -> Result<Zeroizing<[u8; N]>, Error> {
    let mut bytes = Zeroizing::new([0; N]);
    fill(bytes.as_mut())?;
    Ok(bytes)
}
pub fn keygen() -> Result<(EncapsulationKey, DecapsulationKey), Error> {
    let seeds =
        random_bytes::<64>(|out| getrandom::fill(out).map_err(|_| Error::RandomnessUnavailable))?;
    Ok(keygen_internal(
        seeds[..32].try_into().expect("32 bytes"),
        seeds[32..].try_into().expect("32 bytes"),
    ))
}
pub fn encapsulate(ek: &EncapsulationKey) -> Result<(Ciphertext, SharedSecret), Error> {
    let m =
        random_bytes::<32>(|out| getrandom::fill(out).map_err(|_| Error::RandomnessUnavailable))?;
    Ok(encaps_internal(ek, &m))
}
pub fn decapsulate(dk: &DecapsulationKey, c: &Ciphertext) -> SharedSecret {
    let ek = &dk.0[VECTOR_BYTES..VECTOR_BYTES + PUBLIC_KEY_BYTES];
    let offset = VECTOR_BYTES + PUBLIC_KEY_BYTES;
    let m = pke_decrypt(&dk.0[..VECTOR_BYTES], c);
    let material = derive(b"G\0", &[&m[..], &dk.0[offset..offset + 32]]);
    let mut cp = Zeroizing::new([0; CIPHERTEXT_BYTES]);
    pke_encrypt_into(ek, &m, &material[32..], &mut cp);
    let fallback = xof::<32>(b"J\0", &[&dk.0[offset + 32..], c.as_bytes()]);
    let mut good = Zeroizing::new([0; 32]);
    good.copy_from_slice(&material[..32]);
    SharedSecret(Zeroizing::new(
        (*fallback).ct_select(&*good, c.as_bytes().ct_eq(&cp[..])),
    ))
}

#[cfg(feature = "research-vectors")]
#[path = "dev_hardening.rs"]
pub mod hardening;

#[derive(serde::Serialize)]
pub struct Diagnostics {
    pub profile: &'static str,
    pub fresh_round_trips: usize,
    pub implicit_rejections_checked: usize,
    pub elapsed_seconds: f64,
    pub security_validation: &'static str,
    pub secrets_printed: bool,
}

/// Functional diagnostics using fresh OS randomness, with no secret output.
pub fn run_diagnostics(rounds: usize) -> Result<Diagnostics, Error> {
    let start = std::time::Instant::now();
    for i in 0..rounds {
        let (ek, dk) = keygen()?;
        let (c, key) = encapsulate(&ek)?;
        if !decapsulate(&dk, &c).matches(&key) {
            return Err(Error::SelfTestFailure);
        }
        let mut altered = c.clone();
        altered.0[0] = 255;
        altered.0[1] |= 31;
        altered.0[CIPHERTEXT_BYTES - 8..].copy_from_slice(&(i as u64).to_le_bytes());
        let rejected = decapsulate(&dk, &altered);
        let expected = xof::<32>(
            b"J\0",
            &[&dk.0[PRIVATE_KEY_BYTES - 32..], altered.as_bytes()],
        );
        if !bool::from(rejected.as_bytes().as_slice().ct_eq(&expected[..])) {
            return Err(Error::SelfTestFailure);
        }
    }
    Ok(Diagnostics {
        profile: PROFILE,
        fresh_round_trips: rounds,
        implicit_rejections_checked: rounds,
        elapsed_seconds: start.elapsed().as_secs_f64(),
        security_validation: "pending",
        secrets_printed: false,
    })
}

/// Only public, synthetic case numbers are accepted by this opt-in test facility.
#[cfg(feature = "research-vectors")]
pub mod research_vectors {
    use super::*;
    #[derive(serde::Serialize)]
    pub struct Vector {
        pub case: u32,
        pub d: Vec<u8>,
        pub z: Vec<u8>,
        pub m: Vec<u8>,
        pub ek: Vec<u8>,
        pub dk: Vec<u8>,
        pub ciphertext: Vec<u8>,
        pub shared: Vec<u8>,
        pub rejected_shared: Vec<u8>,
        pub rho: Vec<u8>,
        pub sigma: Vec<u8>,
        pub a00: Vec<u8>,
    }
    pub fn generate(case: u32) -> Vector {
        let seeds = xof::<96>(b"TEST\0", &[&case.to_le_bytes()]);
        let d = seeds[..32].try_into().expect("32 bytes");
        let z = seeds[32..64].try_into().expect("32 bytes");
        let m = seeds[64..].try_into().expect("32 bytes");
        let (ek, dk) = keygen_internal(d, z);
        let (ciphertext, shared) = encaps_internal(&ek, m);
        assert!(decapsulate(&dk, &ciphertext).matches(&shared));
        let mut altered = ciphertext.clone();
        altered.0[0] = 255;
        altered.0[1] |= 31;
        let rejected = decapsulate(&dk, &altered);
        let expected = xof::<32>(b"J\0", &[z, altered.as_bytes()]);
        assert_eq!(rejected.as_bytes().as_slice(), &expected[..]);
        let expanded = derive(b"KG\0", &[d, &[6]]);
        Vector {
            case,
            d: d.to_vec(),
            z: z.to_vec(),
            m: m.to_vec(),
            ek: ek.as_bytes().to_vec(),
            dk: dk.0.to_vec(),
            ciphertext: ciphertext.as_bytes().to_vec(),
            shared: shared.as_bytes().to_vec(),
            rejected_shared: rejected.as_bytes().to_vec(),
            rho: expanded[..32].to_vec(),
            sigma: expanded[32..].to_vec(),
            a00: pack(uniform(&expanded[..32], 0, 0).coefficients(), 13),
        }
    }

    #[derive(serde::Serialize)]
    pub struct RejectionVector {
        pub case: u32,
        pub shared: Vec<u8>,
    }

    pub fn rejections(count: u32) -> impl Iterator<Item = RejectionVector> {
        let seeds = xof::<96>(b"TEST\0", &[&0_u32.to_le_bytes()]);
        let d = seeds[..32].try_into().expect("32 bytes");
        let z = seeds[32..64].try_into().expect("32 bytes");
        let m = seeds[64..].try_into().expect("32 bytes");
        let (ek, dk) = keygen_internal(d, z);
        let (ciphertext, _) = encaps_internal(&ek, m);
        (0..count).map(move |i| {
            let mut bad = ciphertext.clone();
            bad.0[0] = 255;
            bad.0[1] |= 31;
            bad.0[CIPHERTEXT_BYTES - 8..].copy_from_slice(&u64::from(i).to_le_bytes());
            let shared = decapsulate(&dk, &bad);
            RejectionVector {
                case: i,
                shared: shared.as_bytes().to_vec(),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "research-vectors")]
    #[test]
    fn current_engine_matches_independently_verified_case0() {
        let v = research_vectors::generate(0);
        let mut h = Sha3_256::new();
        for bytes in [
            &v.d,
            &v.z,
            &v.m,
            &v.ek,
            &v.dk,
            &v.ciphertext,
            &v.shared,
            &v.rejected_shared,
            &v.rho,
            &v.sigma,
            &v.a00,
        ] {
            Digest::update(&mut h, bytes);
        }
        // SHA3-256 of the eleven byte fields in the frozen, Python-verified case 0.
        let expected = [
            176, 95, 219, 161, 45, 186, 114, 85, 118, 63, 80, 216, 172, 188, 2, 0, 213, 169, 25,
            160, 190, 42, 228, 106, 253, 12, 181, 212, 95, 25, 59, 250,
        ];
        assert_eq!(h.finalize().as_slice(), &expected);
    }
    #[test]
    fn entropy_failure_is_propagated() {
        assert!(matches!(
            random_bytes::<64>(|_| Err(Error::RandomnessUnavailable)),
            Err(Error::RandomnessUnavailable)
        ));
    }
    #[test]
    fn full_deterministic_roundtrip_and_rejection() {
        let (ek, dk) = keygen_internal(&[7; 32], &[9; 32]);
        let (c, k) = encaps_internal(&ek, &[11; 32]);
        assert!(decapsulate(&dk, &c).matches(&k));
        assert_eq!(
            (ek.as_bytes().len(), dk.to_bytes().len(), c.as_bytes().len()),
            (2528, 5088, 2656)
        );
        let imported = DecapsulationKey::from_bytes(&dk.to_bytes()).unwrap();
        assert!(decapsulate(&imported, &c).matches(&k));
        let mut malformed = c.as_bytes().to_vec();
        malformed[0] = 255;
        malformed[1] |= 31;
        let rejected = decapsulate(&dk, &Ciphertext::from_bytes(&malformed).unwrap());
        assert_eq!(
            rejected.as_bytes().as_slice(),
            &xof::<32>(b"J\0", &[&[9; 32], &malformed])[..]
        );
    }
    #[test]
    fn canonical_boundaries_and_private_hash_validation() {
        let (ek, dk) = keygen_internal(&[1; 32], &[2; 32]);
        for length in [0, 1, PUBLIC_KEY_BYTES - 1, PUBLIC_KEY_BYTES + 1] {
            assert!(EncapsulationKey::from_bytes(&vec![0; length]).is_err());
        }
        for length in [0, 1, PRIVATE_KEY_BYTES - 1, PRIVATE_KEY_BYTES + 1] {
            assert!(DecapsulationKey::from_bytes(&vec![0; length]).is_err());
        }
        for length in [0, 1, CIPHERTEXT_BYTES - 1, CIPHERTEXT_BYTES + 1] {
            assert!(Ciphertext::from_bytes(&vec![0; length]).is_err());
        }
        let mut bad = ek.as_bytes().to_vec();
        bad[0] = 255;
        bad[1] |= 31;
        assert!(matches!(
            EncapsulationKey::from_bytes(&bad),
            Err(Error::NoncanonicalEncoding)
        ));
        let mut bad = dk.to_bytes();
        bad[VECTOR_BYTES + PUBLIC_KEY_BYTES] ^= 1;
        assert!(matches!(
            DecapsulationKey::from_bytes(&bad),
            Err(Error::InconsistentPrivateKey)
        ));
        for distance in 1..=32 {
            for n in [PUBLIC_KEY_BYTES - distance, PUBLIC_KEY_BYTES + distance] {
                assert!(matches!(
                    EncapsulationKey::from_bytes(&vec![0; n]),
                    Err(Error::InvalidLength)
                ));
            }
            for n in [PRIVATE_KEY_BYTES - distance, PRIVATE_KEY_BYTES + distance] {
                assert!(matches!(
                    DecapsulationKey::from_bytes(&vec![0; n]),
                    Err(Error::InvalidLength)
                ));
            }
            for n in [CIPHERTEXT_BYTES - distance, CIPHERTEXT_BYTES + distance] {
                assert!(matches!(
                    Ciphertext::from_bytes(&vec![0; n]),
                    Err(Error::InvalidLength)
                ));
            }
        }
        let mut bad = dk.to_bytes();
        let mut last = [0; 256];
        last[255] = 8191;
        bad[VECTOR_BYTES - POLY_BYTES..VECTOR_BYTES].copy_from_slice(&pack(&last, 13));
        assert!(matches!(
            DecapsulationKey::from_bytes(&bad),
            Err(Error::NoncanonicalEncoding)
        ));
    }

    #[test]
    fn canonical_bad_ciphertext_and_last_noncanonical_coefficient_reject() {
        let (ek, dk) = keygen_internal(&[31; 32], &[41; 32]);
        let empty = Ciphertext::from_bytes(&vec![0; CIPHERTEXT_BYTES]).unwrap();
        let m = pke_decrypt(&dk.0[..VECTOR_BYTES], &empty);
        let coins = derive(b"G\0", &[&m[..], &hash_public(ek.as_bytes())]);
        assert_ne!(
            pke_encrypt(&ek, &m, &coins[32..]).as_bytes(),
            empty.as_bytes()
        );
        assert_eq!(
            decapsulate(&dk, &empty).as_bytes().as_slice(),
            &xof::<32>(b"J\0", &[&[41; 32], empty.as_bytes()])[..]
        );
        let (mut c, _) = encaps_internal(&ek, &[51; 32]);
        let offset = VECTOR_BYTES - POLY_BYTES;
        let mut p = unpack(&c.0[offset..VECTOR_BYTES], 13);
        p[255] = 8191;
        c.0[offset..VECTOR_BYTES].copy_from_slice(&pack(&p, 13));
        assert_eq!(
            decapsulate(&dk, &c).as_bytes().as_slice(),
            &xof::<32>(b"J\0", &[&[41; 32], c.as_bytes()])[..]
        );
    }
    #[test]
    fn packing_and_rounding_exhaustive() {
        for d in [1, 5, 13] {
            for value in 0..(1_u16 << d) {
                assert_eq!(unpack(&pack(&[value; 256], d), d), [value; 256]);
            }
        }
        for x in 0..Q {
            for d in [1, 5] {
                let got = decompress(compress(x, d), d);
                let diff = (i32::from(got) - i32::from(x)).rem_euclid(i32::from(Q));
                assert!(diff.min(i32::from(Q) - diff) <= i32::from(Q) / (1 << (d + 1)) + 1);
            }
        }
    }
    #[test]
    fn operating_system_randomness_roundtrip() {
        let (ek, dk) = keygen().unwrap();
        let (c, k) = encapsulate(&ek).unwrap();
        assert!(decapsulate(&dk, &c).matches(&k));
    }
}
