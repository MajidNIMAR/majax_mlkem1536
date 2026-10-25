//! Experimental R1 rank-six KEM. See docs/SPECIFICATION_DEV_Q7681_R1.md.
//! Functional reference, not a hardened or externally reviewed implementation.

use crate::reference_ring::{ReferencePolynomial, DEGREE};
use ctutils::{CtEq, CtSelect};
use sha3::{Digest, Sha3_256, Sha3_512};
use shake::{ExtendableOutput, Shake128, Shake256, Update, XofReader};
use zeroize::Zeroizing;

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
type Poly = ReferencePolynomial<Q>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidLength,
    NoncanonicalEncoding,
    InconsistentPrivateKey,
    RandomnessUnavailable,
    SelfTestFailure,
}

#[derive(Clone)]
pub struct EncapsulationKey(Vec<u8>);
pub struct DecapsulationKey(Zeroizing<Vec<u8>>);
pub struct SharedSecret(Zeroizing<[u8; SHARED_SECRET_BYTES]>);
#[derive(Clone)]
pub struct Ciphertext(Vec<u8>);

impl EncapsulationKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PUBLIC_KEY_BYTES {
            return Err(Error::InvalidLength);
        }
        decode_vector(&bytes[..VECTOR_BYTES], true)?;
        Ok(Self(bytes.to_vec()))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl DecapsulationKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PRIVATE_KEY_BYTES {
            return Err(Error::InvalidLength);
        }
        decode_vector(&bytes[..VECTOR_BYTES], true)?;
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
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }
    /// The returned expanded private encoding is wiped when its owner is dropped.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_vec())
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
        Ok(Self(bytes.to_vec()))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

fn polynomial(values: [u16; DEGREE]) -> Poly {
    Poly::from_coefficients(values).expect("internally reduced coefficients")
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
    Zeroizing::new(h.finalize().into())
}
fn xof(label: &[u8], parts: &[&[u8]], length: usize) -> Zeroizing<Vec<u8>> {
    let mut h = Shake256::default();
    h.update(TAG);
    h.update(label);
    for p in parts {
        h.update(p);
    }
    let mut out = Zeroizing::new(vec![0; length]);
    h.finalize_xof().read(&mut out);
    out
}
fn uniform(rho: &[u8], i: u8, j: u8) -> Poly {
    let mut h = Shake128::default();
    h.update(TAG);
    h.update(b"A\0");
    h.update(rho);
    h.update(&[i, j]);
    let mut reader = h.finalize_xof();
    let mut a = [0; DEGREE];
    let mut index = 0;
    while index < DEGREE {
        let mut pair = [0; 2];
        reader.read(&mut pair);
        let value = u16::from_le_bytes(pair) & 8191;
        if value < Q {
            a[index] = value;
            index += 1;
        }
    }
    polynomial(a)
}
fn noise(seed: &[u8], nonce: u8) -> Poly {
    let bytes = xof(b"N\0", &[seed, &[nonce]], 192);
    let values = std::array::from_fn(|j| {
        let bit = |k: usize| i32::from((bytes[k / 8] >> (k % 8)) & 1);
        let a = bit(6 * j) + bit(6 * j + 1) + bit(6 * j + 2);
        let b = bit(6 * j + 3) + bit(6 * j + 4) + bit(6 * j + 5);
        (a - b).rem_euclid(i32::from(Q)) as u16
    });
    polynomial(values)
}
fn pack(values: &[u16; DEGREE], width: usize) -> Vec<u8> {
    let mut bytes = vec![0; DEGREE * width / 8];
    for (j, &value) in values.iter().enumerate() {
        for k in 0..width {
            let bit = j * width + k;
            bytes[bit / 8] |= (((value >> k) & 1) as u8) << (bit % 8);
        }
    }
    bytes
}
fn unpack(bytes: &[u8], width: usize) -> [u16; DEGREE] {
    std::array::from_fn(|j| {
        (0..width)
            .map(|k| {
                let bit = j * width + k;
                u16::from((bytes[bit / 8] >> (bit % 8)) & 1) << k
            })
            .sum()
    })
}
fn decode_vector(bytes: &[u8], strict: bool) -> Result<Vec<Poly>, Error> {
    if bytes.len() != VECTOR_BYTES {
        return Err(Error::InvalidLength);
    }
    bytes
        .chunks_exact(POLY_BYTES)
        .map(|p| {
            let mut a = Zeroizing::new(unpack(p, 13));
            if strict && a.iter().any(|&v| v >= Q) {
                return Err(Error::NoncanonicalEncoding);
            }
            for v in a.iter_mut() {
                *v %= Q;
            }
            Ok(polynomial(*a))
        })
        .collect()
}
fn encode_vector(vector: &[Poly]) -> Vec<u8> {
    vector
        .iter()
        .flat_map(|p| pack(p.coefficients(), 13))
        .collect()
}
fn compress(x: u16, width: usize) -> u16 {
    ((((u32::from(x) << width) + u32::from(Q / 2)) / u32::from(Q)) & ((1 << width) - 1)) as u16
}
fn decompress(x: u16, width: usize) -> u16 {
    ((u32::from(x) * u32::from(Q) + (1 << (width - 1))) >> width) as u16
}
fn message_poly(message: &[u8; 32]) -> Poly {
    polynomial(std::array::from_fn(|i| {
        decompress(u16::from((message[i / 8] >> (i % 8)) & 1), 1)
    }))
}
fn recover_message(p: &Poly) -> Zeroizing<[u8; 32]> {
    let mut m = Zeroizing::new([0; 32]);
    for (i, &x) in p.coefficients().iter().enumerate() {
        m[i / 8] |= (compress(x, 1) as u8) << (i % 8);
    }
    m
}
fn pke_keygen(d: &[u8; 32]) -> (EncapsulationKey, Zeroizing<Vec<u8>>) {
    let expanded = derive(b"KG\0", &[d, &[6]]);
    let (rho, sigma) = expanded.split_at(32);
    let s: Vec<_> = (0..6).map(|i| noise(sigma, i)).collect();
    let t: Vec<_> = (0..6)
        .map(|i| {
            let mut value = noise(sigma, 6 + i);
            for j in 0..6 {
                value = value.add(&uniform(rho, i, j).multiply(&s[j as usize]));
            }
            value
        })
        .collect();
    let mut ek = encode_vector(&t);
    ek.extend_from_slice(rho);
    (EncapsulationKey(ek), Zeroizing::new(encode_vector(&s)))
}
fn pke_encrypt(ek: &EncapsulationKey, m: &[u8; 32], seed: &[u8]) -> Ciphertext {
    let t = decode_vector(&ek.0[..VECTOR_BYTES], true).expect("validated encapsulation key");
    let rho = &ek.0[VECTOR_BYTES..];
    let r: Vec<_> = (0..6).map(|i| noise(seed, i)).collect();
    let u: Vec<_> = (0..6)
        .map(|i| {
            let mut value = noise(seed, 6 + i);
            for j in 0..6 {
                value = value.add(&uniform(rho, j, i).multiply(&r[j as usize]));
            }
            value
        })
        .collect();
    let mut v = noise(seed, 12).add(&message_poly(m));
    for i in 0..6 {
        v = v.add(&t[i].multiply(&r[i]));
    }
    let compressed = std::array::from_fn(|i| compress(v.coefficients()[i], 5));
    let mut c = encode_vector(&u);
    c.extend(pack(&compressed, 5));
    Ciphertext(c)
}
fn pke_decrypt(sk: &[u8], c: &Ciphertext) -> Zeroizing<[u8; 32]> {
    let s = decode_vector(sk, true).expect("validated decapsulation key");
    // Noncanonical ciphertext coefficients are reduced internally; re-encryption
    // remains canonical and will force the implicit rejection path.
    let u = decode_vector(&c.0[..VECTOR_BYTES], false).expect("fixed ciphertext length");
    let packed = unpack(&c.0[VECTOR_BYTES..], 5);
    let mut v = polynomial(packed.map(|x| decompress(x, 5)));
    for i in 0..6 {
        v = v.subtract(&s[i].multiply(&u[i]));
    }
    recover_message(&v)
}
fn keygen_internal(d: &[u8; 32], z: &[u8; 32]) -> (EncapsulationKey, DecapsulationKey) {
    let (ek, mut sk) = pke_keygen(d);
    sk.extend_from_slice(ek.as_bytes());
    sk.extend_from_slice(&hash_public(ek.as_bytes()));
    sk.extend_from_slice(z);
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
    let ek = EncapsulationKey(dk.0[VECTOR_BYTES..VECTOR_BYTES + PUBLIC_KEY_BYTES].to_vec());
    let offset = VECTOR_BYTES + PUBLIC_KEY_BYTES;
    let m = pke_decrypt(&dk.0[..VECTOR_BYTES], c);
    let material = derive(b"G\0", &[&m[..], &dk.0[offset..offset + 32]]);
    let cp = pke_encrypt(&ek, &m, &material[32..]);
    let fallback = xof(b"J\0", &[&dk.0[offset + 32..], c.as_bytes()], 32);
    let mut good = Zeroizing::new([0; 32]);
    good.copy_from_slice(&material[..32]);
    let mut bad = Zeroizing::new([0; 32]);
    bad.copy_from_slice(&fallback);
    SharedSecret(Zeroizing::new(
        (*bad).ct_select(&*good, c.as_bytes().ct_eq(cp.as_bytes())),
    ))
}

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
        let expected = xof(
            b"J\0",
            &[&dk.0[PRIVATE_KEY_BYTES - 32..], altered.as_bytes()],
            32,
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
        let seeds = xof(b"TEST\0", &[&case.to_le_bytes()], 96);
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
        let expected = xof(b"J\0", &[z, altered.as_bytes()], 32);
        assert_eq!(rejected.as_bytes().as_slice(), &expected[..]);
        let expanded = derive(b"KG\0", &[d, &[6]]);
        Vector {
            case,
            d: d.to_vec(),
            z: z.to_vec(),
            m: m.to_vec(),
            ek: ek.0,
            dk: dk.0.to_vec(),
            ciphertext: ciphertext.0,
            shared: shared.as_bytes().to_vec(),
            rejected_shared: rejected.as_bytes().to_vec(),
            rho: expanded[..32].to_vec(),
            sigma: expanded[32..].to_vec(),
            a00: pack(uniform(&expanded[..32], 0, 0).coefficients(), 13),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let mut malformed = c.0.clone();
        malformed[0] = 255;
        malformed[1] |= 31;
        let rejected = decapsulate(&dk, &Ciphertext::from_bytes(&malformed).unwrap());
        assert_eq!(
            rejected.as_bytes().as_slice(),
            &xof(b"J\0", &[&[9; 32], &malformed], 32)[..]
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
        let mut bad = ek.0.clone();
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
