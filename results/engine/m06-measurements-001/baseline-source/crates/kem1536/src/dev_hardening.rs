//! Research-only synthetic robustness and timing fixtures. No application secrets.
use super::*;

const FORMAT_SEED: u64 = 0x4d30_322d_464f_524d;
const MUTATION_SEED: u64 = 0x4d30_322d_4d55_5441;
const TIMING_SEED: u64 = 0x4d30_322d_5449_4d45;

fn next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}
fn fill(state: &mut u64, bytes: &mut [u8]) {
    for chunk in bytes.chunks_mut(8) {
        let word = next(state).to_le_bytes();
        chunk.copy_from_slice(&word[..chunk.len()]);
    }
}
fn fixture() -> (EncapsulationKey, DecapsulationKey, Ciphertext) {
    let seed = xof::<96>(b"TEST\0", &[&0_u32.to_le_bytes()]);
    let (ek, dk) = keygen_internal(
        seed[..32].try_into().unwrap(),
        seed[32..64].try_into().unwrap(),
    );
    let (c, _) = encaps_internal(&ek, seed[64..].try_into().unwrap());
    (ek, dk, c)
}

#[derive(serde::Serialize)]
pub struct FormatReport {
    pub inputs: usize,
    pub public_key_imports: usize,
    pub private_key_imports: usize,
    pub ciphertext_imports: usize,
    pub wrong_lengths_rejected: usize,
    pub exact_length_inputs: usize,
    pub accepted_imports: usize,
    pub seed: u64,
    pub panics_observed: usize,
}
pub fn formats() -> FormatReport {
    let mut state = FORMAT_SEED;
    let mut report = FormatReport {
        inputs: 20000,
        public_key_imports: 0,
        private_key_imports: 0,
        ciphertext_imports: 0,
        wrong_lengths_rejected: 0,
        exact_length_inputs: 0,
        accepted_imports: 0,
        seed: FORMAT_SEED,
        panics_observed: 0,
    };
    for i in 0..20000 {
        let kind = i % 3;
        let expected = [PUBLIC_KEY_BYTES, PRIVATE_KEY_BYTES, CIPHERTEXT_BYTES][kind];
        let length = if i % 7 == 0 {
            expected
        } else {
            expected - 64 + (next(&mut state) % 129) as usize
        };
        let mut raw = vec![0; length];
        fill(&mut state, &mut raw);
        let result = match kind {
            0 => {
                report.public_key_imports += 1;
                EncapsulationKey::from_bytes(&raw).map(|v| assert_eq!(v.as_bytes(), raw))
            }
            1 => {
                report.private_key_imports += 1;
                DecapsulationKey::from_bytes(&raw).map(|v| assert_eq!(&v.to_bytes()[..], raw))
            }
            _ => {
                report.ciphertext_imports += 1;
                Ciphertext::from_bytes(&raw).map(|v| assert_eq!(v.as_bytes(), raw))
            }
        };
        if length != expected {
            assert_eq!(result, Err(Error::InvalidLength));
            report.wrong_lengths_rejected += 1;
        } else {
            report.exact_length_inputs += 1;
            if result.is_ok() {
                report.accepted_imports += 1;
            }
        }
    }
    report
}

#[derive(serde::Serialize)]
pub struct Mutation {
    pub case: u32,
    pub class: u32,
    pub ciphertext: Vec<u8>,
    pub shared: Vec<u8>,
    pub accepted: bool,
}
pub fn mutations() -> impl Iterator<Item = Mutation> {
    let (ek, dk, base) = fixture();
    let mut state = MUTATION_SEED;
    (0..10000_u32).map(move |i| {
        let class = i % 5;
        let mut raw = base.as_bytes().to_vec();
        match class {
            0 => {
                raw[0] = 255;
                raw[1] |= 31;
                raw[CIPHERTEXT_BYTES - 8..].copy_from_slice(&u64::from(i).to_le_bytes());
            }
            1 => raw.fill(0),
            2 => {
                let bit = (next(&mut state) % (160 * 8)) as usize;
                raw[VECTOR_BYTES + bit / 8] ^= 1 << (bit % 8);
            }
            3 => {
                fill(&mut state, &mut raw);
                for j in 0..RANK {
                    let values = std::array::from_fn(|_| (next(&mut state) % u64::from(Q)) as u16);
                    pack_into(&values, 13, &mut raw[j * POLY_BYTES..(j + 1) * POLY_BYTES]);
                }
            }
            _ => {
                let position = (next(&mut state) % 1536) as usize;
                let p = position / 256;
                let mut values = unpack_public(&raw[p * POLY_BYTES..(p + 1) * POLY_BYTES]);
                values[position % 256] = Q;
                pack_into(&values, 13, &mut raw[p * POLY_BYTES..(p + 1) * POLY_BYTES]);
            }
        }
        let c = Ciphertext::from_bytes(&raw).unwrap();
        let secret = decapsulate(&dk, &c);
        // Independent acceptance tracing stays inside this synthetic research build.
        let message = pke_decrypt(&dk.0[..VECTOR_BYTES], &c);
        let coins = derive(b"G\0", &[&message[..], &hash_public(ek.as_bytes())]);
        let expected = pke_encrypt(&ek, &message, &coins[32..]);
        let accepted = expected.as_bytes() == c.as_bytes();
        if !accepted {
            assert_eq!(
                secret.as_bytes().as_slice(),
                &xof::<32>(b"J\0", &[&dk.0[PRIVATE_KEY_BYTES - 32..], &raw])[..]
            );
        }
        Mutation {
            case: i,
            class,
            ciphertext: raw,
            shared: secret.as_bytes().to_vec(),
            accepted,
        }
    })
}
fn unpack_public(raw: &[u8]) -> [u16; 256] {
    std::array::from_fn(|i| unpack_coefficient(raw, 13, i))
}

#[derive(serde::Serialize)]
pub struct TimingRow {
    pub sequence: usize,
    pub class: usize,
    pub nanoseconds: u64,
}
pub fn timing() -> Vec<TimingRow> {
    use std::hint::black_box;
    let (_, dk, valid) = fixture();
    let canonical = Ciphertext::from_bytes(&[0; CIPHERTEXT_BYTES]).unwrap();
    let mut bad = valid.clone();
    bad.0[0] = 255;
    bad.0[1] |= 31;
    let classes = [valid, canonical, bad];
    for i in 0..100 {
        black_box(decapsulate(&dk, black_box(&classes[i % 3])));
    }
    let mut order: Vec<_> = (0..3)
        .flat_map(|class| std::iter::repeat_n(class, 2000))
        .collect();
    let mut state = TIMING_SEED;
    for i in (1..order.len()).rev() {
        let j = (next(&mut state) % (i as u64 + 1)) as usize;
        order.swap(i, j);
    }
    let mut rows = Vec::with_capacity(order.len());
    for (sequence, class) in order.into_iter().enumerate() {
        let start = std::time::Instant::now();
        let secret = black_box(decapsulate(&dk, black_box(&classes[class])));
        black_box(secret.as_bytes());
        let nanoseconds = start.elapsed().as_nanos() as u64;
        rows.push(TimingRow {
            sequence,
            class,
            nanoseconds,
        });
    }
    rows
}

#[inline(never)]
pub fn reduce_probe(x: u64) -> u16 {
    crate::engine_poly::reduce_wide(std::hint::black_box(x))
}
#[inline(never)]
pub fn quotient_probe(x: u32) -> u32 {
    quotient(std::hint::black_box(x))
}
