//! Only public synthetic M01 fixtures, without enabling research APIs in R1.
use kem1536::dev_kem::{self as r1, Ciphertext, DecapsulationKey, EncapsulationKey, Error};
use shake::{ExtendableOutput, Shake256, Update, XofReader};
use std::sync::OnceLock;

const FIXTURES: &[u8; 164864] = include_bytes!("../fixtures/cases.bin");
const RECORD: usize = 10304;
const TAG: &[u8] = b"KEM1536-DEV-Q7681-R1\0";

struct Fixture {
    ek: EncapsulationKey,
    dk: DecapsulationKey,
    ciphertext: Ciphertext,
    shared: [u8; 32],
}
static KEYS: OnceLock<Vec<Fixture>> = OnceLock::new();
fn fixtures() -> &'static [Fixture] {
    KEYS.get_or_init(|| {
        FIXTURES
            .chunks_exact(RECORD)
            .map(|raw| Fixture {
                ek: EncapsulationKey::from_bytes(&raw[..2528]).unwrap(),
                dk: DecapsulationKey::from_bytes(&raw[2528..7616]).unwrap(),
                ciphertext: Ciphertext::from_bytes(&raw[7616..10272]).unwrap(),
                shared: raw[10272..].try_into().unwrap(),
            })
            .collect()
    })
}

pub fn import_public(data: &[u8]) {
    match EncapsulationKey::from_bytes(data) {
        Ok(key) => {
            assert_eq!(data.len(), r1::PUBLIC_KEY_BYTES);
            assert_eq!(data, key.as_bytes());
            assert_eq!(
                EncapsulationKey::from_bytes(key.as_bytes())
                    .unwrap()
                    .as_bytes(),
                data
            );
        }
        Err(e) if data.len() != r1::PUBLIC_KEY_BYTES => assert_eq!(e, Error::InvalidLength),
        Err(_) => (),
    }
}

pub fn import_private(data: &[u8]) {
    match DecapsulationKey::from_bytes(data) {
        Ok(key) => {
            assert_eq!(data.len(), r1::PRIVATE_KEY_BYTES);
            assert_eq!(data, &key.to_bytes()[..]);
            let c = &fixtures()[0].ciphertext;
            let a = r1::decapsulate(&key, c);
            assert!(a.matches(&r1::decapsulate(&key, c)));
        }
        Err(e) if data.len() != r1::PRIVATE_KEY_BYTES => assert_eq!(e, Error::InvalidLength),
        Err(_) => (),
    }
}

pub fn decapsulate(data: &[u8]) {
    let Some((&selector, raw)) = data.split_first() else {
        return;
    };
    let c = match Ciphertext::from_bytes(raw) {
        Ok(c) => c,
        Err(e) => {
            assert_ne!(raw.len(), r1::CIPHERTEXT_BYTES);
            assert_eq!(e, Error::InvalidLength);
            return;
        }
    };
    let index = usize::from(selector) % 16;
    let f = &fixtures()[index];
    let actual = r1::decapsulate(&f.dk, &c);
    assert!(actual.matches(&r1::decapsulate(&f.dk, &c)));
    if raw == f.ciphertext.as_bytes() {
        assert_eq!(actual.as_bytes(), &f.shared);
    }
    // Decode 13-bit coefficients independently of the engine's decoder.
    let noncanonical = (0..1536).any(|j| {
        let mut coefficient = 0_u16;
        for bit in 0..13 {
            let position = j * 13 + bit;
            coefficient |= u16::from((raw[position / 8] >> (position % 8)) & 1) << bit;
        }
        coefficient >= 7681
    });
    if noncanonical {
        let base = index * RECORD;
        let z = &FIXTURES[base + 2528 + 5088 - 32..base + 2528 + 5088];
        let mut h = Shake256::default();
        h.update(TAG);
        h.update(b"J\0");
        h.update(z);
        h.update(raw);
        let mut expected = [0; 32];
        h.finalize_xof().read(&mut expected);
        assert_eq!(actual.as_bytes(), &expected);
    }
}

pub fn api_sequence(data: &[u8]) {
    let Some((&selector, steps)) = data.split_first() else {
        return;
    };
    let f = &fixtures()[usize::from(selector) % 16];
    // Public bounded interpreter: offsets, mutations, import/export and honest exchanges.
    for step in steps.chunks(4).take(16) {
        if step.len() != 4 {
            break;
        }
        let offset = usize::from(u16::from_le_bytes([step[1], step[2]]));
        match step[0] % 4 {
            0 => {
                let mut raw = f.ek.as_bytes().to_vec();
                let i = offset % raw.len();
                raw[i] ^= step[3];
                import_public(&raw);
            }
            1 => {
                let mut raw = f.dk.to_bytes();
                let i = offset % raw.len();
                raw[i] ^= step[3];
                import_private(&raw);
            }
            2 => {
                let mut raw = vec![selector];
                raw.extend_from_slice(f.ciphertext.as_bytes());
                raw[1 + offset % r1::CIPHERTEXT_BYTES] ^= step[3];
                decapsulate(&raw);
            }
            _ => {
                // Fresh system randomness: no deterministic application entry point.
                let (ek, dk) = if step[3] & 1 != 0 {
                    r1::keygen().unwrap()
                } else {
                    (
                        EncapsulationKey::from_bytes(f.ek.as_bytes()).unwrap(),
                        DecapsulationKey::from_bytes(&f.dk.to_bytes()).unwrap(),
                    )
                };
                let (c, s) = r1::encapsulate(&ek).unwrap();
                assert!(s.matches(&r1::decapsulate(&dk, &c)));
                let copied = Ciphertext::from_bytes(c.clone().as_bytes()).unwrap();
                assert!(s.matches(&r1::decapsulate(&dk, &copied)));
            }
        }
    }
}
