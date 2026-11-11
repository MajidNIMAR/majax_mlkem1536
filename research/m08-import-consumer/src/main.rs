//! Default-feature consumer retaining the actual R1 import API for M08 review.
//! All encoded fixtures are synthetic. No key encoding or shared secret is printed.

use kem1536::dev_kem::{self as r1, DecapsulationKey, EncapsulationKey, Error};
use serde_json::json;
use sha3::{Digest, Sha3_256};
use std::hint::black_box;
use std::time::Instant;
use zeroize::Zeroizing;

const DEGREE: usize = 256;
const VECTOR_COEFFICIENTS: usize = 6 * DEGREE;
const VECTOR_BYTES: usize = VECTOR_COEFFICIENTS * 13 / 8;
const PUBLIC_OFFSET: usize = VECTOR_BYTES;
const HASH_OFFSET: usize = VECTOR_BYTES + r1::PUBLIC_KEY_BYTES;

// These wrappers deliberately survive optimisation as callers of the normal API.
// A compiler may inline from_bytes or its helpers inside them; the complete
// emitted wrapper/callee closure, rather than one assumed symbol, is reviewed.
#[inline(never)]
pub fn import_public_probe(bytes: &[u8]) -> Result<EncapsulationKey, Error> {
    EncapsulationKey::from_bytes(black_box(bytes))
}

#[inline(never)]
pub fn import_private_probe(bytes: &[u8]) -> Result<DecapsulationKey, Error> {
    DecapsulationKey::from_bytes(black_box(bytes))
}

fn error_code(error: Error) -> u8 {
    match error {
        Error::InvalidLength => 1,
        Error::NoncanonicalEncoding => 2,
        Error::InconsistentPrivateKey => 3,
        Error::RandomnessUnavailable => 4,
        Error::SelfTestFailure => 5,
    }
}

fn public_status(result: Result<EncapsulationKey, Error>, input: &[u8]) -> u8 {
    match result {
        Ok(key) => {
            assert!(key.as_bytes() == input, "public import changed encoding");
            black_box(&key);
            0
        }
        Err(error) => error_code(error),
    }
}

fn private_status(result: Result<DecapsulationKey, Error>, input: &[u8]) -> u8 {
    match result {
        Ok(key) => {
            // This validation allocation and both owner drops are outside timing.
            let copied = key.to_bytes();
            assert!(&copied[..] == input, "private import changed encoding");
            black_box(&key);
            0
        }
        Err(error) => error_code(error),
    }
}

// Intentionally independent of the production encoder/decoder: one-bit writes.
fn set_coefficient(bytes: &mut [u8], position: usize, value: u16) {
    assert!(position < VECTOR_COEFFICIENTS && value < 8192);
    for bit in 0..13 {
        let index = 13 * position + bit;
        let mask = 1_u8 << (index % 8);
        bytes[index / 8] =
            (bytes[index / 8] & !mask) | ((((value >> bit) & 1) as u8) << (index % 8));
    }
}

fn refresh_public_hash(private: &mut [u8]) {
    let mut hash = Sha3_256::new();
    hash.update(b"KEM1536-DEV-Q7681-R1\0");
    hash.update(b"H\0");
    hash.update(&private[PUBLIC_OFFSET..HASH_OFFSET]);
    private[HASH_OFFSET..HASH_OFFSET + 32].copy_from_slice(&hash.finalize());
}

fn fixture_encodings() -> (Vec<u8>, Zeroizing<Vec<u8>>) {
    let mut public = vec![0_u8; r1::PUBLIC_KEY_BYTES];
    let mut private = Zeroizing::new(vec![0_u8; r1::PRIVATE_KEY_BYTES]);
    for position in 0..VECTOR_COEFFICIENTS {
        set_coefficient(
            &mut public[..VECTOR_BYTES],
            position,
            ((17 * position + 37) % 7681) as u16,
        );
        let signed = (position % 7) as i32 - 3;
        set_coefficient(
            &mut private[..VECTOR_BYTES],
            position,
            ((7681 + signed) % 7681) as u16,
        );
    }
    public[VECTOR_BYTES..].fill(17);
    private[PUBLIC_OFFSET..HASH_OFFSET].copy_from_slice(&public);
    private[HASH_OFFSET + 32..].fill(201);
    refresh_public_hash(&mut private);
    (public, private)
}

struct Case {
    name: &'static str,
    private: bool,
    bytes: Zeroizing<Vec<u8>>,
    expected: u8,
}

impl Case {
    fn public(name: &'static str, bytes: &[u8], expected: u8) -> Self {
        Self {
            name,
            private: false,
            bytes: Zeroizing::new(bytes.to_vec()),
            expected,
        }
    }

    fn private(name: &'static str, bytes: &[u8], expected: u8) -> Self {
        Self {
            name,
            private: true,
            bytes: Zeroizing::new(bytes.to_vec()),
            expected,
        }
    }

    fn observe(&self) -> u8 {
        if self.private {
            private_status(import_private_probe(&self.bytes), &self.bytes)
        } else {
            public_status(import_public_probe(&self.bytes), &self.bytes)
        }
    }
}

fn cases() -> Vec<Case> {
    let (public, private) = fixture_encodings();
    let mut cases = vec![
        Case::public("public_valid", &public, 0),
        Case::public("public_noncanonical_first", &public, 2),
        Case::public("public_noncanonical_last", &public, 2),
        Case::private("private_valid", &private, 0),
        Case::private("private_secret_noncanonical_first", &private, 2),
        Case::private("private_secret_noncanonical_last", &private, 2),
        Case::private("private_public_noncanonical", &private, 2),
        Case::private("private_hash_invalid", &private, 3),
        Case::private("private_secret_and_hash_invalid", &private, 2),
        Case::private("private_public_and_hash_invalid", &private, 2),
        Case::private("private_secret_and_public_invalid", &private, 2),
        Case::public("public_short", &public[..7], 1),
        Case::private("private_short", &private[..7], 1),
    ];
    set_coefficient(&mut cases[1].bytes, 0, 7681);
    set_coefficient(&mut cases[2].bytes, VECTOR_COEFFICIENTS - 1, 8191);
    set_coefficient(&mut cases[4].bytes, 0, 7681);
    set_coefficient(&mut cases[5].bytes, VECTOR_COEFFICIENTS - 1, 8191);
    set_coefficient(&mut cases[6].bytes[PUBLIC_OFFSET..HASH_OFFSET], 0, 7681);
    cases[7].bytes[HASH_OFFSET] ^= 1;
    set_coefficient(&mut cases[8].bytes, 0, 7681);
    cases[8].bytes[HASH_OFFSET] ^= 1;
    set_coefficient(&mut cases[9].bytes[PUBLIC_OFFSET..HASH_OFFSET], 0, 7681);
    cases[9].bytes[HASH_OFFSET] ^= 1;
    set_coefficient(&mut cases[10].bytes, 0, 7681);
    set_coefficient(&mut cases[10].bytes[PUBLIC_OFFSET..HASH_OFFSET], 0, 7681);
    cases
}

fn fixture_digests() -> serde_json::Value {
    let (public, private) = fixture_encodings();
    let hexadecimal = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    json!({"kind":"deterministic synthetic structural encodings; not a generated KEM key pair",
        "public_sha3_256":hexadecimal(&Sha3_256::digest(&public)),
        "private_sha3_256":hexadecimal(&Sha3_256::digest(&private)),
        "encoding_bytes_printed":false})
}

fn smoke() {
    let mut observations = Vec::new();
    for case in cases() {
        let status = case.observe();
        assert_eq!(status, case.expected, "import case {} failed", case.name);
        observations.push(json!({"operation":case.name,"status":status,"expected":case.expected}));
    }
    let (public, private) = r1::keygen().expect("fresh synthetic key generation failed");
    let imported_public =
        import_public_probe(public.as_bytes()).expect("fresh public import failed");
    let private_bytes = private.to_bytes();
    let imported_private =
        import_private_probe(&private_bytes).expect("fresh private import failed");
    // Syntax and the embedded-public hash cannot establish the entropy of z.
    let mut fixed_z = private_bytes.clone();
    fixed_z[r1::PRIVATE_KEY_BYTES - 32..].fill(0);
    assert_eq!(private_status(import_private_probe(&fixed_z), &fixed_z), 0);
    let (ciphertext, shared) =
        r1::encapsulate(&imported_public).expect("fresh encapsulation failed");
    assert!(
        shared.matches(&r1::decapsulate(&imported_private, &ciphertext)),
        "fresh imported-key exchange failed"
    );
    let mut altered = Zeroizing::new(ciphertext.as_bytes().to_vec());
    altered[r1::CIPHERTEXT_BYTES - 1] ^= 1;
    let bad = r1::Ciphertext::from_bytes(&altered).expect("fixed ciphertext length");
    let rejected = r1::decapsulate(&imported_private, &bad);
    assert!(
        !shared.matches(&rejected),
        "fresh changed ciphertext unexpectedly matched"
    );
    assert!(
        rejected.matches(&r1::decapsulate(&imported_private, &bad)),
        "implicit rejection not repeatable"
    );
    println!(
        "{}",
        json!({"schema":1,"profile":r1::PROFILE,"host":std::env::consts::OS,
        "architecture":std::env::consts::ARCH,"research_vectors_feature_requested":false,
        "fixtures":fixture_digests(),"cases":observations,"fresh_imported_key_round_trips":1,
        "fresh_rejections":1,"repeat_rejection_equal":true,"fresh_private_with_fixed_z_imported":true,
        "fixed_z_import_is_syntax_not_entropy_validation":true,"secrets_printed":false})
    );
}

fn exhaustive() {
    let (mut public, private) = fixture_encodings();
    let original_public = public.clone();
    let mut value_alignment_cases = 0_u64;
    for alignment in 0..8 {
        for value in 0..8192_u16 {
            set_coefficient(&mut public, alignment, value);
            let status = public_status(import_public_probe(&public), &public);
            assert_eq!(
                status,
                if value < 7681 { 0 } else { 2 },
                "value/alignment canonicality mismatch"
            );
            value_alignment_cases += 1;
        }
        public.copy_from_slice(&original_public);
    }
    let mut boundary_position_cases = 0_u64;
    let mut private_copy = private.clone();
    for position in 0..VECTOR_COEFFICIENTS {
        for value in [7680_u16, 7681, 8191] {
            let expected = if value < 7681 { 0 } else { 2 };
            set_coefficient(&mut public, position, value);
            assert_eq!(
                public_status(import_public_probe(&public), &public),
                expected
            );
            public.copy_from_slice(&original_public);
            boundary_position_cases += 1;
            for embedded_public in [false, true] {
                private_copy.copy_from_slice(&private);
                let offset = if embedded_public { PUBLIC_OFFSET } else { 0 };
                set_coefficient(
                    &mut private_copy[offset..offset + VECTOR_BYTES],
                    position,
                    value,
                );
                refresh_public_hash(&mut private_copy);
                assert_eq!(
                    private_status(import_private_probe(&private_copy), &private_copy),
                    expected
                );
                boundary_position_cases += 1;
                private_copy[HASH_OFFSET] ^= 1;
                assert_eq!(
                    private_status(import_private_probe(&private_copy), &private_copy),
                    if expected == 0 { 3 } else { 2 }
                );
                boundary_position_cases += 1;
            }
        }
    }
    println!(
        "{}",
        json!({"schema":1,"profile":r1::PROFILE,"mode":"exhaustive single-coefficient probes",
        "fixture":fixture_digests(),"single_coefficient_value_alignment_cases":value_alignment_cases,
        "boundary_position_cases":boundary_position_cases,"total_cases":value_alignment_cases+boundary_position_cases,
        "complete_vector_space_exhausted":false,"all_expected_statuses_and_accepted_encodings_match":true,
        "formal_program_verification":false,"secrets_printed":false})
    );
}

fn latency(series: usize, samples: usize, warmups: usize) {
    let cases = cases();
    for case in cases.iter().filter(|case| case.expected != 1) {
        for _ in 0..warmups {
            assert_eq!(case.observe(), case.expected);
        }
        for sample in 0..samples {
            let (nanoseconds, status) = if case.private {
                let start = Instant::now();
                let result = black_box(import_private_probe(black_box(&case.bytes)));
                let nanoseconds = start.elapsed().as_nanos();
                (nanoseconds, private_status(result, &case.bytes))
            } else {
                let start = Instant::now();
                let result = black_box(import_public_probe(black_box(&case.bytes)));
                let nanoseconds = start.elapsed().as_nanos();
                (nanoseconds, public_status(result, &case.bytes))
            };
            assert_eq!(status, case.expected);
            println!(
                "{}",
                json!({"schema":1,"profile":r1::PROFILE,"operation":case.name,
                "series":series,"iteration":sample,"nanoseconds":u64::try_from(nanoseconds).expect("duration overflow"),
                "status":status,"expected_status":case.expected,"validation_and_drop_outside_timer":true,
                "secrets_printed":false})
            );
        }
    }
}

fn main() {
    assert_eq!(r1::Q, 7681);
    assert_eq!(r1::RANK, 6);
    let arguments: Vec<String> = std::env::args().collect();
    match arguments.get(1).map(String::as_str).unwrap_or("smoke") {
        "smoke" if arguments.len() <= 2 => smoke(),
        "exhaustive" if arguments.len() == 2 => exhaustive(),
        "fixture-digests" if arguments.len() == 2 => println!("{}", fixture_digests()),
        "latency" if arguments.len() == 5 => {
            let series = arguments[2].parse::<usize>().expect("series must be unsigned");
            let samples = arguments[3].parse::<usize>().expect("samples must be unsigned");
            let warmups = arguments[4].parse::<usize>().expect("warmups must be unsigned");
            assert!(series < 100 && (1..=100_000).contains(&samples) && warmups <= 10_000);
            latency(series, samples, warmups);
        }
        _ => panic!("usage: m08-import-consumer [smoke|exhaustive|fixture-digests|latency SERIES SAMPLES WARMUPS]"),
    }
}
