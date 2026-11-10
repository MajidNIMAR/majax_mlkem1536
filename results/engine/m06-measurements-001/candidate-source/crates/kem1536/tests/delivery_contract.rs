//! Public API contracts exercised without the deterministic research feature.
use kem1536::dev_kem::{self as kem, Ciphertext, DecapsulationKey, EncapsulationKey, Error};

#[test]
fn rejection_is_bound_to_both_key_and_entire_ciphertext() {
    for _ in 0..8 {
        let (ek, dk) = kem::keygen().unwrap();
        let (c, expected) = kem::encapsulate(&ek).unwrap();
        let mut encoded = dk.to_bytes();
        // z affects implicit rejection, not the honest PKE path.
        encoded[kem::PRIVATE_KEY_BYTES - 1] ^= 1;
        let other_z = DecapsulationKey::from_bytes(&encoded).unwrap();
        assert!(expected.matches(&kem::decapsulate(&other_z, &c)));
        let mut base = c.as_bytes().to_vec();
        // Fix the first u coefficient to 8191. Flipping its low bit in byte
        // 0 or 1 still leaves 8190 or 7935, so all variants must reject.
        base[0] = 255;
        base[1] |= 31;
        let base_input = Ciphertext::from_bytes(&base).unwrap();
        let baseline = kem::decapsulate(&dk, &base_input);
        for position in [0, 1, 415, 416, 831, 1247, 1663, 2079, 2495, 2496, 2655] {
            let mut altered = base.clone();
            altered[position] ^= 1;
            assert_eq!(altered.iter().zip(&base).filter(|(a, b)| a != b).count(), 1);
            let bad = Ciphertext::from_bytes(&altered).unwrap();
            let first = kem::decapsulate(&dk, &bad);
            assert!(!first.matches(&baseline));
            assert!(first.matches(&kem::decapsulate(&dk, &bad)));
            assert!(!first.matches(&expected));
            assert!(!first.matches(&kem::decapsulate(&other_z, &bad)));
        }
    }
}

#[test]
fn every_encoded_polynomial_boundary_is_validated_on_import() {
    let (ek, dk) = kem::keygen().unwrap();
    for polynomial in 0..6 {
        for source in [ek.as_bytes(), dk.to_bytes().as_slice()] {
            let mut bad = source.to_vec();
            let offset = polynomial * 416;
            bad[offset] = 255;
            bad[offset + 1] |= 31;
            if bad.len() == kem::PUBLIC_KEY_BYTES {
                assert!(matches!(
                    EncapsulationKey::from_bytes(&bad),
                    Err(Error::NoncanonicalEncoding)
                ));
            } else {
                assert!(matches!(
                    DecapsulationKey::from_bytes(&bad),
                    Err(Error::NoncanonicalEncoding)
                ));
            }
        }
    }
    let mut bad = dk.to_bytes();
    bad[2496 + kem::PUBLIC_KEY_BYTES + 31] ^= 1;
    assert!(matches!(
        DecapsulationKey::from_bytes(&bad),
        Err(Error::InconsistentPrivateKey)
    ));
}
