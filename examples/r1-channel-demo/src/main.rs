//! Local, one-message composition example. The receiver public key is assumed authentic.
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use kem1536::dev_kem::{self as kem, Ciphertext, SharedSecret};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

fn transcript(public_key: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"MAJAX-R1-CHANNEL-DEMO-v1\0");
    hash.update(public_key);
    hash.update(ciphertext);
    hash.finalize().into()
}

fn cipher(secret: &SharedSecret, context: &[u8; 32]) -> Aes256Gcm {
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(context), secret.as_bytes())
        .expand(b"sender-to-receiver;one-message;AES-256-GCM", &mut key[..])
        .unwrap();
    Aes256Gcm::new_from_slice(&key[..]).unwrap()
}

fn demonstrate() {
    let (ek, dk) = kem::keygen().expect("OS randomness");
    let (encapsulation, sender_secret) = kem::encapsulate(&ek).expect("OS randomness");
    let receiver_secret = kem::decapsulate(&dk, &encapsulation);
    let context = transcript(ek.as_bytes(), encapsulation.as_bytes());
    let sender = cipher(&sender_secret, &context);
    let receiver = cipher(&receiver_secret, &context);
    let mut nonce_bytes = [0; 12];
    getrandom::fill(&mut nonce_bytes).expect("OS randomness");
    let nonce = Nonce::from(nonce_bytes);
    let plaintext = b"Message public de demonstration du KEM experimental R1.";
    // Exactly one encryption under this derived directional key.
    let encrypted = sender
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &context,
            },
        )
        .unwrap();
    let recovered = receiver
        .decrypt(
            &nonce,
            Payload {
                msg: &encrypted,
                aad: &context,
            },
        )
        .unwrap();
    assert_eq!(&recovered, plaintext);

    let mut altered_payload = encrypted.clone();
    altered_payload[0] ^= 1;
    assert!(receiver
        .decrypt(
            &nonce,
            Payload {
                msg: &altered_payload,
                aad: &context
            }
        )
        .is_err());
    let mut altered_tag = encrypted.clone();
    let last = altered_tag.len() - 1;
    altered_tag[last] ^= 1;
    assert!(receiver
        .decrypt(
            &nonce,
            Payload {
                msg: &altered_tag,
                aad: &context
            }
        )
        .is_err());
    let mut altered_context = context;
    altered_context[0] ^= 1;
    assert!(receiver
        .decrypt(
            &nonce,
            Payload {
                msg: &encrypted,
                aad: &altered_context
            }
        )
        .is_err());
    let mut altered_nonce = nonce_bytes;
    altered_nonce[0] ^= 1;
    assert!(receiver
        .decrypt(
            &Nonce::from(altered_nonce),
            Payload {
                msg: &encrypted,
                aad: &context
            }
        )
        .is_err());

    let mut changed_kem = encapsulation.as_bytes().to_vec();
    changed_kem[0] = 255;
    changed_kem[1] |= 31;
    let changed_kem = Ciphertext::from_bytes(&changed_kem).unwrap();
    let wrong_secret = kem::decapsulate(&dk, &changed_kem);
    let wrong_receiver = cipher(
        &wrong_secret,
        &transcript(ek.as_bytes(), changed_kem.as_bytes()),
    );
    assert!(wrong_receiver
        .decrypt(
            &nonce,
            Payload {
                msg: &encrypted,
                aad: &context
            }
        )
        .is_err());
    let (_, other_dk) = kem::keygen().unwrap();
    let other_secret = kem::decapsulate(&other_dk, &encapsulation);
    assert!(cipher(&other_secret, &context)
        .decrypt(
            &nonce,
            Payload {
                msg: &encrypted,
                aad: &context
            }
        )
        .is_err());
}

fn main() {
    demonstrate();
    println!("{{\"profile\":\"KEM1536-DEV-Q7681-R1\",\"roundtrip\":true,\"tamper_checks\":6,\"secrets_printed\":false,\"peer_authentication_assumed\":true}}");
}

#[cfg(test)]
mod tests {
    #[test]
    fn composition_and_six_tamper_cases() {
        super::demonstrate();
    }
}
