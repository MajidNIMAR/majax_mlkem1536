//! Offline replay of public fuzz fixtures; separate from the application CLI.
use kem1536::dev_kem::{self as r1, Ciphertext, DecapsulationKey, EncapsulationKey};
use serde::Deserialize;
use serde_json::json;
use std::io::{BufRead, Write};

const FIXTURES: &[u8; 164864] = include_bytes!("../../../../fuzz/fixtures/cases.bin");
#[derive(Deserialize)]
struct Request {
    kind: String,
    key: usize,
    raw: Vec<u8>,
}
fn main() {
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for line in std::io::stdin().lock().lines() {
        let request: Request = serde_json::from_str(&line.unwrap()).unwrap();
        assert!(request.key < 16 && request.raw.len() <= 16384);
        let result = match request.kind.as_str() {
            "public" => json!({"accepted":EncapsulationKey::from_bytes(&request.raw).is_ok()}),
            "private" => json!({"accepted":DecapsulationKey::from_bytes(&request.raw).is_ok()}),
            "ciphertext" => match Ciphertext::from_bytes(&request.raw) {
                Ok(c) => {
                    let base = request.key * 10304;
                    let dk =
                        DecapsulationKey::from_bytes(&FIXTURES[base + 2528..base + 7616]).unwrap();
                    json!({"accepted":true,"shared":r1::decapsulate(&dk,&c).as_bytes().to_vec()})
                }
                Err(_) => json!({"accepted":false}),
            },
            _ => panic!("unknown synthetic replay request"),
        };
        serde_json::to_writer(&mut out, &result).unwrap();
        writeln!(&mut out).unwrap();
        out.flush().unwrap();
    }
}
