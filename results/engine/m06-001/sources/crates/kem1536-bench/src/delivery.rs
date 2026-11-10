//! Finite timing diagnostic over eight fresh keys and five input classes.
use kem1536::dev_kem as kem;
use serde::Serialize;
use std::{hint::black_box, io::Write, time::Instant};

#[derive(Serialize)]
struct Row {
    key: usize,
    class: &'static str,
    round: usize,
    nanoseconds: u64,
}

pub(crate) fn timing() {
    let names = [
        "honest",
        "canonical_changed_v",
        "noncanonical_first_u",
        "noncanonical_last_u",
        "zero",
    ];
    let mut rows = Vec::with_capacity(16000);
    let mut order_state = 0x4d30_342d_5449_4d45_u64;
    for key in 0..8 {
        let (ek, dk) = kem::keygen().unwrap();
        let (honest, expected) = kem::encapsulate(&ek).unwrap();
        let mut changed = honest.as_bytes().to_vec();
        changed[kem::CIPHERTEXT_BYTES - 1] ^= 128;
        let mut first = honest.as_bytes().to_vec();
        first[0] = 255;
        first[1] |= 31;
        let mut last = honest.as_bytes().to_vec();
        // Last coefficient of the last 13-bit u polynomial.
        last[2494] |= 224;
        last[2495] = 255;
        let inputs = [
            honest,
            kem::Ciphertext::from_bytes(&changed).unwrap(),
            kem::Ciphertext::from_bytes(&first).unwrap(),
            kem::Ciphertext::from_bytes(&last).unwrap(),
            kem::Ciphertext::from_bytes(&[0; kem::CIPHERTEXT_BYTES]).unwrap(),
        ];
        for round in 0..450 {
            let mut order = [0, 1, 2, 3, 4];
            for i in (1..5).rev() {
                order_state = order_state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1);
                order.swap(i, (order_state as usize) % (i + 1));
            }
            for class in order {
                let start = Instant::now();
                let secret = black_box(kem::decapsulate(black_box(&dk), black_box(&inputs[class])));
                let nanoseconds = start.elapsed().as_nanos().try_into().unwrap();
                assert_eq!(secret.matches(&expected), class == 0);
                if round >= 50 {
                    rows.push(Row {
                        key,
                        class: names[class],
                        round: round - 50,
                        nanoseconds,
                    });
                }
            }
        }
    }
    let mut output = std::io::BufWriter::new(std::io::stdout().lock());
    for row in rows {
        serde_json::to_writer(&mut output, &row).unwrap();
        writeln!(&mut output).unwrap();
    }
}
