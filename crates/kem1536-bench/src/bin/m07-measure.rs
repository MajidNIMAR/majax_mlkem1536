//! M07 API-return latency measurements. Destruction and validation are outside timing.
use kem1536::dev_kem as r1;
use serde::Serialize;
use std::{hint::black_box, io::Write, time::Instant};

#[derive(Serialize)]
struct Observation {
    operation: &'static str,
    series: usize,
    iteration: usize,
    nanoseconds: u64,
}

fn timed<T>(operation: impl FnOnce() -> T) -> (T, u64) {
    let start = Instant::now();
    let result = black_box(operation());
    let elapsed = start.elapsed().as_nanos().try_into().unwrap();
    (result, elapsed)
}

fn measure(series: usize, samples: usize, warmup: usize) {
    assert!((1..=100_000).contains(&samples) && warmup <= 10_000);
    let (ek, dk) = r1::keygen().unwrap();
    let (ciphertext, expected) = r1::encapsulate(&ek).unwrap();
    let mut altered = ciphertext.as_bytes().to_vec();
    altered[0] = 255;
    altered[1] |= 31;
    let rejected_ciphertext = r1::Ciphertext::from_bytes(&altered).unwrap();
    let expected_rejected = r1::decapsulate(&dk, &rejected_ciphertext);
    assert!(!expected_rejected.matches(&expected));
    let names = ["keygen", "encaps", "decaps_valid", "decaps_rejected"];
    let mut rows = Vec::with_capacity(samples * names.len());
    for offset in 0..names.len() {
        let operation = (offset + series) % names.len();
        for iteration in 0..samples + warmup {
            let nanoseconds = match operation {
                0 => {
                    let ((new_ek, new_dk), elapsed) = timed(|| r1::keygen().unwrap());
                    let (c, s) = r1::encapsulate(&new_ek).unwrap();
                    assert!(s.matches(&r1::decapsulate(&new_dk, &c)));
                    elapsed
                }
                1 => {
                    let ((c, s), elapsed) = timed(|| r1::encapsulate(black_box(&ek)).unwrap());
                    assert!(s.matches(&r1::decapsulate(&dk, &c)));
                    elapsed
                }
                2 => {
                    let (s, elapsed) =
                        timed(|| r1::decapsulate(black_box(&dk), black_box(&ciphertext)));
                    assert!(s.matches(&expected));
                    elapsed
                }
                _ => {
                    let (s, elapsed) =
                        timed(|| r1::decapsulate(black_box(&dk), black_box(&rejected_ciphertext)));
                    assert!(s.matches(&expected_rejected));
                    elapsed
                }
            };
            if iteration >= warmup {
                rows.push(Observation {
                    operation: names[operation],
                    series,
                    iteration: iteration - warmup,
                    nanoseconds,
                });
            }
        }
    }
    let mut output = std::io::BufWriter::new(std::io::stdout().lock());
    for row in rows {
        serde_json::to_writer(&mut output, &row).unwrap();
        output.write_all(b"\n").unwrap();
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [series, samples, warmup] => measure(
            series.parse().unwrap(),
            samples.parse().unwrap(),
            warmup.parse().unwrap(),
        ),
        _ => panic!("usage: m07-measure <series> <samples> <warmup>"),
    }
}
