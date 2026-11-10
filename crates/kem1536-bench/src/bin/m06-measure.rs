//! M06 single-version measurements. Only public timings and sizes are emitted.
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

fn timed<T>(f: impl FnOnce() -> T) -> (T, u64) {
    let start = Instant::now();
    let value = black_box(f());
    let ns = start.elapsed().as_nanos().try_into().unwrap();
    (value, ns)
}

fn measure(series: usize, samples: usize, warmup: usize) {
    assert!((1..=100_000).contains(&samples) && warmup <= 10_000);
    let (ek, dk) = r1::keygen().unwrap();
    let (ciphertext, expected) = r1::encapsulate(&ek).unwrap();
    let names = ["keygen", "encaps", "decaps"];
    let mut rows = Vec::with_capacity(samples * 3);
    for offset in 0..3 {
        let operation = (offset + series) % 3;
        for iteration in 0..samples + warmup {
            let ns = match operation {
                0 => {
                    let ((new_ek, new_dk), ns) = timed(|| r1::keygen().unwrap());
                    let (c, s) = r1::encapsulate(&new_ek).unwrap();
                    assert!(s.matches(&r1::decapsulate(&new_dk, &c)));
                    ns
                }
                1 => {
                    let ((c, s), ns) = timed(|| r1::encapsulate(black_box(&ek)).unwrap());
                    assert!(s.matches(&r1::decapsulate(&dk, &c)));
                    ns
                }
                _ => {
                    let (s, ns) = timed(|| r1::decapsulate(black_box(&dk), black_box(&ciphertext)));
                    assert!(s.matches(&expected));
                    ns
                }
            };
            // All validation and destruction above takes place after elapsed().
            if iteration >= warmup {
                rows.push(Observation {
                    operation: names[operation],
                    series,
                    iteration: iteration - warmup,
                    nanoseconds: ns,
                });
            }
        }
    }
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for row in rows {
        serde_json::to_writer(&mut out, &row).unwrap();
        writeln!(&mut out).unwrap();
    }
}

fn rss() {
    for _ in 0..1000 {
        let (ek, dk) = r1::keygen().unwrap();
        let (c, s) = r1::encapsulate(&ek).unwrap();
        assert!(s.matches(&r1::decapsulate(&dk, &c)));
        black_box((&ek, &dk, &c, &s));
    }
    println!("{{\"round_trips\":1000,\"secrets_printed\":false}}");
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode, series, samples, warmup] if mode == "measure" => {
            measure(
                series.parse().unwrap(),
                samples.parse().unwrap(),
                warmup.parse().unwrap(),
            );
        }
        [mode] if mode == "rss" => rss(),
        _ => panic!("usage: m06-measure measure <series> <samples> <warmup> | rss"),
    }
}
