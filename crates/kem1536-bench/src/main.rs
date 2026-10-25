use kem1536::dev_kem as r1;
use ml_kem::{Decapsulate, Encapsulate, Kem, MlKem1024};
use serde::Serialize;
use std::{hint::black_box, io::Write, time::Instant};

#[derive(Serialize)]
struct Observation {
    engine: &'static str,
    operation: &'static str,
    series: usize,
    iteration: usize,
    nanoseconds: u64,
}

fn measured<T>(operation: impl FnOnce() -> T) -> (T, u64) {
    let start = Instant::now();
    let result = black_box(operation());
    let duration = start.elapsed().as_nanos().try_into().unwrap();
    (result, duration)
}

fn r1_series(series: usize, rows: &mut Vec<Observation>) {
    let (ek, dk) = r1::keygen().unwrap();
    let (ciphertext, expected) = r1::encapsulate(&ek).unwrap();
    for (op, operation) in ["keygen", "encaps", "decaps"].into_iter().enumerate() {
        for iteration in 0..1100 {
            let ns = match op {
                0 => {
                    let ((new_ek, new_dk), ns) = measured(|| r1::keygen().unwrap());
                    let (c, s) = r1::encapsulate(&new_ek).unwrap();
                    assert!(s.matches(&r1::decapsulate(&new_dk, &c)));
                    ns
                }
                1 => {
                    let ((c, s), ns) = measured(|| r1::encapsulate(black_box(&ek)).unwrap());
                    assert!(s.matches(&r1::decapsulate(&dk, &c)));
                    ns
                }
                _ => {
                    let (s, ns) =
                        measured(|| r1::decapsulate(black_box(&dk), black_box(&ciphertext)));
                    assert!(s.matches(&expected));
                    ns
                }
            };
            if iteration >= 100 {
                rows.push(Observation {
                    engine: "R1",
                    operation,
                    series,
                    iteration: iteration - 100,
                    nanoseconds: ns,
                });
            }
        }
    }
}

fn mlkem_series(series: usize, rows: &mut Vec<Observation>) {
    let (dk, ek) = MlKem1024::generate_keypair();
    let (ciphertext, expected) = ek.encapsulate();
    for (op, operation) in ["keygen", "encaps", "decaps"].into_iter().enumerate() {
        for iteration in 0..1100 {
            let ns = match op {
                0 => {
                    let ((new_dk, new_ek), ns) = measured(MlKem1024::generate_keypair);
                    let (c, s) = new_ek.encapsulate();
                    assert_eq!(s, new_dk.decapsulate(&c));
                    ns
                }
                1 => {
                    let ((c, s), ns) = measured(|| black_box(&ek).encapsulate());
                    assert_eq!(s, dk.decapsulate(&c));
                    ns
                }
                _ => {
                    let (s, ns) = measured(|| black_box(&dk).decapsulate(black_box(&ciphertext)));
                    assert_eq!(s, expected);
                    ns
                }
            };
            if iteration >= 100 {
                rows.push(Observation {
                    engine: "ML-KEM-1024",
                    operation,
                    series,
                    iteration: iteration - 100,
                    nanoseconds: ns,
                });
            }
        }
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match arguments.as_slice() {
        [mode] if mode == "measure" => {
            let mut rows = Vec::with_capacity(30000);
            for series in 0..5 {
                if series % 2 == 0 {
                    r1_series(series, &mut rows);
                    mlkem_series(series, &mut rows);
                } else {
                    mlkem_series(series, &mut rows);
                    r1_series(series, &mut rows);
                }
                eprintln!("completed series {series}");
            }
            let mut out = std::io::BufWriter::new(std::io::stdout().lock());
            for row in rows {
                serde_json::to_writer(&mut out, &row).unwrap();
                writeln!(&mut out).unwrap();
            }
        }
        [mode, engine] if mode == "rss" && ["R1", "ML-KEM-1024"].contains(&engine.as_str()) => {
            for _ in 0..1000 {
                if engine == "R1" {
                    let (ek, dk) = r1::keygen().unwrap();
                    let (c, s) = r1::encapsulate(&ek).unwrap();
                    assert!(s.matches(&r1::decapsulate(&dk, &c)));
                    black_box((&ek, &dk, &c, &s));
                } else {
                    let (dk, ek) = MlKem1024::generate_keypair();
                    let (c, s) = ek.encapsulate();
                    assert_eq!(s, dk.decapsulate(&c));
                    black_box((&ek, &dk, &c, &s));
                }
            }
            println!("{{\"round_trips\":1000,\"secrets_printed\":false}}");
            std::io::stdout().flush().unwrap();
            // A controller can query the final process peak before allowing exit.
            let mut done = String::new();
            std::io::stdin().read_line(&mut done).unwrap();
        }
        _ => {
            eprintln!("usage: kem1536-bench measure | rss <R1|ML-KEM-1024>");
            std::process::exit(1);
        }
    }
}
