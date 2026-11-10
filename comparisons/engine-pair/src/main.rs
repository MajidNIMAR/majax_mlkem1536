//! Measure the actual public APIs of the two repositories in one process.
//! JSON output contains public metadata and durations, never key material.

use kem1536::dev_kem as r1;
use majax_mlkem as old;
use serde::Serialize;
use std::{collections::BTreeMap, hint::black_box, io::Write, time::Instant};

#[derive(Clone, Copy, Serialize)]
struct Configuration {
    series: usize,
    warmups_per_operation_and_series: usize,
    observations_per_operation_and_series: usize,
}

#[derive(Serialize)]
struct Engine {
    name: &'static str,
    backend: &'static str,
    public_key_bytes: usize,
    expanded_private_key_bytes: usize,
    ciphertext_bytes: usize,
    shared_secret_bytes: usize,
}

#[derive(Serialize)]
struct Metadata {
    kind: &'static str,
    schema: u8,
    configuration: Configuration,
    engines: [Engine; 2],
    architecture: &'static str,
    operating_system: &'static str,
    deterministic_testing_enabled: bool,
    caller_validation_in_timer: bool,
    caller_output_drop_in_timer: bool,
    application_rng_path_in_timer: bool,
    public_api_representation_note: &'static str,
}

#[derive(Serialize)]
struct Observation {
    kind: &'static str,
    engine: &'static str,
    operation: &'static str,
    series: usize,
    iteration: usize,
    nanoseconds: u64,
}

#[derive(Serialize)]
struct Summary {
    kind: &'static str,
    engine: &'static str,
    operation: &'static str,
    observations: usize,
    median_nanoseconds: f64,
    p95_nanoseconds_nearest_rank: u64,
    minimum_nanoseconds: u64,
    maximum_nanoseconds: u64,
}

fn measured<T>(action: impl FnOnce() -> T) -> (T, u64) {
    let started = Instant::now();
    let result = black_box(action());
    let nanoseconds = started.elapsed().as_nanos().try_into().unwrap();
    (result, nanoseconds)
}

fn record(
    output: &mut Vec<Observation>,
    cfg: Configuration,
    engine: &'static str,
    operation: &'static str,
    series: usize,
    iteration: usize,
    nanoseconds: u64,
) {
    if iteration >= cfg.warmups_per_operation_and_series {
        output.push(Observation {
            kind: "observation",
            engine,
            operation,
            series,
            iteration: iteration - cfg.warmups_per_operation_and_series,
            nanoseconds,
        });
    }
}

fn operation_order(series: usize) -> [usize; 3] {
    if series.is_multiple_of(2) {
        [0, 1, 2]
    } else {
        [2, 1, 0]
    }
}

fn measure_r1(cfg: Configuration, series: usize, output: &mut Vec<Observation>) {
    let (ek, dk) = r1::keygen().expect("R1 OS RNG available");
    let (ciphertext, expected) = r1::encapsulate(&ek).expect("R1 encapsulation");
    for operation in operation_order(series) {
        for iteration in
            0..cfg.warmups_per_operation_and_series + cfg.observations_per_operation_and_series
        {
            let nanoseconds = match operation {
                0 => {
                    let ((new_ek, new_dk), ns) =
                        measured(|| r1::keygen().expect("R1 key generation"));
                    let (c, s) = r1::encapsulate(&new_ek).expect("R1 validation encapsulation");
                    assert!(s.matches(&r1::decapsulate(&new_dk, &c)));
                    ns
                }
                1 => {
                    let ((c, s), ns) =
                        measured(|| r1::encapsulate(black_box(&ek)).expect("R1 encapsulation"));
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
            record(
                output,
                cfg,
                "R1",
                ["keygen", "encaps", "decaps"][operation],
                series,
                iteration,
                nanoseconds,
            );
        }
    }
}

fn measure_original(cfg: Configuration, series: usize, output: &mut Vec<Observation>) {
    let keys = old::generate_keypair();
    let encapsulation = old::encapsulate(&keys.public_key).expect("PQClean encapsulation");
    for operation in operation_order(series) {
        for iteration in
            0..cfg.warmups_per_operation_and_series + cfg.observations_per_operation_and_series
        {
            let nanoseconds = match operation {
                0 => {
                    let (new_keys, ns) = measured(old::generate_keypair);
                    let fresh = old::encapsulate(&new_keys.public_key)
                        .expect("PQClean validation encapsulation");
                    let recovered =
                        old::decapsulate(&fresh.ciphertext, new_keys.secret_key.expose())
                            .expect("PQClean validation decapsulation");
                    assert!(fresh.shared_secret.expose() == recovered.expose());
                    ns
                }
                1 => {
                    let (fresh, ns) = measured(|| {
                        old::encapsulate(black_box(&keys.public_key))
                            .expect("PQClean encapsulation")
                    });
                    let recovered = old::decapsulate(&fresh.ciphertext, keys.secret_key.expose())
                        .expect("PQClean validation decapsulation");
                    assert!(fresh.shared_secret.expose() == recovered.expose());
                    ns
                }
                _ => {
                    let (recovered, ns) = measured(|| {
                        old::decapsulate(
                            black_box(&encapsulation.ciphertext),
                            black_box(keys.secret_key.expose()),
                        )
                        .expect("PQClean decapsulation")
                    });
                    assert!(encapsulation.shared_secret.expose() == recovered.expose());
                    ns
                }
            };
            record(
                output,
                cfg,
                "original-ML-KEM-1024",
                ["keygen", "encaps", "decaps"][operation],
                series,
                iteration,
                nanoseconds,
            );
        }
    }
}

fn metadata(configuration: Configuration) -> Metadata {
    Metadata {
        kind: "metadata",
        schema: 1,
        configuration,
        engines: [
            Engine {
                name: "R1",
                backend: "Rust baseline x86-64; arithmetic defined by frozen source",
                public_key_bytes: r1::PUBLIC_KEY_BYTES,
                expanded_private_key_bytes: r1::PRIVATE_KEY_BYTES,
                ciphertext_bytes: r1::CIPHERTEXT_BYTES,
                shared_secret_bytes: r1::SHARED_SECRET_BYTES,
            },
            Engine {
                name: "original-ML-KEM-1024",
                backend: old::active_backend().identifier(),
                public_key_bytes: old::PUBLIC_KEY_BYTES,
                expanded_private_key_bytes: old::SECRET_KEY_BYTES,
                ciphertext_bytes: old::CIPHERTEXT_BYTES,
                shared_secret_bytes: old::SHARED_SECRET_BYTES,
            },
        ],
        architecture: std::env::consts::ARCH,
        operating_system: std::env::consts::OS,
        deterministic_testing_enabled: false,
        caller_validation_in_timer: false,
        caller_output_drop_in_timer: false,
        application_rng_path_in_timer: true,
        public_api_representation_note: "R1 typed prevalidated keys; original public byte APIs include their imports/copies; internal drops and validation remain inside each API call",
    }
}

fn summaries(rows: &[Observation]) -> Vec<Summary> {
    let mut groups: BTreeMap<(&str, &str), Vec<u64>> = BTreeMap::new();
    for row in rows {
        groups
            .entry((row.engine, row.operation))
            .or_default()
            .push(row.nanoseconds);
    }
    groups
        .into_iter()
        .map(|((engine, operation), mut values)| {
            values.sort_unstable();
            let n = values.len();
            let median = if n.is_multiple_of(2) {
                (u128::from(values[n / 2 - 1]) + u128::from(values[n / 2])) as f64 / 2.0
            } else {
                values[n / 2] as f64
            };
            Summary {
                kind: "summary",
                engine,
                operation,
                observations: n,
                median_nanoseconds: median,
                p95_nanoseconds_nearest_rank: values[(95 * n).div_ceil(100) - 1],
                minimum_nanoseconds: values[0],
                maximum_nanoseconds: values[n - 1],
            }
        })
        .collect()
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if arguments.len() != 3 {
        eprintln!("usage: kem-engine-pair <series> <warmups> <observations-per-series>");
        std::process::exit(2);
    }
    let cfg = Configuration {
        series: arguments[0].parse().expect("public positive series count"),
        warmups_per_operation_and_series: arguments[1].parse().expect("public warmup count"),
        observations_per_operation_and_series: arguments[2]
            .parse()
            .expect("public positive observation count"),
    };
    assert!((1..=100).contains(&cfg.series));
    assert!((1..=100_000).contains(&cfg.observations_per_operation_and_series));
    assert!(cfg.warmups_per_operation_and_series <= 10_000);
    let mut rows = Vec::with_capacity(cfg.series * cfg.observations_per_operation_and_series * 6);
    for series in 0..cfg.series {
        if series.is_multiple_of(2) {
            measure_r1(cfg, series, &mut rows);
            measure_original(cfg, series, &mut rows);
        } else {
            measure_original(cfg, series, &mut rows);
            measure_r1(cfg, series, &mut rows);
        }
    }
    let summaries = summaries(&rows);
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    serde_json::to_writer(&mut out, &metadata(cfg)).unwrap();
    writeln!(out).unwrap();
    for row in rows {
        serde_json::to_writer(&mut out, &row).unwrap();
        writeln!(out).unwrap();
    }
    for summary in summaries {
        serde_json::to_writer(&mut out, &summary).unwrap();
        writeln!(out).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_r1_public_api_exchanges_and_rejects_a_mutation() {
        let (ek, dk) = r1::keygen().unwrap();
        let (c, s) = r1::encapsulate(&ek).unwrap();
        assert!(s.matches(&r1::decapsulate(&dk, &c)));
        let mut bytes = c.as_bytes().to_vec();
        bytes[0] ^= 1;
        let altered = r1::Ciphertext::from_bytes(&bytes).unwrap();
        assert!(!s.matches(&r1::decapsulate(&dk, &altered)));
        assert!(r1::Ciphertext::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn actual_original_public_api_exchanges_and_rejects_a_mutation() {
        let keys = old::generate_keypair();
        let encapsulated = old::encapsulate(&keys.public_key).unwrap();
        let recovered =
            old::decapsulate(&encapsulated.ciphertext, keys.secret_key.expose()).unwrap();
        assert!(encapsulated.shared_secret.expose() == recovered.expose());
        let mut altered = encapsulated.ciphertext;
        altered[0] ^= 1;
        let rejected = old::decapsulate(&altered, keys.secret_key.expose()).unwrap();
        assert!(encapsulated.shared_secret.expose() != rejected.expose());
        assert!(old::decapsulate(&altered[..altered.len() - 1], keys.secret_key.expose()).is_err());
    }
}
