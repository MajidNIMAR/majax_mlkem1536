//! Synthetic public inputs only; arithmetic microbenchmark, not a CT test.
#[allow(dead_code)]
#[path = "../../../crates/kem1536/src/engine_poly.rs"]
mod engine_poly;

use engine_poly::{NttPolynomial, Polynomial, Q};
use std::{hint::black_box, time::Instant};

fn main() {
    let args: Vec<usize> = std::env::args()
        .skip(1)
        .map(|arg| arg.parse().unwrap())
        .collect();
    let [series, samples, warmup, batch] = args[..] else {
        panic!("usage: series samples warmup batch");
    };
    assert!(samples > 0 && batch > 0);
    let mut input = Polynomial::zero();
    input.fill_with(|i| (i as u16 * 29 + 17) % Q);
    let mut transformed = NttPolynomial::zero();
    input.forward_into(&mut transformed);
    let mut out = Polynomial::zero();
    let mut ntt_out = NttPolynomial::zero();
    let operations = ["forward", "inverse", "multiply_add"];
    let mut rows = Vec::new();
    for offset in 0..operations.len() {
        let operation = (offset + series) % operations.len();
        for iteration in 0..warmup + samples {
            let start = Instant::now();
            for _ in 0..batch {
                match operation {
                    0 => black_box(&input).forward_into(black_box(&mut ntt_out)),
                    1 => black_box(&transformed).inverse_into(black_box(&mut out)),
                    _ => ntt_out.multiply_add_assign(
                        black_box(&transformed),
                        black_box(&transformed),
                    ),
                }
            }
            let elapsed = start.elapsed().as_nanos();
            if operation == 1 {
                assert_eq!(out.coefficients(), input.coefficients());
            }
            if iteration >= warmup {
                rows.push(format!(
                    "{{\"operation\":\"{}\",\"series\":{},\"iteration\":{},\"batch\":{},\"nanoseconds\":{}}}",
                    operations[operation], series, iteration - warmup, batch, elapsed
                ));
            }
        }
    }
    for row in rows {
        println!("{row}");
    }
    black_box(ntt_out);
}
