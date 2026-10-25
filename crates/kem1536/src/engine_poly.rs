//! Fixed-bound coefficient arithmetic for R1. The generic ring remains an oracle.
//! Source-level fixed work is not a universal constant-time guarantee.

use zeroize::Zeroizing;

pub(crate) const N: usize = 256;
pub(crate) const Q: u16 = 7681;
const RECIP64: u128 = (1_u128 << 64) / (Q as u128);
const RECIP32: u64 = (1_u64 << 32) / (Q as u64);

/// Input < 2q. The wrapping subtraction's top bit selects the correction.
#[inline]
pub(crate) fn reduce_once(x: u32) -> u16 {
    let t = x.wrapping_sub(u32::from(Q));
    t.wrapping_add((t >> 31) * u32::from(Q)) as u16
}

/// Exact for every u64: reciprocal quotient is at most one below floor(x/q).
#[inline]
pub(crate) fn reduce_wide(x: u64) -> u16 {
    let estimate = ((u128::from(x) * RECIP64) >> 64) as u64;
    let r = x - estimate * u64::from(Q);
    let t = r.wrapping_sub(u64::from(Q));
    t.wrapping_add((t >> 63) * u64::from(Q)) as u16
}

#[inline]
pub(crate) fn quotient(x: u32) -> u32 {
    let estimate = ((u64::from(x) * RECIP32) >> 32) as u32;
    let remainder = x - estimate * u32::from(Q);
    estimate + 1 - (remainder.wrapping_sub(u32::from(Q)) >> 31)
}

pub(crate) struct Polynomial {
    coefficients: Zeroizing<[u16; N]>,
}
impl Polynomial {
    /// Callers supply canonical coefficients, established by their bounded formula.
    pub(crate) fn from_fn(mut value: impl FnMut(usize) -> u16) -> Self {
        let mut out = Self {
            coefficients: Zeroizing::new([0; N]),
        };
        for i in 0..N {
            out.coefficients[i] = value(i);
        }
        out
    }
    pub(crate) fn coefficients(&self) -> &[u16; N] {
        &self.coefficients
    }
    pub(crate) fn add(&self, other: &Self) -> Self {
        Self::from_fn(|i| {
            reduce_once(u32::from(self.coefficients[i]) + u32::from(other.coefficients[i]))
        })
    }
    pub(crate) fn subtract(&self, other: &Self) -> Self {
        Self::from_fn(|i| {
            reduce_once(
                u32::from(self.coefficients[i]) + u32::from(Q) - u32::from(other.coefficients[i]),
            )
        })
    }
    pub(crate) fn multiply(&self, other: &Self) -> Self {
        let mut sums = Zeroizing::new([0_i64; N]);
        for i in 0..N {
            for j in 0..N {
                let product = i64::from(self.coefficients[i]) * i64::from(other.coefficients[j]);
                // This branch depends only on public loop indices.
                if i + j < N {
                    sums[i + j] += product;
                } else {
                    sums[i + j - N] -= product;
                }
            }
        }
        // |sum| <= 256*(q-1)^2 < OFFSET; OFFSET is a multiple of q.
        const OFFSET: i64 = (N as i64) * (Q as i64) * (Q as i64);
        Self::from_fn(|i| reduce_wide((sums[i] + OFFSET) as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reference_ring::ReferencePolynomial;

    #[test]
    fn reciprocal_reduction_and_quotient_boundaries() {
        for x in 0..2 * u32::from(Q) {
            assert_eq!(reduce_once(x), (x % u32::from(Q)) as u16);
        }
        for x in 0..(1_u32 << 18) {
            assert_eq!(quotient(x), x / u32::from(Q));
        }
        let mut x = 0x6b65_6d31_3533_3602_u64;
        for _ in 0..100000 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
            assert_eq!(reduce_wide(x), (x % u64::from(Q)) as u16);
            assert_eq!(quotient(x as u32), (x as u32) / u32::from(Q));
        }
        for x in [0, 1, u64::from(Q) - 1, u64::from(Q), u64::MAX - 1, u64::MAX] {
            assert_eq!(reduce_wide(x), (x % u64::from(Q)) as u16);
        }
    }

    #[test]
    fn arithmetic_agrees_with_separate_generic_oracle() {
        for case in 0..8_u32 {
            let aa = std::array::from_fn(|i| ((i as u32 * 97 + case * 1337) % u32::from(Q)) as u16);
            let bb =
                std::array::from_fn(|i| ((i as u32 * i as u32 + case * 491) % u32::from(Q)) as u16);
            let a = Polynomial::from_fn(|i| aa[i]);
            let b = Polynomial::from_fn(|i| bb[i]);
            let ra = ReferencePolynomial::<Q>::from_coefficients(aa).unwrap();
            let rb = ReferencePolynomial::<Q>::from_coefficients(bb).unwrap();
            assert_eq!(a.add(&b).coefficients(), ra.add(&rb).coefficients());
            assert_eq!(
                a.subtract(&b).coefficients(),
                ra.subtract(&rb).coefficients()
            );
            assert_eq!(
                a.multiply(&b).coefficients(),
                ra.multiply(&rb).coefficients()
            );
        }
    }
}
