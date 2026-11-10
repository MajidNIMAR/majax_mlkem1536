//! Scalar negacyclic NTT arithmetic for R1; the generic ring remains an oracle.
//! Source-level fixed work is not a universal constant-time guarantee.

use zeroize::Zeroizing;

pub(crate) const N: usize = 256;
pub(crate) const Q: u16 = 7681;
#[cfg(any(test, feature = "research-vectors"))]
const RECIP64: u128 = (1_u128 << 64) / (Q as u128);
const RECIP32: u64 = (1_u64 << 32) / (Q as u64);
const PSI: u16 = 4055; // Exact order 512; PSI^256 = -1 modulo Q.
const OMEGA: u16 = 5685; // PSI^2, exact order 256.
const PSI_INVERSE: u16 = 2811;
const OMEGA_INVERSE: u16 = 5653;
const N_INVERSE: u16 = 7651;

// These divisions/remainders are evaluated at compile time on public constants.
const fn public_power(mut base: u16, mut exponent: usize) -> u16 {
    let mut result = 1_u32;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = result * base as u32 % Q as u32;
        }
        base = (base as u32 * base as u32 % Q as u32) as u16;
        exponent >>= 1;
    }
    result as u16
}
const fn public_powers(root: u16, scale: u16) -> [u16; N] {
    let mut values = [0; N];
    let mut i = 0;
    let mut value = scale;
    while i < N {
        values[i] = value;
        value = (value as u32 * root as u32 % Q as u32) as u16;
        i += 1;
    }
    values
}
const fn stage_roots(root: u16) -> [u16; 8] {
    let mut roots = [0; 8];
    let mut stage = 0;
    while stage < roots.len() {
        roots[stage] = public_power(root, N >> (stage + 1));
        stage += 1;
    }
    roots
}
const TWIST: [u16; N] = public_powers(PSI, 1);
const UNTWIST_SCALED: [u16; N] = public_powers(PSI_INVERSE, N_INVERSE);
const FORWARD_ROOTS: [u16; 8] = stage_roots(OMEGA);
const INVERSE_ROOTS: [u16; 8] = stage_roots(OMEGA_INVERSE);

#[cfg(test)]
std::thread_local! {
    // Tests run concurrently; each measured operation owns its thread's counter.
    static TRANSFORM_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn count_transforms<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    let previous = TRANSFORM_CALLS.with(|calls| calls.replace(0));
    let result = operation();
    let measured = TRANSFORM_CALLS.with(|calls| calls.replace(previous));
    (result, measured)
}

/// Input < 2q. The wrapping subtraction's top bit selects the correction.
#[inline]
pub(crate) fn reduce_once(x: u32) -> u16 {
    let t = x.wrapping_sub(u32::from(Q));
    t.wrapping_add((t >> 31) * u32::from(Q)) as u16
}

/// Exact for every u64: reciprocal quotient is at most one below floor(x/q).
#[inline]
#[cfg(any(test, feature = "research-vectors"))]
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

#[inline]
fn product(a: u16, b: u16) -> u16 {
    // Canonical inputs: product <= 7680^2 = 58_982_400.
    // The 32-bit reciprocal leaves a remainder < 2Q; a single correction
    // suffices. No 128-bit product or division on secret coefficients.
    let x = u32::from(a) * u32::from(b);
    let estimate = ((u64::from(x) * RECIP32) >> 32) as u32;
    reduce_once(x - estimate * u32::from(Q))
}

/// In-place cyclic radix-2 DIT, unnormalised in either direction.
/// All permutations, table addresses and loop bounds are public.
#[inline(never)]
fn transform(values: &mut [u16; N], roots: &[u16; 8]) {
    #[cfg(test)]
    TRANSFORM_CALLS.with(|calls| calls.set(calls.get() + 1));
    for i in 0..N {
        let j = (i as u8).reverse_bits() as usize;
        if i < j {
            values.swap(i, j);
        }
    }
    for (stage, &root) in roots.iter().enumerate() {
        let length = 2 << stage;
        let half = length >> 1;
        let mut start = 0;
        while start < N {
            let mut twiddle = 1;
            for offset in 0..half {
                let low = values[start + offset];
                let high = product(values[start + offset + half], twiddle);
                values[start + offset] = reduce_once(u32::from(low) + u32::from(high));
                values[start + offset + half] =
                    reduce_once(u32::from(low) + u32::from(Q) - u32::from(high));
                twiddle = product(twiddle, root);
            }
            start += length;
        }
    }
}

pub(crate) struct Polynomial {
    coefficients: Zeroizing<[u16; N]>,
}
impl Polynomial {
    /// Only zeroes are returned; secret results are written into their owner.
    pub(crate) fn zero() -> Self {
        Self {
            coefficients: Zeroizing::new([0; N]),
        }
    }

    pub(crate) fn fill_with(&mut self, mut value: impl FnMut(usize) -> u16) {
        for i in 0..N {
            self.coefficients[i] = value(i);
        }
    }

    /// Callers supply canonical coefficients, established by their bounded formula.
    #[cfg(test)]
    pub(crate) fn from_fn(mut value: impl FnMut(usize) -> u16) -> Self {
        let mut out = Self::zero();
        for i in 0..N {
            out.coefficients[i] = value(i);
        }
        out
    }
    pub(crate) fn coefficients(&self) -> &[u16; N] {
        &self.coefficients
    }
    pub(crate) fn add_assign(&mut self, other: &Self) {
        for i in 0..N {
            self.coefficients[i] =
                reduce_once(u32::from(self.coefficients[i]) + u32::from(other.coefficients[i]));
        }
    }
    pub(crate) fn subtract_assign(&mut self, other: &Self) {
        for i in 0..N {
            self.coefficients[i] = reduce_once(
                u32::from(self.coefficients[i]) + u32::from(Q) - u32::from(other.coefficients[i]),
            );
        }
    }

    /// Twist and transform directly into an existing owner in the NTT domain.
    #[inline(never)]
    pub(crate) fn forward_into(&self, out: &mut NttPolynomial) {
        for (i, &twist) in TWIST.iter().enumerate() {
            out.values[i] = product(self.coefficients[i], twist);
        }
        transform(&mut out.values, &FORWARD_ROOTS);
    }

    /// Write into a caller-owned result, avoiding a secret Polynomial return.
    /// The two fixed scratch buffers are wiped by their Zeroizing owners.
    /// Retained as the per-product NTT path for arithmetic regression tests.
    #[cfg(test)]
    #[inline(never)]
    pub(crate) fn multiply_into(&self, other: &Self, out: &mut Self) {
        let mut left = Zeroizing::new([0_u16; N]);
        let mut right = Zeroizing::new([0_u16; N]);
        for i in 0..N {
            left[i] = product(self.coefficients[i], TWIST[i]);
            right[i] = product(other.coefficients[i], TWIST[i]);
        }
        transform(&mut left, &FORWARD_ROOTS);
        transform(&mut right, &FORWARD_ROOTS);
        for i in 0..N {
            left[i] = product(left[i], right[i]);
        }
        transform(&mut left, &INVERSE_ROOTS);
        for i in 0..N {
            // The inverse normalisation and untwist are precombined modulo Q.
            out.coefficients[i] = product(left[i], UNTWIST_SCALED[i]);
        }
    }
}

/// Canonical negacyclic NTT values, distinct from coefficient polynomials.
/// The constructor returns zeroes only; transformed secrets stay in their owner.
pub(crate) struct NttPolynomial {
    values: Zeroizing<[u16; N]>,
}
impl NttPolynomial {
    pub(crate) fn zero() -> Self {
        Self {
            values: Zeroizing::new([0; N]),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.values.fill(0);
    }

    /// Accumulate one product with a reduction after every term.
    /// Each product is canonical, so sum <= 2*(Q-1) < 2Q. This bound
    /// is independent of the number of products already accumulated.
    #[inline(never)]
    pub(crate) fn multiply_add_assign(&mut self, left: &Self, right: &Self) {
        for i in 0..N {
            self.values[i] = reduce_once(
                u32::from(self.values[i]) + u32::from(product(left.values[i], right.values[i])),
            );
        }
    }

    /// Preserve this NTT value and invert directly in the coefficient owner.
    /// Both source and destination are wiped by their own Zeroizing storage.
    #[inline(never)]
    pub(crate) fn inverse_into(&self, out: &mut Polynomial) {
        out.coefficients.copy_from_slice(&self.values[..]);
        transform(&mut out.coefficients, &INVERSE_ROOTS);
        for (value, &untwist) in out.coefficients.iter_mut().zip(&UNTWIST_SCALED) {
            *value = product(*value, untwist);
        }
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
            let mut a = Polynomial::from_fn(|i| aa[i]);
            let b = Polynomial::from_fn(|i| bb[i]);
            let ra = ReferencePolynomial::<Q>::from_coefficients(aa).unwrap();
            let rb = ReferencePolynomial::<Q>::from_coefficients(bb).unwrap();
            a.add_assign(&b);
            assert_eq!(a.coefficients(), ra.add(&rb).coefficients());
            a.fill_with(|i| aa[i]);
            a.subtract_assign(&b);
            assert_eq!(a.coefficients(), ra.subtract(&rb).coefficients());
            a.fill_with(|i| aa[i]);
            let mut out = Polynomial::zero();
            a.multiply_into(&b, &mut out);
            assert_eq!(out.coefficients(), ra.multiply(&rb).coefficients());
        }
    }

    #[test]
    fn ntt_roots_and_inverse_roundtrips() {
        assert_eq!(public_power(PSI, 256), Q - 1);
        assert_eq!(public_power(PSI, 512), 1);
        assert_eq!(product(PSI, PSI), OMEGA);
        assert_eq!(public_power(OMEGA, 128), Q - 1);
        assert_eq!(public_power(OMEGA, 256), 1);
        assert_eq!(product(PSI, PSI_INVERSE), 1);
        assert_eq!(product(OMEGA, OMEGA_INVERSE), 1);
        assert_eq!(product(N as u16, N_INVERSE), 1);
        for case in 0..16 {
            let initial =
                std::array::from_fn(|i| ((i * i * 73 + i * 19 + case * 3571) % Q as usize) as u16);
            let mut values = initial;
            transform(&mut values, &FORWARD_ROOTS);
            assert!(values.iter().all(|&x| x < Q));
            transform(&mut values, &INVERSE_ROOTS);
            for value in &mut values {
                *value = product(*value, N_INVERSE);
            }
            assert_eq!(values, initial);
        }
    }

    #[test]
    fn ntt_product_reduction_canonical_boundaries() {
        for a in 0..Q {
            for b in [0, 1, Q - 2, Q - 1] {
                assert_eq!(
                    product(a, b),
                    (u32::from(a) * u32::from(b) % u32::from(Q)) as u16
                );
            }
        }
    }

    #[test]
    fn ntt_product_edges_wrap_sign_and_pseudorandom_oracle() {
        let mut state = 0x4e54_542d_5231_0004_u64;
        let mut out = Polynomial::from_fn(|_| Q - 1);
        for case in 0..70 {
            let mut next = || {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                (state % u64::from(Q)) as u16
            };
            let aa = std::array::from_fn(|i| match case {
                0 => 0,
                1 => Q - 1,
                2 => u16::from(i == N - 1),
                3 => u16::from(i == 0),
                4 => {
                    if i % 2 == 0 {
                        Q - 1
                    } else {
                        0
                    }
                }
                5 => (i as u16) * 29,
                _ => next(),
            });
            let bb = std::array::from_fn(|i| match case {
                0 | 1 => Q - 1,
                2 => u16::from(i == 1),
                3 => Q - 1,
                4 => {
                    if i % 2 == 0 {
                        0
                    } else {
                        Q - 1
                    }
                }
                5 => (i as u16) * 17,
                _ => next(),
            });
            let a = Polynomial::from_fn(|i| aa[i]);
            let b = Polynomial::from_fn(|i| bb[i]);
            a.multiply_into(&b, &mut out);
            let ra = ReferencePolynomial::<Q>::from_coefficients(aa).unwrap();
            let rb = ReferencePolynomial::<Q>::from_coefficients(bb).unwrap();
            assert_eq!(
                out.coefficients(),
                ra.multiply(&rb).coefficients(),
                "case {case}"
            );
            assert!(out.coefficients().iter().all(|&x| x < Q));
            if case == 2 {
                assert_eq!(out.coefficients()[0], Q - 1);
                assert!(out.coefficients()[1..].iter().all(|&x| x == 0));
            }
        }
    }

    #[test]
    fn retained_ntt_dot_products_match_independent_convolution() {
        let mut state = 0x4d30_362d_444f_5401_u64;
        let mut left = NttPolynomial::zero();
        let mut right = NttPolynomial::zero();
        let mut sum = NttPolynomial::zero();
        let mut out = Polynomial::zero();
        for case in 0..20 {
            // Reuse the accumulator across cases: stale terms must be removed.
            sum.clear();
            assert!(sum.values.iter().all(|&value| value == 0));
            let mut expected = ReferencePolynomial::<Q>::from_coefficients([0; N]).unwrap();
            for term in 0..6 {
                let mut next = || {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    (state % u64::from(Q)) as u16
                };
                let aa = std::array::from_fn(|i| match case {
                    0 => 0,
                    1 => Q - 1,
                    2 => u16::from(i == N - 1),
                    3 => {
                        if (i + term) % 2 == 0 {
                            Q - 1
                        } else {
                            0
                        }
                    }
                    _ => next(),
                });
                let bb = std::array::from_fn(|i| match case {
                    0 | 1 => Q - 1,
                    2 => u16::from(i == 1),
                    3 => (i as u16 * 17 + term as u16) % Q,
                    _ => next(),
                });
                let a = Polynomial::from_fn(|i| aa[i]);
                let b = Polynomial::from_fn(|i| bb[i]);
                a.forward_into(&mut left);
                b.forward_into(&mut right);
                sum.multiply_add_assign(&left, &right);
                assert!(left.values.iter().all(|&value| value < Q));
                assert!(right.values.iter().all(|&value| value < Q));
                assert!(sum.values.iter().all(|&value| value < Q));
                let ra = ReferencePolynomial::<Q>::from_coefficients(aa).unwrap();
                let rb = ReferencePolynomial::<Q>::from_coefficients(bb).unwrap();
                expected = expected.add(&ra.multiply(&rb));
            }
            let retained = *sum.values;
            out.fill_with(|_| Q - 1);
            sum.inverse_into(&mut out);
            assert_eq!(out.coefficients(), expected.coefficients(), "case {case}");
            assert_eq!(*sum.values, retained, "inverse must preserve the NTT input");
            assert!(out.coefficients().iter().all(|&value| value < Q));
            if case == 2 {
                assert_eq!(out.coefficients()[0], Q - 6);
                assert!(out.coefficients()[1..].iter().all(|&value| value == 0));
            }
        }
    }

    #[test]
    fn pointwise_accumulator_reduces_every_term_at_canonical_boundaries() {
        let mut left = NttPolynomial::zero();
        let mut right = NttPolynomial::zero();
        let mut sum = NttPolynomial::zero();
        left.values.fill(Q - 1);
        right.values.fill(Q - 1);
        sum.values.fill(Q - 1);
        // (-1)*(-1)=1: the first term crosses q exactly and later terms
        // remain canonical without accumulating a rank-dependent large sum.
        for term in 0..(Q as usize + 7) {
            sum.multiply_add_assign(&left, &right);
            let expected = ((Q as usize + term) % Q as usize) as u16;
            assert!(sum.values.iter().all(|&value| value == expected));
        }
        sum.clear();
        assert!(sum.values.iter().all(|&value| value == 0));
    }
}
