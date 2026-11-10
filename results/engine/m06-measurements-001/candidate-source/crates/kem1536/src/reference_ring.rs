//! Reference arithmetic in Z_q[X]/(X^256 + 1), independent of the KEM profile.
//!
//! This schoolbook implementation is an algebraic oracle for future engine
//! components. Timing, zeroization and side-channel properties are not audited.
//! It must not be used as a production secret-processing implementation.

pub const DEGREE: usize = 256;

use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingError {
    InvalidModulus,
    NoncanonicalCoefficient { index: usize },
}

/// Canonical coefficients; intentionally no Debug implementation for their values.
#[derive(Clone, PartialEq, Eq)]
pub struct ReferencePolynomial<const Q: u16> {
    coefficients: [u16; DEGREE],
}

impl<const Q: u16> Drop for ReferencePolynomial<Q> {
    fn drop(&mut self) {
        self.coefficients.zeroize();
    }
}

impl<const Q: u16> ReferencePolynomial<Q> {
    pub fn from_coefficients(coefficients: [u16; DEGREE]) -> Result<Self, RingError> {
        if Q < 3 || Q.is_multiple_of(2) {
            return Err(RingError::InvalidModulus);
        }
        if let Some(index) = coefficients.iter().position(|&value| value >= Q) {
            return Err(RingError::NoncanonicalCoefficient { index });
        }
        Ok(Self { coefficients })
    }

    pub fn coefficients(&self) -> &[u16; DEGREE] {
        &self.coefficients
    }

    pub fn add(&self, other: &Self) -> Self {
        let coefficients = std::array::from_fn(|i| {
            ((u32::from(self.coefficients[i]) + u32::from(other.coefficients[i])) % u32::from(Q))
                as u16
        });
        Self { coefficients }
    }

    pub fn subtract(&self, other: &Self) -> Self {
        let coefficients = std::array::from_fn(|i| {
            ((u32::from(self.coefficients[i]) + u32::from(Q) - u32::from(other.coefficients[i]))
                % u32::from(Q)) as u16
        });
        Self { coefficients }
    }

    /// O(256^2) negacyclic convolution, with exact signed accumulation.
    pub fn multiply(&self, other: &Self) -> Self {
        let mut sums = [0_i64; DEGREE];
        for (i, &a) in self.coefficients.iter().enumerate() {
            for (j, &b) in other.coefficients.iter().enumerate() {
                let product = i64::from(a) * i64::from(b);
                if i + j < DEGREE {
                    sums[i + j] += product;
                } else {
                    sums[i + j - DEGREE] -= product;
                }
            }
        }
        // Each accumulator has 256 terms, hence |sum| < 256*(2^16)^2 < 2^40.
        let coefficients = sums.map(|value| value.rem_euclid(i64::from(Q)) as u16);
        Self { coefficients }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exercise<const Q: u16>() {
        let a = ReferencePolynomial::<Q>::from_coefficients(std::array::from_fn(|i| {
            ((37 * i + 11) % usize::from(Q)) as u16
        }))
        .unwrap();
        let b = ReferencePolynomial::<Q>::from_coefficients(std::array::from_fn(|i| {
            ((i * i + 19) % usize::from(Q)) as u16
        }))
        .unwrap();
        let c = ReferencePolynomial::<Q>::from_coefficients([Q - 1; DEGREE]).unwrap();
        assert!(a.add(&b).subtract(&b) == a);
        assert!(a.multiply(&b) == b.multiply(&a));
        assert!(a.multiply(&b.add(&c)) == a.multiply(&b).add(&a.multiply(&c)));
        let all_minus_one_squared: [u16; DEGREE] = std::array::from_fn(|i| {
            (2 * i as i64 - (DEGREE as i64 - 2)).rem_euclid(i64::from(Q)) as u16
        });
        assert_eq!(c.multiply(&c).coefficients(), &all_minus_one_squared);

        // Independent oracle: ordinary length-511 convolution, then X^256 = -1.
        let mut convolution = [0_u64; 2 * DEGREE - 1];
        for (degree, sum) in convolution.iter_mut().enumerate() {
            for i in 0..DEGREE {
                if degree >= i && degree - i < DEGREE {
                    *sum += u64::from(a.coefficients[i]) * u64::from(b.coefficients[degree - i]);
                }
            }
        }
        let expected: [u16; DEGREE] = std::array::from_fn(|i| {
            let high = convolution.get(i + DEGREE).copied().unwrap_or(0);
            (i64::try_from(convolution[i]).unwrap() - i64::try_from(high).unwrap())
                .rem_euclid(i64::from(Q)) as u16
        });
        assert_eq!(a.multiply(&b).coefficients(), &expected);
    }

    #[test]
    fn independent_convolution_and_ring_laws_at_both_moduli() {
        exercise::<3329>();
        exercise::<7681>();
        exercise::<65535>(); // Also exercises the accumulator bound at a large modulus.
    }

    #[test]
    fn quotient_sign_and_multiplicative_identity() {
        let mut high = [0; DEGREE];
        high[255] = 1;
        let mut x = [0; DEGREE];
        x[1] = 1;
        let a = ReferencePolynomial::<7681>::from_coefficients(high).unwrap();
        let b = ReferencePolynomial::<7681>::from_coefficients(x).unwrap();
        let mut expected = [0; DEGREE];
        expected[0] = 7680;
        assert_eq!(a.multiply(&b).coefficients(), &expected);
        let mut one = [0; DEGREE];
        one[0] = 1;
        let identity = ReferencePolynomial::<7681>::from_coefficients(one).unwrap();
        assert!(a.multiply(&identity) == a);
    }

    #[test]
    fn rejects_invalid_moduli_and_noncanonical_inputs() {
        assert!(matches!(
            ReferencePolynomial::<0>::from_coefficients([0; DEGREE]),
            Err(RingError::InvalidModulus)
        ));
        assert!(matches!(
            ReferencePolynomial::<3328>::from_coefficients([0; DEGREE]),
            Err(RingError::InvalidModulus)
        ));
        let mut coefficients = [0; DEGREE];
        coefficients[17] = 3329;
        assert!(matches!(
            ReferencePolynomial::<3329>::from_coefficients(coefficients),
            Err(RingError::NoncanonicalCoefficient { index: 17 })
        ));
    }
}
