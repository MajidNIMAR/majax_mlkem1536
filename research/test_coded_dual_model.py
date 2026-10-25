"""Model boundaries, exact toy probabilities and stable-integral identities."""

from fractions import Fraction
import math
import unittest

from coded_dual_model import log_integral, repetition_model, validate, zero_success, zero_weights


class CodedDualTests(unittest.TestCase):
    def test_integral_normalization_and_beta_two(self):
        self.assertEqual(log_integral(800, 0), 0)
        for c in (0.01, 0.5, 1.0):
            expected = math.log(-math.expm1(-c) / c)
            self.assertAlmostEqual(log_integral(2, c), expected, places=13)
        self.assertTrue(math.isfinite(log_integral(1500, 10)))
        with self.assertRaises(ValueError):
            log_integral(0, 1)

    def test_zero_probability_against_exact_small_cases(self):
        p0 = Fraction(5, 16)
        for population in (4, 8):
            for guessed in (0, 1, 2):
                weights = zero_weights(population, guessed, 3)
                for repeats in (1, 3, 10):
                    expected = sum((math.comb(population, z) * p0 ** z * (1 - p0) ** (population - z)
                                    * (1 - (1 - Fraction(math.comb(z, guessed), math.comb(population, guessed))) ** repeats)
                                    for z in range(guessed, population + 1)), Fraction())
                    self.assertAlmostEqual(zero_success(repeats, weights), float(expected), places=13)

    def test_repetition_limit_is_explicit(self):
        self.assertIsNone(repetition_model(4, 4, 3))
        self.assertEqual(repetition_model(8, 0, 3), 1)
        self.assertGreater(repetition_model(256, 8, 3), 1)

    def test_dimension_and_sample_guards(self):
        validate(1536, 256, 7681, 3, 1200, 24, 128, 16)
        for args in ((1536, 1536, 7681, 3, 1200, 24, 128, 16),
                     (1536, 256, 7681, 3, 1792, 24, 128, 16),
                     (1536, 256, 7681, 3, 1200, 1410, 128, 16)):
            with self.assertRaises(ValueError):
                validate(*args)


if __name__ == "__main__":
    unittest.main()
