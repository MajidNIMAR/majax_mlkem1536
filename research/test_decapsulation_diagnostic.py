"""Exhaustive modular checks for arbitrary correlated rounding errors."""

from fractions import Fraction
import unittest

from decapsulation_diagnostic import bounded_rounding_failures, variance_components
from noise_exact import Law, cbd, combine, compress, decompress, rounding_law


class DecapsulationDiagnosticTests(unittest.TestCase):
    def test_bounds_against_exhaustive_adaptive_errors(self):
        # Cover wraparound over multiple periods, asymmetric errors, both bits,
        # both q mod 4 classes, and the lossless case. Each T can choose its
        # own error, so this checks dependence rather than independent noise.
        weights = [1 + (i % 5) for i in range(73)]
        offset, final = -39, Law.counts({-2: 1, 0: 3, 1: 2})
        denominator = sum(weights) * final.denominator
        for q in (13, 17, 19):
            for a, b in ((-2, 1), (0, 2), (-1, -1), (0, 0)):
                calculated = bounded_rounding_failures(offset, weights, sum(weights),
                                                       final, q, a, b)
                for bit in (0, 1):
                    minimum = maximum = 0
                    for i, weight in enumerate(weights):
                        for extra, final_weight in final.weights.items():
                            outcomes = [compress((decompress(bit, q, 1) + offset + i
                                                  + extra + delta) % q, q, 1) != bit
                                        for delta in range(a, b + 1)]
                            minimum += weight * final_weight * all(outcomes)
                            maximum += weight * final_weight * any(outcomes)
                    self.assertEqual(calculated[bit], (Fraction(minimum, denominator),
                                                        Fraction(maximum, denominator)))

    def test_lossless_intrinsic_variance_and_rank_scaling(self):
        p = dict(n=256, k=6, q=3329, eta1=2, eta2=2, du=12, dv=12)
        self.assertEqual(variance_components(p)["total_variance"], "3073")
        self.assertEqual(variance_components(p | {"k": 4})["total_variance"], "2049")
        terms = variance_components(p)["terms"]
        self.assertEqual(terms["s_times_rounding_u"]["exact"], "0")
        self.assertEqual(terms["rounding_v"]["exact"], "0")

    def test_invalid_error_span_rejected(self):
        with self.assertRaises(ValueError):
            bounded_rounding_failures(0, [1], 1, Law.counts({0: 1}), 17, -5, 5)

    def test_variance_includes_nonzero_rounding_mean(self):
        p = dict(n=256, k=6, q=3329, eta1=2, eta2=2, du=11, dv=5)
        secret, error = cbd(2), cbd(2)
        ru, rv = rounding_law(3329, 11), rounding_law(3329, 5)
        self.assertEqual(ru.mean(), Fraction(1, 3329))
        first = combine(secret, secret, product=True)
        second = combine(secret, combine(error, ru), product=True)
        final = combine(error, rv)
        expected = 1536 * (first.variance() + second.variance()) + final.variance()
        self.assertEqual(Fraction(variance_components(p)["total_variance"]), expected)


if __name__ == "__main__":
    unittest.main()
