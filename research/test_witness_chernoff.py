"""Independent bit enumeration and actual decoder checks for the certificate."""

from fractions import Fraction
import itertools
import unittest

from noise_exact import compress, decompress
from witness_chernoff import mgf_cbd, mgf_product, safe_radius


class WitnessChernoffTests(unittest.TestCase):
    def test_mgfs_against_all_input_bit_strings(self):
        z = Fraction(13, 10)
        for eta in (1, 2, 3):
            samples = [sum(bits[:eta]) - sum(bits[eta:])
                       for bits in itertools.product((0, 1), repeat=2 * eta)]
            brute = sum((z ** (a * b) for a in samples for b in samples), Fraction(0)) / len(samples) ** 2
            self.assertEqual(mgf_product(eta, z), brute)
            self.assertEqual(mgf_cbd(eta, z), sum((z ** a for a in samples), Fraction(0)) / len(samples))

    def test_safe_radius_against_exhaustive_decoding(self):
        for q, dv in ((17, 2), (19, 2), (3329, 5), (7681, 5)):
            radius, (a, b) = safe_radius(q, dv)
            # All residue/error sums in the safe interval lie between these
            # two endpoints; exhaust every integer in that resulting interval.
            for bit in (0, 1):
                for noise in range(-radius + a, radius + b + 1):
                    self.assertEqual(compress((decompress(bit, q, 1) + noise) % q, q, 1), bit)
            self.assertEqual(radius, min(q // 4 - max(abs(a), abs(b)),
                                         min(x - decompress(1, q, 1)
                                             for x in range(q) if compress(x, q, 1) == 0
                                             and x > q // 2) - 1 - b))

    def test_markov_bound_on_small_exhaustive_sum(self):
        z = Fraction(13, 10)
        # CBD1 values with multiplicity. Four independent products and e2.
        samples = (-1, 0, 0, 1)
        products = [a * b for a in samples for b in samples]
        threshold = 3
        failures = sum(abs(sum(terms) + e2) >= threshold
                       for terms in itertools.product(products, repeat=4) for e2 in samples)
        exact = Fraction(failures, len(products) ** 4 * len(samples))
        upper = 2 * mgf_product(1, z) ** 4 * mgf_cbd(1, z) / z ** threshold
        self.assertLessEqual(exact, upper)


if __name__ == "__main__":
    unittest.main()
