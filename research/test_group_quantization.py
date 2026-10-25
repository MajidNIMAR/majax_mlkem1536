"""Independent exhaustive checks of the H02 cover and support-function bound."""

from fractions import Fraction
import itertools
import unittest

from group_quantization import (BOX, DIAMOND, centered, cover_certificate,
                                encode_pair, grouped_mgf, reconstruction)
from group_quantization import pair_positions
from mixed_precision import domination_mgf
from witness_chernoff import mgf_product


class GroupQuantizationTests(unittest.TestCase):
    def test_fast_encoder_against_full_codebook_distances(self):
        for q, bits in ((5, 2), (7, 2), (13, 3), (31, 4)):
            self.assertTrue(cover_certificate(q, bits)["certified_L1_error_at_most_one"])
            codebook = [reconstruction(i, j, q, bits)
                        for i in range(1 << bits) for j in range(1 << bits)]
            self.assertEqual(len(codebook), len(set(codebook)))
            for x, y in itertools.product(range(q), repeat=2):
                indices = encode_pair(x, y, q, bits)
                a, b = reconstruction(*indices, q, bits)
                error = centered(a - x, q), centered(b - y, q)
                self.assertLessEqual(sum(abs(e) for e in error), 1)
                brute = min(centered(a - x, q) ** 2 + centered(b - y, q) ** 2 for a, b in codebook)
                self.assertEqual(sum(e * e for e in error), brute)

    def test_cover_negative_boundary_and_actual_modulus(self):
        self.assertFalse(cover_certificate(17, 3)["certified_L1_error_at_most_one"])
        result = cover_certificate(7681, 12)
        self.assertTrue(result["certified_L1_error_at_most_one"])
        self.assertEqual(result["unique_codewords"], 1 << 24)
        with self.assertRaises(ValueError):
            reconstruction(4096, 0, 7681, 12)

    def test_group_mgf_against_all_bits_and_adaptive_errors(self):
        z = Fraction(13, 10)
        samples = (-1, 0, 0, 1)  # All CBD1 bit outcomes, with multiplicity.
        for support in (DIAMOND, BOX):
            expectation = Fraction(0)
            for s1, s2, e1, e2 in itertools.product(samples, repeat=4):
                worst = max(abs(s1 * dx + s2 * dy) for dx, dy in support)
                expectation += z ** (-s1 * e1 - s2 * e2 + worst)
            self.assertEqual(grouped_mgf(1, support, z), expectation / 256)
        self.assertEqual(grouped_mgf(3, BOX, z), domination_mgf(3, 1, z) ** 2)
        self.assertLess(grouped_mgf(3, DIAMOND, z), grouped_mgf(3, BOX, z))
        self.assertEqual(grouped_mgf(3, ((0, 0),), z), mgf_product(3, z) ** 2)

    def test_pairings_are_disjoint_for_every_output(self):
        for count in range(769):
            selected = pair_positions(count)
            self.assertEqual(len(selected), count)
            sizes = [sum(b * 128 <= i < (b + 1) * 128 for i in selected) for b in range(6)]
            self.assertLessEqual(max(sizes) - min(sizes), 1)
        for output in range(256):
            pairs = [((output - 2 * j) % 256, (output - 2 * j - 1) % 256) for j in range(128)]
            self.assertEqual(sorted(index for pair in pairs for index in pair), list(range(256)))
            self.assertEqual(len(set(pairs)), 128)


if __name__ == "__main__":
    unittest.main()
