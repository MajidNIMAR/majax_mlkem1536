"""Exhaustive pointwise checks of the mixed-precision domination argument."""

from fractions import Fraction
import itertools
import unittest

from mixed_precision import (TOTAL, domination_mgf, error_radius, exact_c05,
                             interleaved_widths)
from witness_chernoff import mgf_product


class MixedPrecisionTests(unittest.TestCase):
    def test_mgf_against_bits_and_adversarial_rounding(self):
        z = Fraction(13, 10)
        for eta in (1, 2):
            samples = [sum(bits[:eta]) - sum(bits[eta:])
                       for bits in itertools.product((0, 1), repeat=2 * eta)]
            for radius in (0, 1, 2):
                right = sum((max(z ** (-s * e - s * delta)
                                 for delta in range(-radius, radius + 1))
                             for s in samples for e in samples), Fraction(0)) / len(samples) ** 2
                left = sum((max(z ** (s * e + s * delta)
                                for delta in range(-radius, radius + 1))
                            for s in samples for e in samples), Fraction(0)) / len(samples) ** 2
                self.assertEqual(domination_mgf(eta, radius, z), right)
                self.assertEqual(right, left)

    def test_lossless_and_convexity(self):
        self.assertEqual({w: error_radius(w) for w in (11, 12, 13)}, {11: 2, 12: 1, 13: 0})
        for z in (Fraction(1001, 1000), Fraction(13, 10), Fraction(3, 2)):
            zero, one, two = [domination_mgf(3, radius, z) for radius in (0, 1, 2)]
            self.assertEqual(zero, mgf_product(3, z))
            self.assertLessEqual(one ** 2, zero * two)

    def test_public_masks_and_all_output_rotations(self):
        # Exhaust every count and check no state/secret enters the assignment.
        for count in range(TOTAL + 1):
            mask = interleaved_widths(count)
            self.assertEqual(mask.count(12), count)
            per_block = [mask[b * 256:(b + 1) * 256].count(12) for b in range(6)]
            self.assertLessEqual(max(per_block) - min(per_block), 1)
        mask = interleaved_widths(384)
        # Every negacyclic output permutes secret entries; count of each error
        # radius stays the same, so the same one-coordinate MGF bound applies.
        for output in range(256):
            rotated = [mask[b * 256 + (output - j) % 256] for b in range(6) for j in range(256)]
            self.assertEqual(rotated.count(12), 384)

    def test_exact_threshold(self):
        self.assertTrue(exact_c05(Fraction(1, 1 << 175)))
        self.assertFalse(exact_c05(Fraction(1, 1 << 174)))
        with self.assertRaises(ValueError):
            interleaved_widths(TOTAL + 1)


if __name__ == "__main__":
    unittest.main()
