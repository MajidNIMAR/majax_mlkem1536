"""Checks against brute enumeration, rather than a second recurrence."""

from collections import Counter
from fractions import Fraction
import itertools
import math
import unittest

from noise_exact import (Law, analyze, cbd, combine, compress, decompress,
                         probability_record, symmetric_power)


class NoiseArithmeticTests(unittest.TestCase):
    def test_cbd_against_all_bit_strings(self):
        for eta in (1, 2, 3):
            histogram = Counter(sum(bits[:eta])-sum(bits[eta:])
                                for bits in itertools.product((0, 1), repeat=2*eta))
            self.assertEqual(cbd(eta), Law.counts(dict(histogram)))

    def test_recurrence_against_repeated_small_convolution(self):
        for base in (cbd(1), cbd(2), combine(cbd(1), cbd(2), product=True)):
            ordinary = Law.counts({0: 1})
            for exponent in range(1, 7):
                ordinary = combine(ordinary, base)
                offset, weights, denominator = symmetric_power(base, exponent)
                recurrence = {offset+i: Fraction(value, denominator)
                              for i, value in enumerate(weights) if value}
                reference = {x: Fraction(value, ordinary.denominator)
                             for x, value in ordinary.weights.items()}
                self.assertEqual(recurrence, reference)

    def test_exact_decoder_against_exhaustive_elementary_noise(self):
        q, du, dv = 17, 2, 2
        counts = (1, 2, 1)
        failures = [0, 0]
        for values in itertools.product(range(-1, 2), repeat=5):
            e, y, s, e1, e2 = values
            weight = math.prod(counts[x+1] for x in values)
            for u in range(q):
                ru = (decompress(compress(u, q, du), q, du)-u+q//2) % q-q//2
                for v in range(q):
                    rv = (decompress(compress(v, q, dv), q, dv)-v+q//2) % q-q//2
                    noise = e*y-s*(e1+ru)+e2+rv
                    for bit in (0, 1):
                        residue = (decompress(bit, q, 1)+noise) % q
                        failures[bit] += weight*(compress(residue, q, 1) != bit)
        result = analyze(n=1, k=1, q=q, eta1=1, eta2=1, du=du, dv=dv)
        for bit in (0, 1):
            expected = Fraction(failures[bit], (4**5)*q*q)
            self.assertEqual(result[f"bit{bit}_failure"], probability_record(expected))

    def test_fips_half_up_and_lossless_encoding(self):
        self.assertEqual(decompress(1, 3329, 1), 1665)
        self.assertEqual(decompress(1, 17, 1), 9)
        for q in (3329, 7681):
            bits = (q-1).bit_length()
            for x in range(q):
                self.assertEqual(decompress(compress(x, q, bits), q, bits), x)

    def test_invalid_recurrence_laws_rejected(self):
        with self.assertRaises(ValueError):
            symmetric_power(Law.counts({0: 1, 1: 1}), 4)
        with self.assertRaises(ValueError):
            symmetric_power(cbd(2), 0)

    def test_baseline_calibration_and_p0_rejection(self):
        baseline = analyze(256, 4, 3329, 2, 2, 11, 5)
        p0 = analyze(256, 6, 3329, 2, 2, 11, 5)
        self.assertLess(abs(baseline["message_union_bound_uniform_bits"]["log2"]+174.8), 0.5)
        # Even the single-coefficient event is above the project threshold.
        self.assertGreater(p0["message_lower_bound_single_coefficient"]["log2"], -174.8)


if __name__ == "__main__":
    unittest.main()
