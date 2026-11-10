"""Fault-oriented checks for the independent R1 correctness bridge."""

from collections import Counter
from copy import deepcopy
from fractions import Fraction
import itertools
import json
import unittest

from verify_r1_certificate_bridge import (ROOT, Q, cbd_bits, compress, decompress,
                                          multiply, quantizer_contract, verify_certificate,
                                          verify_static_contract, verify_vector)


class CertificateBridgeTests(unittest.TestCase):
    def test_bits_cbd_all_64_patterns_and_disjoint_word_slices(self):
        words = [cbd_bits(i) for i in range(64)]
        self.assertEqual(Counter(words), {-3: 1, -2: 6, -1: 15, 0: 20, 1: 15, 2: 6, 3: 1})
        # Joint law of two disjoint six-bit coefficients is exactly a product.
        joint = Counter((cbd_bits(word & 63), cbd_bits(word >> 6)) for word in range(4096))
        for a, na in Counter(words).items():
            for b, nb in Counter(words).items():
                self.assertEqual(joint[a, b], na * nb)

    def test_decoder_support_and_first_unsafe_upper_boundary(self):
        result = quantizer_contract()
        self.assertEqual(result["decoder_intervals"], [[-1920, 1920], [-1920, 1919]])
        self.assertEqual(result["common_safe_radius"], 1799)
        self.assertEqual(result["v_error_range"], [-120, 120])
        self.assertEqual(compress((decompress(1, 1) + 1799 + 120) % Q, 1), 1)
        self.assertEqual(compress((decompress(1, 1) + 1800 + 120) % Q, 1), 0)

    def test_exact_certificate_and_tampering_rejected(self):
        saved = json.loads((ROOT / "results/j2/run-004/correctness-certificate.json").read_text())
        result = verify_certificate(saved)
        self.assertTrue(result["exact_upper_at_most_2_pow_minus_310"])
        for field, value in (("common_safe_radius", 1800), ("one_sided_tail_threshold", 1801),
                             ("tilt_z", "14/10"), ("v_error_range", [-119, 120])):
            bad = deepcopy(saved)
            bad[field] = value
            with self.assertRaises(ValueError):
                verify_certificate(bad)
        bad = deepcopy(saved)
        bad["mgf_product"]["numerator_hex"] = "1"
        with self.assertRaises(ValueError):
            verify_certificate(bad)

    def test_negacyclic_sign_and_transpose_cancellation_exhaustive_small_ring(self):
        n = 3
        # Basis products exhaust all reductions X^i X^j including wrap signs.
        for i, j in itertools.product(range(n), repeat=2):
            a, b, expected = [0] * n, [0] * n, [0] * n
            a[i], b[j] = 1, 1
            expected[(i + j) % n] = -1 if i + j >= n else 1
            self.assertEqual(multiply(a, b), expected)
        # The ring is commutative; expand every matrix/s/r basis triple.
        for ai, sj, rj in itertools.product(range(n), repeat=3):
            a, s, r = [0] * n, [0] * n, [0] * n
            a[ai], s[sj], r[rj] = 1, 1, 1
            self.assertEqual(multiply(multiply(a, s), r), multiply(s, multiply(a, r)))

    def test_shared_secret_wrong_ideal_independence_not_assumed(self):
        # s reused in both terms: (s*a)+(s*b) has a different MGF from
        # two independent products. This catches invalid blanket independence.
        samples = (-1, 0, 0, 1)
        z = Fraction(13, 10)
        shared = sum((z ** (s * a + s * b) for s, a, b in itertools.product(samples, repeat=3)), Fraction()) / 64
        independent = (sum((z ** (s * a) for s, a in itertools.product(samples, repeat=2)), Fraction()) / 16) ** 2
        self.assertNotEqual(shared, independent)

    def test_source_contract_rejects_sampler_and_rounding_regression(self):
        source = (ROOT / "crates/kem1536/src/dev_kem.rs").read_text()
        verify_static_contract(source)
        for before, after in (("xof::<192>", "xof::<191>"),
                              ("noise(seed, 12)", "noise(seed, 11)"),
                              ("Q / 2", "Q / 2 + 1")):
            self.assertIn(before, source)
            with self.assertRaises(ValueError):
                verify_static_contract(source.replace(before, after))

    def test_synthetic_vector_reconstruction_and_bit_flip(self):
        import gzip
        with gzip.open(ROOT / "results/engine/r1-001/vectors.jsonl.gz", "rt") as stream:
            row = json.loads(next(stream))
        result = verify_vector(row)
        self.assertEqual(result["coefficients_checked"], 256)
        bad = deepcopy(row)
        bad["ek"][0] ^= 1
        with self.assertRaisesRegex(ValueError, "honest-key"):
            verify_vector(bad)


if __name__ == "__main__":
    unittest.main()
