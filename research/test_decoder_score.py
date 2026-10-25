"""CBD identities, exact phases, geometric controls and shared-secret covariance."""

import itertools
import math
import unittest

from decoder_score import LN2, covariance, log_phi, phase_weights


class DecoderScoreTests(unittest.TestCase):
    def test_phase_law_by_cbd_bit_enumeration(self):
        for eta in (1, 2, 3):
            q, r = 5, (1, -2)
            counts = [0] * q
            for bits in itertools.product((0, 1), repeat=4 * eta):
                s1 = sum(bits[:eta]) - sum(bits[eta:2*eta])
                s2 = sum(bits[2*eta:3*eta]) - sum(bits[3*eta:])
                counts[(s1 * r[0] + s2 * r[1]) % q] += 1
            self.assertEqual(counts, phase_weights(r, q, eta))
            mean = sum(c * math.cos(2 * math.pi * i / q) for i, c in enumerate(counts)) / 2 ** (4 * eta)
            self.assertAlmostEqual(mean, math.exp(log_phi(r, q, eta)), places=13)

    def test_gaussian_upper_and_periodicity(self):
        for q in (3, 5, 7):
            for r in itertools.product(range(-q//2 + 1, q//2 + 1), repeat=2):
                for eta in (1, 2, 3):
                    exact = log_phi(r, q, eta)
                    upper = -eta * math.pi ** 2 * sum(v * v for v in r) / q ** 2
                    self.assertLessEqual(exact, upper + 1e-12)
                    self.assertAlmostEqual(exact, log_phi([v + q for v in r], q, eta), places=13)

    def test_equal_norm_is_not_equal_cbd_bias(self):
        a, b = (3000, 0), (1800, 2400)
        self.assertEqual(sum(v*v for v in a), sum(v*v for v in b))
        self.assertGreater(abs(log_phi(a, 7681, 3) - log_phi(b, 7681, 3)), 0.1)

    def test_shared_secret_pair_covariance(self):
        q, eta, a, b = 7, 1, (1, 2), (2, -1)
        values = []
        for bits in itertools.product((0, 1), repeat=4):
            s = (bits[0]-bits[1], bits[2]-bits[3])
            values.append(tuple(math.cos(2 * math.pi * sum(x*y for x, y in zip(s, r)) / q) for r in (a, b)))
        expected = sum(x*y for x,y in values)/16 - sum(x for x,_ in values)*sum(y for _,y in values)/256
        result = covariance(a, b, q, eta)
        actual = 0 if not result["sign"] else result["sign"] * 2 ** result["log2_abs"]
        self.assertAlmostEqual(expected, actual, places=13)

    def test_antipodal_and_disjoint_scores(self):
        a = (1, 2, 0)
        self.assertEqual(covariance(a, tuple(-v for v in a), 7, 1), covariance(a, a, 7, 1))
        self.assertEqual(covariance((1, 0), (0, 1), 7, 1)["sign"], 0)
        self.assertEqual(log_phi((0, 0), 7, 3) / LN2, 0)


if __name__ == "__main__":
    unittest.main()
