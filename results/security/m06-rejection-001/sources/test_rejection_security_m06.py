"""Independent finite game enumerations and exact inequalities for M06 J.

These are mathematical fixtures, not an implementation or benchmark of R1.
No test purports to enumerate a general quantum adversary.
"""

from collections import Counter
from fractions import Fraction
from itertools import product
import unittest

from rejection_security_m06 import (one_candidate_gap, query_limits_for_gap,
                                    rejection_bounds)


def finite_transcript_laws(keys, messages, alphabet, strategy):
    """Enumerate every H, R and z, independently of the bound implementation."""
    real, ideal = Counter(), Counter()
    cells = keys * messages
    for table in product(range(alphabet), repeat=cells):
        h = lambda k, m: table[k * messages + m]
        for z in range(keys):
            f = lambda m: h(z, m)
            real[strategy(h, f)] += Fraction(1, alphabet**cells * keys)
        for random_row in product(range(alphabet), repeat=messages):
            f = lambda m: random_row[m]
            ideal[strategy(h, f)] += Fraction(1, alphabet ** (cells + messages))
    return real, ideal


def total_variation(first, second):
    return sum((abs(first[key] - second[key]) for key in first.keys() | second.keys()),
               Fraction(0)) / 2


class RejectionSecurityTests(unittest.TestCase):
    def test_exact_gap_budgets_and_edge_cases(self):
        actual = rejection_bounds(1 << 64, 1 << 64)
        self.assertEqual(actual, dict(rom=Fraction(1, 1 << 192),
                                     qrom=Fraction(1, 1 << 63)))
        self.assertEqual(rejection_bounds(1 << 300, 0), dict(rom=0, qrom=0))
        self.assertEqual(rejection_bounds(0, 1 << 300), dict(rom=0, qrom=0))
        self.assertEqual(rejection_bounds(1 << 300, 1), dict(rom=1, qrom=1))
        for bad in (-1, True, 1.5):
            with self.assertRaises(ValueError):
                rejection_bounds(bad, 1)
            with self.assertRaises(ValueError):
                rejection_bounds(1, bad)
        for bad in (0, 255, True):
            with self.assertRaises(ValueError):
                rejection_bounds(1, 1, bad)

    def test_allocation_limits_use_exact_gap_not_cca_bias(self):
        limits = query_limits_for_gap(Fraction(1, 1 << 130))
        self.assertEqual(limits, dict(rom_max_public_queries=1 << 126,
                                     qrom_max_public_queries=0))
        # At each returned endpoint the stated sufficient inequality holds;
        # one further query violates THIS bound, not necessarily security.
        gap = Fraction(3, 32)
        limits = query_limits_for_gap(gap, 12)
        for model in ("rom", "qrom"):
            maximum = limits[model + "_max_public_queries"]
            self.assertLessEqual(rejection_bounds(maximum, 1, 12)[model], gap)
            self.assertGreater(rejection_bounds(maximum + 1, 1, 12)[model], gap)

    def test_full_toy_distributions_for_repetition_and_no_indexed_access(self):
        for keys in (2, 3):
            # Seeing the entire tiny public table still reveals no hidden
            # correlation if the indexed interface is never used.
            def no_indexed(h, f):
                return tuple(h(k, m) for k in range(keys) for m in range(2))

            real, ideal = finite_transcript_laws(keys, 2, 2, no_indexed)
            self.assertEqual(real, ideal)

            def repeated_indexed(h, f):
                return f(0), f(0), f(1), f(1)

            real, ideal = finite_transcript_laws(keys, 2, 2, repeated_indexed)
            self.assertEqual(real, ideal)
            self.assertEqual(sum(real.values()), 1)
            self.assertEqual(sum(ideal.values()), 1)

    def test_one_candidate_exact_gap_and_accidental_output_matches(self):
        for keys, alphabet in ((2, 2), (4, 2), (2, 4)):
            def strategy(h, f):
                return h(0, 0), f(0)

            real, ideal = finite_transcript_laws(keys, 1, alphabet, strategy)
            gap = total_variation(real, ideal)
            expected = Fraction(1, keys) * (1 - Fraction(1, alphabet))
            self.assertEqual(gap, expected)
            self.assertLessEqual(gap, Fraction(1, keys))
            self.assertGreater(sum(p for (x, y), p in ideal.items() if x == y), 0)
        self.assertEqual(one_candidate_gap(2, 1), Fraction(1, 8))

    def test_two_distinct_ciphertexts_do_not_require_a_birthday_penalty(self):
        def strategy(h, f):
            return h(0, 0), h(0, 1), f(0), f(1)

        real, ideal = finite_transcript_laws(4, 2, 2, strategy)
        self.assertEqual(total_variation(real, ideal), one_candidate_gap(2, 1, 2))
        # Adding an unrelated birthday term would obscure the exact coupling:
        # both worlds contain ordinary collisions of the random indexed row.
        self.assertEqual(sum(p for (_, _, x, y), p in real.items() if x == y), Fraction(1, 2))
        self.assertEqual(sum(p for (_, _, x, y), p in ideal.items() if x == y), Fraction(1, 2))

    def test_adaptive_public_and_indexed_queries_are_covered(self):
        def strategy(h, f):
            first = f(0)
            value = h(0, 0)
            next_key = 1 if value == first else 2
            # Input and second candidate are selected from the transcript.
            next_message = value ^ first
            second = f(next_message)
            other = h(next_key, next_message)
            return first, value, next_key, next_message, second, other

        real, ideal = finite_transcript_laws(3, 2, 2, strategy)
        gap = total_variation(real, ideal)
        self.assertGreater(gap, 0)
        self.assertLessEqual(gap, Fraction(2, 3))
        # q/N is an upper bound for all strategies, not an equality claim.
        self.assertLess(gap, Fraction(2, 3))

    def test_coherent_global_namespace_and_oracle_difference_norm(self):
        # Rational amplitudes before normalization: |J,k0,->, |J,k1,->,
        # |N,k0,->. The row replacement multiplies selected |-> by -1.
        # Thus ||(U'-U)psi||^2=4*weight(secret J row), exactly.
        amplitudes = {("J", 0, 0): Fraction(3), ("J", 0, 1): Fraction(-3),
                      ("J", 1, 0): Fraction(2), ("J", 1, 1): Fraction(-2),
                      ("N", 0, 0): Fraction(4), ("N", 0, 1): Fraction(-4)}
        norm_squared = sum(a * a for a in amplitudes.values())
        keys = 4
        average_row_weight, average_difference_squared = Fraction(0), Fraction(0)
        for z in range(keys):
            weight = sum(a * a for (domain, key, _), a in amplitudes.items()
                         if domain == "J" and key == z) / norm_squared
            changed = {}
            for (domain, key, answer), amplitude in amplitudes.items():
                basis = (domain, key, answer ^ int(domain == "J" and key == z))
                changed[basis] = amplitude
            difference = sum((changed.get(basis, 0) - amplitudes.get(basis, 0)) ** 2
                             for basis in changed.keys() | amplitudes.keys()) / norm_squared
            self.assertEqual(difference, 4 * weight)
            average_row_weight += weight / keys
            average_difference_squared += difference / keys
        self.assertEqual(average_row_weight, Fraction(13, 116))
        self.assertLessEqual(average_row_weight, Fraction(1, keys))
        self.assertEqual(average_difference_squared, 4 * average_row_weight)

    def test_one_query_quantum_measurement_exhaustively(self):
        # Prepare uniform |key>|0>, query H, then project onto uniform
        # |key>|r>, where r is the one classical indexed response.
        # Acceptance probability is (#matching table entries / N)^2.
        # This retains cross terms between keys, rather than measuring the
        # query register as a classical candidate. All tables are exhausted.
        keys = 4
        real, ideal = Fraction(0), Fraction(0)
        for table in product(range(2), repeat=keys):
            for z in range(keys):
                r = table[z]
                matches = sum(value == r for value in table)
                real += Fraction(matches**2, keys**2 * keys * 2**keys)
            for r in range(2):
                matches = sum(value == r for value in table)
                ideal += Fraction(matches**2, keys**2 * 2 * 2**keys)
        self.assertEqual(real, Fraction(7, 16))
        self.assertEqual(ideal, Fraction(5, 16))
        self.assertEqual(real - ideal, Fraction(1, 8))
        self.assertLessEqual(real - ideal, rejection_bounds(1, 1, 2)["qrom"])


if __name__ == "__main__":
    unittest.main()
