"""Independent arithmetic and exhaustive scalar checks for the M05 argument."""

from fractions import Fraction
from itertools import product
from math import comb
import unittest

from r1_security_bounds import (MESSAGE_SPACE, expanded_sampler_delta, inclusive_queries,
                                load_certificate, qrom_ow_obligation, qrom_terms,
                                qrom_total_upper, rom_pke_obligation, rom_terms, sqrt_interval)


class R1SecurityBoundsTests(unittest.TestCase):
    def test_implicit_calls_and_both_g_coordinates_are_counted(self):
        # 7 adversarial G512 + 11 Decaps + 1 challenge = 19 calls per G half.
        # The key/rejection oracle gets another 5 adversarial J + 11 Decaps.
        q = inclusive_queries(7, 5, 11)
        self.assertEqual((q["coins"], q["key_only"], q["key_and_rejection"], q["total_rom"]),
                         (19, 19, 35, 54))
        self.assertEqual(rom_terms(Fraction(1, 1000), 7, 5, 11)["correction_coefficient"], 119)
        quantum = qrom_terms(Fraction(1, 1000), 7, 5, 11)
        self.assertEqual((quantum["queries"]["qrom_coins"], quantum["queries"]["qrom_key"]), (26, 26))
        for bad in (-1, True, 1.5):
            with self.assertRaises(ValueError):
                inclusive_queries(bad, 0, 0)

    def test_rom_target_inversion_is_exact_and_unachievable_targets_are_rejected(self):
        delta = Fraction(1, 10000)
        target = Fraction(1, 8)
        terms = rom_terms(delta, 3, 5, 2)
        required = rom_pke_obligation(delta, 3, 5, 2, target)
        self.assertEqual(6 * required + terms["known_additive"], target)
        self.assertGreater(6 * (required + Fraction(1, MESSAGE_SPACE)) + terms["known_additive"], target)
        self.assertIsNone(rom_pke_obligation(delta, 3, 5, 2, terms["known_additive"] / 2))

    def test_integer_sqrt_enclosures_do_not_depend_on_decimal_rounding(self):
        for value in (Fraction(0), Fraction(1), Fraction(2, 3), Fraction(1, 7), Fraction(1, 1 << 255)):
            low, high = sqrt_interval(value, 256)
            self.assertLessEqual(low * low, value)
            self.assertGreaterEqual(high * high, value)
            self.assertLessEqual(high - low, Fraction(1, 1 << 256))
        self.assertEqual(sqrt_interval(Fraction(9, 64), 64), (Fraction(3, 8), Fraction(3, 8)))

    def test_qrom_obligation_uses_probability_not_cpa_bias(self):
        delta = Fraction(1, 10**9)
        terms = qrom_terms(delta, 3, 5, 2)
        prf = Fraction(1, 1 << 20)
        ow = Fraction(1, 1 << 24)
        target = terms["correction"] + prf + Fraction(terms["sqrt_ow_coefficient"], 1 << 12)
        self.assertEqual(qrom_ow_obligation(delta, 3, 5, 2, target, prf), ow)
        self.assertEqual(qrom_total_upper(delta, 3, 5, 2, ow, prf), target)
        self.assertIsNone(qrom_ow_obligation(delta, 3, 5, 2, terms["correction"] / 2, 0))

    def test_frozen_certificate_probability_is_checked_with_integers(self):
        delta = load_certificate()
        self.assertLess(delta, Fraction(1, 1 << 310))
        self.assertGreater(delta, Fraction(1, 1 << 311))
        self.assertEqual(expanded_sampler_delta(delta), delta * Fraction(MESSAGE_SPACE - 1, MESSAGE_SPACE))

    def test_cbd_three_splitting_and_conditional_mean_are_exact(self):
        one = {k: Fraction(comb(2, 1 + k), 4) for k in range(-1, 2)}
        two = {k: Fraction(comb(4, 2 + k), 16) for k in range(-2, 3)}
        for total in range(-3, 4):
            mass = sum((p * two.get(total - x, 0) for x, p in one.items()), Fraction(0))
            self.assertEqual(mass, Fraction(comb(6, 3 + total), 64))
            first_moment = sum((x * p * two.get(total - x, 0) for x, p in one.items()), Fraction(0))
            self.assertEqual(first_moment / mass, Fraction(total, 3))

    def test_expanded_oracle_collision_and_quantifiers_exhaustively(self):
        # Scalar q=17 fixture, CBD(1), two possible seeds, three nonces/seed.
        # This exhausts all 3^6 weighted oracle tables; it is NOT an R1 engine.
        values, weight = (-1, 0, 1), {-1: 1, 0: 2, 1: 1}
        independent_tail = Fraction(0)
        for s, e, r, e1, e2 in product(values, repeat=5):
            if abs(e * r - s * e1 + e2) >= 2:
                independent_tail += Fraction(weight[s] * weight[e] * weight[r] * weight[e1] * weight[e2], 4**5)
        mean_envelope, mean_worst_message, largest_fixed_envelope = Fraction(0), Fraction(0), Fraction(0)
        for table in product(values, repeat=6):
            table_probability = Fraction(1, 4**6)
            for value in table:
                table_probability *= weight[value]
            for key_seed in (0, 1):
                s, e = table[3 * key_seed:3 * key_seed + 2]
                envelope = Fraction(0)
                failure = [Fraction(0), Fraction(0)]
                for coin_seed in (0, 1):
                    r, e1, e2 = table[3 * coin_seed:3 * coin_seed + 3]
                    noise = e * r - s * e1 + e2
                    if key_seed == coin_seed:
                        self.assertEqual(noise, e2)
                    envelope += Fraction(abs(noise) >= 2, 2)
                    for message in (0, 1):
                        encoded = (17 * message + 1) // 2
                        public_key = (5 * s + e) % 17
                        u = (5 * r + e1) % 17
                        v = (public_key * r + e2 + encoded) % 17
                        compressed = ((4 * v + 8) // 17) % 4
                        decompressed = (17 * compressed + 2) // 4
                        recovered = ((2 * ((decompressed - s * u) % 17) + 8) // 17) % 2
                        failure[message] += Fraction(recovered != message, 2)
                self.assertLessEqual(max(failure), envelope)
                mean_envelope += table_probability * envelope / 2
                mean_worst_message += table_probability * max(failure) / 2
                largest_fixed_envelope = max(largest_fixed_envelope, envelope)
        self.assertEqual(mean_envelope, expanded_sampler_delta(independent_tail, seed_bits=1))
        self.assertLessEqual(mean_worst_message, mean_envelope)
        # Averaging over fixed oracle/key pairs cannot be replaced by a uniform bound.
        self.assertGreater(largest_fixed_envelope, mean_envelope)


if __name__ == "__main__":
    unittest.main()
