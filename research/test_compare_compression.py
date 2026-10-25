"""Exact target boundaries and explicit scope of attack reuse."""

from fractions import Fraction
import unittest

from compare_compression import PARAMETERS, attack_mapping, target_met


class ComparisonTests(unittest.TestCase):
    def test_exact_target_boundary(self):
        self.assertTrue(target_met(Fraction(1, 2 ** 200), Fraction(200)))
        self.assertFalse(target_met(Fraction(1, 2 ** 200) + Fraction(1, 2 ** 400), Fraction(200)))
        self.assertTrue(target_met(Fraction(1, 2 ** 175), Fraction(874, 5)))
        self.assertFalse(target_met(Fraction(1, 2 ** 174), Fraction(874, 5)))
        with self.assertRaises(ValueError):
            target_met(Fraction(-1), Fraction(200))

    def test_mapping_preserves_attack_assumptions(self):
        mapping = attack_mapping()
        self.assertFalse(mapping['new_costs_computed'])
        self.assertEqual(len(mapping['references']), 30)
        self.assertEqual(len(mapping['minima']), 4)
        for row in mapping['references']:
            self.assertEqual(row['job']['parameters'], PARAMETERS)
            self.assertEqual(row['job']['oracle'], 'none')
            self.assertEqual(row['job']['targets'], 1)
        self.assertTrue(all(row['algorithm'] == 'dual_hybrid' for row in mapping['minima']))


if __name__ == '__main__':
    unittest.main()
