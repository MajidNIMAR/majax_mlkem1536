"""Independent algebra and exhaustive checks for the u-dependence study."""

from collections import Counter
from fractions import Fraction
import itertools
import unittest

from noise_exact import cbd, combine, symmetric_power
from u_dependency import image_counts, meets_c05, negacyclic, toy_coset_study


class UDependencyTests(unittest.TestCase):
    def test_images_against_crt_coordinate_enumeration(self):
        # y=(1+2x,1+3x) has no unit component, but generates the full ring.
        # Independent multiplication via evaluation at roots 2,3, followed
        # by CRT inversion, checks the coefficient convolution implementation.
        ring = list(itertools.product(range(5), repeat=2))
        for y in (((0, 0),), ((1, 2),), ((1, 2), (1, 3))):
            expected = Counter()
            for vector in itertools.product(ring, repeat=len(y)):
                values = [sum((a[0] + root * a[1]) * (b[0] + root * b[1])
                              for a, b in zip(vector, y)) % 5 for root in (2, 3)]
                linear = (values[1] - values[0]) % 5
                constant = (values[0] - 2 * linear) % 5
                expected[constant, linear] += 1
            self.assertEqual(image_counts(y, 5), expected)
        self.assertEqual(negacyclic((0, 1), (0, 1), 5), (4, 0))
        self.assertEqual(len(image_counts(((1, 2), (1, 3)), 5)), 25)

    def test_exact_toy_conditional_and_unconditional_laws(self):
        for rank in (1, 2):
            result = toy_coset_study(rank)
            self.assertEqual(result["y_vectors_checked"], 25 ** rank)
            self.assertEqual(result["joint_tv_conditioned_on_full_ideal"]["fraction"], "0")
            self.assertGreater(Fraction(result["joint_rounding_e1_tv_from_independent_reference"]["fraction"]), 0)
            self.assertGreater(Fraction(result["joint_tv_from_product_of_actual_marginals"]["fraction"]), 0)
            self.assertEqual(sum(row["weight"] for row in result["joint_counts"]), result["denominator"])

    def test_threshold_comparison_without_logarithms(self):
        self.assertTrue(meets_c05(Fraction(1, 1 << 175)))
        self.assertFalse(meets_c05(Fraction(1, 1 << 174)))
        self.assertTrue(meets_c05(Fraction(0)))
        with self.assertRaises(ValueError):
            meets_c05(Fraction(-1))

    def test_intrinsic_shortcut_against_four_separate_cbd_products(self):
        secret = cbd(1)
        product = combine(secret, secret, product=True)
        combined = combine(product, product)
        for count in (1, 2, 4):
            left = symmetric_power(product, 2 * count)
            right = symmetric_power(combined, count)
            self.assertEqual(left[0], right[0])
            self.assertEqual([Fraction(x, left[2]) for x in left[1]],
                             [Fraction(x, right[2]) for x in right[1]])


if __name__ == "__main__":
    unittest.main()
