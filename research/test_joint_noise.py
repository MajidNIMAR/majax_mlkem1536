import unittest
from fractions import Fraction

from joint_noise_check import experiment, negacyclic


class JointNoiseTests(unittest.TestCase):
    def test_product_reduces_x_squared_to_minus_one(self):
        # (1+2X)(3+4X) modulo X^2+1 = -5+10X.
        self.assertEqual(negacyclic((1, 2), (3, 4)), [-5, 10])

    def test_joint_enumeration_distinguishes_covariance_and_independence(self):
        result = experiment()
        self.assertEqual(Fraction(result["covariance_c0_c1"]), 0)
        self.assertNotEqual(Fraction(result["covariance_squared_coefficients"]), 0)
        self.assertNotEqual(Fraction(result["joint"]), Fraction(result["independence_prediction_joint"]))
        self.assertLessEqual(Fraction(result["actual_union"]), Fraction(result["union_bound"]))


if __name__ == "__main__":
    unittest.main()
