"""Checks on valid moment bounds and rejection of unsupported inputs."""

import math
import unittest

from score_transfer import cantelli_budget, covariance_budget, normal_budget, sufficient_list


class ScoreTransferTests(unittest.TestCase):
    def test_cantelli_sharp_two_point_distribution(self):
        # X=2 with probability 1/5, X=-1/2 otherwise: E=0, Var=1.
        mean=.2*2+.8*(-.5)
        variance=.2*4+.8*.25
        self.assertEqual(mean,0)
        self.assertEqual(variance,1)
        # N=1/2 gives baseline variance 1/(2N)=1; threshold 2.
        self.assertAlmostEqual(2**cantelli_budget(0,-1,1),.2)
        required=sufficient_list(3,-2)
        self.assertAlmostEqual(cantelli_budget(3,required,-2),math.log2(.05))

    def test_covariance_accounts_for_ordered_pairs(self):
        N=8
        for excess in (.01,.1,1):
            c=2**covariance_budget(math.log2(N),excess)
            variance=(N*.5+N*(N-1)*c)/N**2
            self.assertAlmostEqual(variance/(.5/N),1+excess)
        # Eight identical centered variables of variance 1/2: excess N-1.
        self.assertAlmostEqual(2**covariance_budget(3,7),.5)

    def test_invalid_assumptions_and_tail_underflow(self):
        for args in ((0,3,-1,0),(0,3,-1,float('nan'))):
            with self.assertRaises(ValueError):
                normal_budget(*args)
        with self.assertRaises(ValueError):
            covariance_budget(0,.1)
        with self.assertRaises(ValueError):
            sufficient_list(3,-2,1)
        with self.assertRaises(ArithmeticError):
            normal_budget(0,20,0)


if __name__=='__main__':
    unittest.main()
