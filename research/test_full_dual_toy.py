"""Dual relations, phase decomposition, Fourier and certified decisions."""

import itertools
import math
import unittest

from full_dual_toy import COS_SCALE,DENOMINATOR,compare_scores,dual_list,evaluate,lwe_law,matrix,passes,score_table
from cbd_decoder import SCALE


class FullDualToyTests(unittest.TestCase):
    def setUp(self):
        self.q=5
        self.costs=[0]+[int(SCALE*(-2*math.log(math.cos(math.pi*d/5)))) for d in (1,2)]
        self.cosines=[COS_SCALE]+[math.floor(COS_SCALE*math.cos(2*math.pi*d/5)) for d in (1,2)]

    def test_dual_relation_sign_pairs_and_nested_lists(self):
        A=matrix(5,0)
        small=dual_list(A,5,4,"radix","cbd",self.costs)
        large=dual_list(A,5,8,"radix","cbd",self.costs)
        self.assertEqual(small["vectors"],large["vectors"][:4])
        ys=[tuple(v["y"]) for v in large["vectors"]]
        self.assertEqual(len(set(ys)),8)
        for row in large["vectors"]:
            self.assertEqual((sum(a[0]*y for a,y in zip(A,row["y"]))-row["x"])%5,0)
            self.assertNotIn(tuple(-y for y in row["y"]),ys)

    def test_public_and_noise_phase_agree(self):
        A=matrix(5,0)
        bank=dual_list(A,5,4,"radix","euclidean",self.costs)
        g=bank["code"]["generators"][0]
        for state in itertools.product((-1,0,1),repeat=7):
            b=[(sum(a*s for a,s in zip(line,state[2:]))+e)%5 for line,e in zip(A,state[:2])]
            u=sum(a*s for a,s in zip(g,state[3:]))%5
            for row in bank["vectors"]:
                self.assertEqual((sum(a*x for a,x in zip(row["y"],b))-row["c"]*u)%5,
                                 sum(a*x for a,x in zip(row["coefficient"],state))%5)

    def test_complete_score_moments_and_null_control(self):
        bank=dual_list(matrix(5,1),5,8,"radix","cbd",self.costs)
        law=lwe_law(bank["A"],bank["code"]["generators"][0],5)
        self.assertEqual(sum(r["weight"] for r in law),DENOMINATOR)
        table,delta=score_table(bank,self.cosines)
        self.assertLess(delta,1e-12)
        result=evaluate(bank,law,table,self.cosines)
        self.assertAlmostEqual(result["uniform_null"]["variance"],1/16)
        self.assertLessEqual(result["strict_success"]["value"],result["uniform_tie_success"]["value"])
        self.assertLessEqual(result["uniform_tie_success"]["value"],result["true_in_argmax"]["value"])

    def test_unresolved_decisions_are_rejected(self):
        self.assertEqual(compare_scores([2,0,0],[2,0,0],self.cosines,2),0)
        self.assertTrue(passes([4,0,0],0,self.cosines,4))
        with self.assertRaises(ArithmeticError):
            compare_scores([1,0],[0,1],[0,0],1)
        with self.assertRaises(ArithmeticError):
            passes([0,1],0,[0,-1],4)


if __name__=="__main__":
    unittest.main()
