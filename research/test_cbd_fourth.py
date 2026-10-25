"""Population moment controls by exhaustive weighted CBD states."""

import itertools
import math
import unittest

from cbd_fourth import population,centered_moments
from real_dual import numpy


class CBDFourthTests(unittest.TestCase):
    def test_all_243_states_and_five_offsets(self):
        a=[[1,0,1,-1,2],[0,1,2,1,1],[1,1,-2,0,-1]]
        c=[[1],[2],[3]]
        result=population(a,c,[[d] for d in range(5)],5,1)
        states=list(itertools.product((-1,0,1),repeat=5))
        weights=[2**z.count(0) for z in states]
        self.assertEqual(sum(weights),4**5)
        for d,row in enumerate(result['offsets']):
            values=[sum(math.cos(2*math.pi*((sum(v*t for v,t in zip(x,z))-label[0]*d)%5)/5)
                        for x,label in zip(a,c))/3 for z in states]
            mean=sum(v*w for v,w in zip(values,weights))/4**5
            for p in range(1,5):
                raw=sum(v**p*w for v,w in zip(values,weights))/4**5
                self.assertAlmostEqual(raw,row['orders'][p-1]['raw_moment'],places=13)
            variance=sum((v-mean)**2*w for v,w in zip(values,weights))/4**5
            fourth=sum((v-mean)**4*w for v,w in zip(values,weights))/4**5
            self.assertAlmostEqual(row['central']['variance'],variance,places=13)
            self.assertAlmostEqual(row['central']['fourth'],fourth,places=13)
            self.assertAlmostEqual(row['central']['kurtosis'],fourth/variance**2,places=12)

    def test_nontrivial_zero_coefficient_is_counted(self):
        a=[[1,0],[0,1],[1,1]]
        result=population(a,[[1],[2],[3]],[[0],[1]],7,3,require_zero_label=True)
        self.assertGreaterEqual(result['counts'][2]['unbalanced_zero_coefficient_mass'],12)
        self.assertEqual(result['counts'][2]['balanced_ordered_mass'],0)
        for p,stats in enumerate(result['counts'],1):
            self.assertEqual(stats['total_ordered_mass'],6**p)
        with self.assertRaises(ArithmeticError):
            population(a,[[1],[2],[4]],[[0]],7,3,require_zero_label=True)

    def test_central_correction_survives_float_underflow(self):
        zero=dict(sign=0,log2_abs=None)
        orders=[dict(correction=zero) for _ in range(3)]+[dict(correction=dict(sign=1,log2_abs=-1200.))]
        result=centered_moments(orders,16)
        self.assertEqual(result['kurtosis'],3-3/32)
        self.assertEqual(result['kurtosis_delta_vs_independent']['value'],0.)
        self.assertEqual(result['kurtosis_delta_vs_independent']['sign'],1)
        self.assertAlmostEqual(result['kurtosis_delta_vs_independent']['log2_abs'],-1190.)

    def test_unsupported_inputs_rejected(self):
        for args in (([[1]],[[1]],[[0]],5,1.5),([[1.5]],[[1]],[[0]],5,1),
                     ([[1]]*17,[[1]]*17,[[0]],5,1)):
            with self.assertRaises(ValueError):
                population(*args)


if __name__=='__main__':
    unittest.main()
