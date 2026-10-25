"""General LLL, bit-exact CBD laws, int64 budget and full-score controls."""

from collections import Counter
import copy
import itertools
import json
from pathlib import Path
import unittest

from exact_lll import reduce_basis
from higher_cbd import array_hash,case_data,evaluate,law,make_bank,numpy,score_data
from lll_dimensions import reduce,verify


class HigherCBDTests(unittest.TestCase):
    def test_dimension_three_calibration_and_dimension_five_certificate(self):
        B=[[1,0,16],[0,1,9],[0,0,17]]
        old,new=reduce_basis(B),reduce(B)
        for key in ("reduced","unimodular","trace","iterations"):
            self.assertEqual(old[key],new[key])
        case=case_data(3,2,0)
        self.assertTrue(verify(case["reduction"]))
        bad=copy.deepcopy(case["reduction"])
        bad["unimodular"][0][0]+=1
        with self.assertRaises(ValueError):
            verify(bad)

    def test_CBD2_CBD3_against_literal_bit_weights_and_full_small_states(self):
        np=numpy()
        A=[[1,2,4]]
        g=[1,2]
        for eta in (1,2,3):
            scalar=Counter(sum(bits[:eta])-sum(bits[eta:]) for bits in itertools.product((0,1),repeat=2*eta))
            expected=np.zeros((5,5),dtype=np.int64)
            for e,s0,s1,s2 in itertools.product(range(-eta,eta+1),repeat=4):
                b=(e+s0+2*s1+4*s2)%5
                u=(s1+2*s2)%5
                expected[b,u]+=scalar[e]*scalar[s0]*scalar[s1]*scalar[s2]
            actual=law(A,g,eta,5)
            self.assertTrue(np.array_equal(actual,expected))
            self.assertEqual(int(actual.sum()),1<<(8*eta))
            self.assertEqual(array_hash(actual),array_hash(actual.astype('>i8')))

    def test_int64_budget_and_invalid_distribution(self):
        with self.assertRaises(ValueError):
            law([[0]*11 for _ in range(3)],[1]*4,3)
        with self.assertRaises(ValueError):
            law([[1,2,3]],[1,2],4)

    def test_complete_higher_dimension_CBD3_score_and_moments(self):
        root=Path(__file__).resolve().parents[1]
        t=next(x for x in json.loads((root/'results/j2/run-013/transcendental-tables.json').read_text()) if x['q']==17)
        case=case_data(3,2,0)
        bank=make_bank(case,'lll_box',4,'radix','cbd',t['cbd_weights'])
        weights=law(case['A'],bank['g'],3)
        self.assertEqual(int(weights.sum()),1<<54)
        data=score_data(bank,t['cosine_weights'])
        result=evaluate(bank,weights,data,3)
        self.assertAlmostEqual(result['uniform_null']['variance'],1/8)
        self.assertLessEqual(result['strict_success']['value'],result['uniform_tie_success']['value'])
        self.assertLessEqual(result['uniform_tie_success']['value'],result['true_in_argmax']['value'])


if __name__=='__main__':
    unittest.main()
