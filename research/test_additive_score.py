"""Exact torus controls for additive moment identities and greedy choices."""

from fractions import Fraction
import itertools
import math
import unittest

from additive_score import exact_moments,pair_counts,greedy_order,signed


def as_fraction(r):
    return Fraction(r['numerator'],r['denominator'])


class AdditiveScoreTests(unittest.TestCase):
    def test_all_49_observations_match_moments(self):
        q=7
        ys=[(1,0),(0,1),(1,1),(2,0)]
        result=exact_moments(ys,q)
        values=[sum(math.cos(2*math.pi*sum(a*x for a,x in zip(y,b))/q) for y in ys)/len(ys)
                for b in itertools.product(range(q),repeat=2)]
        for power,key in ((1,'mean'),(2,'variance'),(3,'third'),(4,'fourth')):
            self.assertAlmostEqual(sum(x**power for x in values)/q**2,float(as_fraction(result[key])),places=13)
        self.assertGreater(result['ordered_signed_triples'],0)
        self.assertGreater(result['extra_quadruples'],0)

    def test_independent_cosines_exact_baseline(self):
        result=exact_moments([(1,0,0),(0,1,0),(0,0,1)],17)
        self.assertEqual(result['extra_quadruples'],0)
        self.assertEqual(result['ordered_signed_triples'],0)
        self.assertEqual(as_fraction(result['kurtosis']),Fraction(5,2))
        self.assertEqual(as_fraction(result['fourth']),Fraction(5,72))

    def test_every_small_greedy_choice_against_full_recomputation(self):
        ys=[(1,0),(0,1),(1,1),(2,0),(1,2),(3,1)]
        order,trace=greedy_order(ys,17)
        selected=[]
        for i,record in zip(order,trace):
            options=[]
            for j in range(len(ys)):
                if j not in selected:
                    P=pair_counts([ys[k] for k in selected+[j]],17)
                    options.append((sum(x*x for x in P.values()),j))
            energy,chosen=min(options)
            self.assertEqual((record['energy'],i),(energy,chosen))
            self.assertEqual(record['candidate_evaluations'],len(options))
            selected.append(i)
        self.assertEqual(sorted(order),list(range(len(ys))))

    def test_invalid_uniform_frequencies_rejected(self):
        for ys in ([(0,0)],[(1,0),(-1,0)],[(1,0),(18,0)]):
            with self.assertRaises(ValueError):
                signed(ys,17)


if __name__=='__main__':
    unittest.main()
