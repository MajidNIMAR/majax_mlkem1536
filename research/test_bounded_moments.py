"""Literal oracles and exact propagation for H13 moment certificates."""

from collections import Counter
from fractions import Fraction as F
import itertools
import math
import unittest

from bounded_moments import certify,constant_certificate,enclose,fraction


class BoundedMomentTests(unittest.TestCase):
    def test_exact_constants_and_coordinate_majorant(self):
        self.assertEqual(constant_certificate()['gaussian_dyadic_factor'],42)
        for q in (5,17,7681):
            for x in range(q//2+1):
                upper=2.**(-(42*x*x//(q*q)))
                self.assertLessEqual(math.cos(math.pi*x/q)**6,upper+1e-15)

    def test_histogram_matches_ordered_literal_expansion(self):
        a=((1,0),(0,1),(1,1))
        got=certify(a,7,cap=12,chunk=1,batch_size=7)
        for p,order in enumerate(got['orders'],1):
            hist=Counter()
            zero=0
            for terms in itertools.product(range(6),repeat=p):
                net=Counter()
                for j in terms:
                    net[j//2]+=(-1)**(j%2)
                if not any(net.values()):
                    continue
                v=[(sum(net[j]*a[j][k] for j in range(3))+3)%7-3 for k in range(2)]
                norm=sum(x*x for x in v)
                hist[min(12,42*norm//49)]+=1
                zero+=norm==0
            self.assertEqual(order['attenuation_histogram'],{str(k):v for k,v in hist.items()})
            self.assertEqual(order['unbalanced_zero_coefficient_mass'],zero)
        self.assertGreaterEqual(got['orders'][2]['unbalanced_zero_coefficient_mass'],12)

    def test_small_weighted_cbd3_law(self):
        a=((1,1,2),(2,0,-1))
        labels=(1,2)
        got=certify(a,5,cap=128)
        states=list(itertools.product(range(-3,4),repeat=3))
        weights=[math.prod(math.comb(6,x+3) for x in z) for z in states]
        self.assertEqual(sum(weights),64**3)
        base=(0.,1/4,0.,9/64)
        for d in range(5):
            values=[sum(math.cos(2*math.pi*(sum(x*y for x,y in zip(v,z))-c*d)/5)
                        for v,c in zip(a,labels))/2 for z in states]
            for p in range(1,5):
                raw=math.fsum(w*s**p for w,s in zip(weights,values))/64**3
                bound=float(fraction(got['orders'][p-1]['raw_correction_absolute_bound']))
                self.assertLessEqual(abs(raw-base[p-1]),bound+2e-14)

    def test_early_stop_matches_all_coordinates(self):
        a=[[((j+1)*i+2*j)%17 for j in range(45)] for i in range(1,5)]
        early=certify(a,17,cap=5,chunk=2)
        full=certify(a,17,cap=5,chunk=145)
        self.assertGreater(sum(r['early_stopped_multisets'] for r in early['orders']),0)
        for x,y in zip(early['orders'],full['orders']):
            self.assertEqual({k:v for k,v in x.items() if k not in ('early_stopped_multisets','coordinates_evaluated')},
                             {k:v for k,v in y.items() if k not in ('early_stopped_multisets','coordinates_evaluated')})

    def test_rational_central_propagation_and_noninformative_case(self):
        N=32
        bounds=[F(1,2**k) for k in (20,25,30,35)]
        cert=enclose(N,bounds)
        base=3-F(3,2*N)
        for signs in itertools.product((-1,1),repeat=4):
            mu,c2,c3,c4=[s*b for s,b in zip(signs,bounds)]
            m2=F(1,2*N)+c2
            variance=m2-mu*mu
            fourth=F(3,4*N*N)-F(3,8*N**3)+c4-4*mu*c3+6*mu*mu*m2-3*mu**4
            self.assertLessEqual(abs(fourth/variance**2-base),fraction(cert['kurtosis_absolute_error_bound']))
        self.assertFalse(enclose(32,[F(1)]*4)['variance_positive_certified'])
        with self.assertRaises(ValueError):
            certify([[1.5]],5)


if __name__=='__main__':
    unittest.main()
