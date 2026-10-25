"""Full CBD moment calibration by literal finite-state enumeration."""

from copy import deepcopy
import itertools
import math
import unittest

from real_dual import numpy,kernels,analytic,validate_bank,statistics,field_rank


def small_bank():
    q=5
    A=[[1,2,4],[2,3,1]]
    vectors=[]
    center=lambda x:(x+2)%q-2
    for y in ([1,0],[0,1],[1,1]):
        x=[center(sum(a*row[0] for a,row in zip(y,A)))]
        t=[sum(a*row[j] for a,row in zip(y,A))%q for j in (1,2)]
        c=min(range(q),key=lambda c:(sum(center(a-c)**2 for a in t),c))
        vectors.append(dict(y=y,x=x,t=t,c=[c],r=[center(a-c) for a in t]))
    return dict(q=q,eta=1,m=2,l=1,A=A,
                code=dict(n=2,k=1,generators=[[1,1]]),vectors=vectors)


class RealDualTests(unittest.TestCase):
    def test_full_moments_against_all_243_CBD_states(self):
        np=numpy()
        b=small_bank()
        self.assertTrue(validate_bank(b))
        k=kernels(b)
        c=np.asarray([v['c'] for v in b['vectors']],dtype=np.int64)
        states=list(itertools.product((-1,0,1),repeat=5))
        weights=[2**s.count(0) for s in states]
        self.assertEqual(sum(weights),4**5)
        for d in range(5):
            values=[]
            for s in states:
                e,secret=s[:2],s[2:]
                public=[(sum(a*t for a,t in zip(row,secret))+v)%5 for row,v in zip(b['A'],e)]
                truth=sum(secret[1:])%5
                direct=[sum(a*z for a,z in zip(s,v['y']+v['x']+v['r'])) for v in b['vectors']]
                phases=[sum(a*z for a,z in zip(public,v['y']))-v['c'][0]*(truth+d) for v in b['vectors']]
                self.assertEqual([p%5 for p in phases],[(p-v['c'][0]*d)%5 for p,v in zip(direct,b['vectors'])])
                values.append(sum(math.cos(2*math.pi*(p%5)/5) for p in phases)/3)
            mean=sum(w*v for w,v in zip(weights,values))/4**5
            variance=sum(w*(v-mean)**2 for w,v in zip(weights,values))/4**5
            predicted=analytic(k,c,[d],3,5)
            self.assertAlmostEqual(predicted['mean'],mean,places=13)
            self.assertAlmostEqual(predicted['variance'],variance,places=13)
        null=[sum(math.cos(2*math.pi*sum(a*z for a,z in zip(y,v['y']))/5) for v in b['vectors'])/3
              for y in itertools.product(range(5),repeat=2)]
        self.assertAlmostEqual(sum(null)/25,0,places=14)
        self.assertAlmostEqual(sum(v*v for v in null)/25,1/6,places=14)

    def test_relation_tamper_and_uniform_aliases_rejected(self):
        b=small_bank()
        for field in ('x','r'):
            bad=deepcopy(b)
            bad['vectors'][0][field][0]+=1
            with self.assertRaises(ValueError):
                validate_bank(bad)
        bad=deepcopy(b)
        bad['vectors'].append(deepcopy(bad['vectors'][0]))
        with self.assertRaises(ValueError):
            validate_bank(bad)
        self.assertEqual(field_rank([[1,2],[2,4]],5),1)
        self.assertEqual(field_rank([[1,2],[2,0]],5),2)

    def test_numerical_boundary_remains_ambiguous(self):
        np=numpy()
        value=statistics(np.asarray([.5,.5+2e-12,.5-2e-12]),8)
        for row in (value['tails'][0],value['tails'][2]):
            self.assertEqual(row['hits_above_margin'],1)
            self.assertEqual(row['ambiguous'],1)


if __name__=='__main__':
    unittest.main()
