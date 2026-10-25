"""Full-codebook checks, interval certification and a directional counterexample."""

import itertools
import math
import unittest

from block_decoder import make_code
from cbd_decoder import SCALE, certificate, decode_scalar, errors, validate_weights


class CBDDecoderTests(unittest.TestCase):
    def test_full_codebook_and_lexicographic_ties(self):
        for family in ("repeated", "radix"):
            code = make_code(5, 4, 2, family)
            weights = [0,10,60]
            for target in itertools.product(range(5), repeat=4):
                expected = min((sum(weights[abs((x-y+2)%5-2)] for x,y in zip(target,code.encode(labels))),list(labels))
                               for labels in itertools.product(range(5),repeat=2))
                actual = decode_scalar(code,target,weights,"cbd")
                word = code.encode(actual["labels"])
                self.assertEqual((sum(weights[abs((x-y+2)%5-2)] for x,y in zip(target,word)),actual["labels"]),expected)

    def test_interval_certificate_resolves_histogram_ties(self):
        # q=5, target (0,1), repetition: labels 0/1 have identical histograms.
        values,g,q,weights = [0,1],[1,1],5,[0,10,60]
        costs = [sum(weights[e] for e in errors(values,g,a,q)) for a in range(q)]
        proof = certificate(values,g,q,weights,costs,0)
        self.assertTrue(proof["real_optimum_certified"])
        self.assertEqual(proof["interval_contenders"],2)
        # Coarse weights can leave distinct histograms inside the interval.
        costs = [0,1,20,20,20]
        proof = certificate([0,0],[1,1],q,weights,costs,0)
        self.assertFalse(proof["real_optimum_certified"])

    def test_cbd_can_trade_distance_for_bias(self):
        q=17
        code=make_code(q,4,1,"radix")
        weights=[int(SCALE*(-2*math.log(math.cos(math.pi*d/q)))) for d in range(q//2+1)]
        found=False
        for target in [(0,0,5,15)]:
            a=decode_scalar(code,target,weights,"euclidean")["labels"][0]
            b=decode_scalar(code,target,weights,"cbd")["labels"][0]
            ra,rb=errors(target,code.generators[0],a,q),errors(target,code.generators[0],b,q)
            if sum(x*x for x in rb)>sum(x*x for x in ra):
                ca=sum(-2*math.log(math.cos(math.pi*x/q)) for x in ra)
                cb=sum(-2*math.log(math.cos(math.pi*x/q)) for x in rb)
                self.assertLess(cb,ca)
                found=True
                break
        self.assertTrue(found)

    def test_invalid_inputs_and_overflow(self):
        for weights in ([0,1],[0,0,1],[0,-1,2],[0,1,2**63]):
            with self.assertRaises(ValueError):
                validate_weights(5,weights)
        code=make_code(5,3,1,"radix")
        with self.assertRaises(ValueError):
            decode_scalar(code,[5,0,0],[0,10,60],"cbd")
        with self.assertRaises(ValueError):
            decode_scalar(code,[0,0,0],[0,10,60],"unknown")


if __name__=="__main__":
    unittest.main()
