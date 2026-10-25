"""Small independent-oracle checks, not a replacement for cross-language vectors."""

import unittest
from fractions import Fraction
import numpy as np
import kem_r1_reference as ref


class R1ReferenceTests(unittest.TestCase):
    def test_negacyclic_sign_and_integer_range(self):
        a=np.zeros(256,dtype=np.int64); b=a.copy()
        a[255]=1; b[1]=1
        expected=np.zeros(256,dtype=np.int64); expected[0]=ref.Q-1
        self.assertTrue(np.array_equal(ref.multiply(a,b),expected))
        a[:]=ref.Q-1
        self.assertTrue(np.array_equal(ref.multiply(a,a),np.array([(2*i-254)%ref.Q for i in range(256)])))

    def test_roundtrip_imports_and_explicit_rejection_oracle(self):
        d,z,m=ref.synthetic_seeds(0)
        ek,dk=ref.keygen(d,z); c,k=ref.encapsulate(ek,m)
        got,accepted=ref.decapsulate(dk,c)
        self.assertTrue(accepted); self.assertEqual(k,got)
        bad=bytearray(c); bad[0]=255; bad[1]|=31
        got,accepted=ref.decapsulate(dk,bytes(bad))
        self.assertFalse(accepted); self.assertEqual(got,ref.fallback(z,bytes(bad)))
        bad=bytearray(dk); bad[ref.VP+ref.EK]^=1
        with self.assertRaises(ValueError): ref.private(bytes(bad))

    def test_compression_against_rational_rounding(self):
        values=np.arange(ref.Q,dtype=np.int64)
        for d in (1,5):
            actual=ref.compress(values,d)
            expected=[(Fraction(int(x)*2**d,ref.Q)+Fraction(1,2)).__floor__()%2**d for x in values]
            self.assertTrue(np.array_equal(actual,expected))


if __name__=='__main__':
    unittest.main()
