"""LLL exact arithmetic, certificate tampering, quotient witnesses and scores."""

import copy
import unittest

from dual_expansion import ROOT,bank_for,bank_key,case_data,read
from exact_lll import determinant,reduce_basis,verify_reduction
from full_dual_toy import evaluate,lwe_law,score_table


class DualExpansionTests(unittest.TestCase):
    def test_reduction_and_unimodular_certificates(self):
        for basis in ([[1,0,16],[0,1,9],[0,0,17]],[[1,0,0],[0,1,0],[0,0,5]],[[12,7,1],[3,5,2],[1,2,7]]):
            result=reduce_basis(basis)
            self.assertTrue(verify_reduction(result))
            self.assertEqual(abs(determinant(result["reduced"])),abs(determinant(basis)))
            self.assertEqual(result,reduce_basis(basis))
            damaged=copy.deepcopy(result)
            damaged["unimodular"][0][0]+=1
            with self.assertRaises(ValueError):
                verify_reduction(damaged)

    def test_projected_witnesses_and_exhaustive_order(self):
        for q in (5,17):
            for identifier in range(4):
                case=case_data(q,identifier)
                self.assertGreaterEqual(len(case["lll_box"]),12)
                reference={(tuple(v["y"]),v["x"]) for v in case["reference"]}
                for i,row in enumerate(case["lll_box"]):
                    raw=[sum(c*v[j] for c,v in zip(row["coefficients"],case["reduction"]["reduced"])) for j in range(3)]
                    centered=[(x+q//2)%q-q//2 for x in raw]
                    self.assertEqual(centered,row["y"]+[row["x"]])
                    self.assertIn((tuple(row["y"]),row["x"]),reference)
                    self.assertGreaterEqual(row["squared_norm"],case["reference"][i]["squared_norm"])

    def test_exact_cache_identity_and_full_N12_score(self):
        tables={t["q"]:t for t in read(ROOT/"results/j2/run-013/transcendental-tables.json")}
        for q in (5,17):
            case=case_data(q,0)
            t=tables[q]
            bank=bank_for(case,"lll_box",12,"radix","cbd",t["cbd_weights"])
            same=copy.deepcopy(bank)
            same["metric"]="metadata-only"
            self.assertEqual(bank_key(bank),bank_key(same))
            same["vectors"][0]["c"]=(same["vectors"][0]["c"]+1)%q
            self.assertNotEqual(bank_key(bank),bank_key(same))
            law=lwe_law(bank["A"],bank["code"]["generators"][0],q)
            scores,_=score_table(bank,t["cosine_weights"])
            result=evaluate(bank,law,scores,t["cosine_weights"])
            self.assertAlmostEqual(result["uniform_null"]["variance"],1/24)

    def test_invalid_and_singular_bases(self):
        for basis in ([[1,0],[0,1]],[[1,0,0],[1,0,0],[0,0,1]],[[1.0,0,0],[0,1,0],[0,0,1]]):
            with self.assertRaises(ValueError):
                reduce_basis(basis)


if __name__=="__main__":
    unittest.main()
