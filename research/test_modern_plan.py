import unittest

from run_modern import jobs


class ModernInstancePolicyTests(unittest.TestCase):
    def test_comparisons_use_identical_families_models_and_budgets(self):
        matrix = list(jobs())
        scenarios = {row["scenario"] for row in matrix}
        signatures = []
        for scenario in scenarios:
            rows = [row for row in matrix if row["scenario"] == scenario]
            signatures.append({(r["algorithm"], r["tool"], r["cost_model"], r["sample_budget"])
                               for r in rows})
            self.assertTrue(all(r["parameters"]["n"] == 256 for r in rows))
            self.assertEqual({r["samples"] for r in rows},
                             {256*rows[0]["parameters"]["k"], 256*(rows[0]["parameters"]["k"]+1)})
        self.assertEqual(len(scenarios), 4)
        self.assertTrue(all(signatures[0] == signature for signature in signatures))
        self.assertEqual(len(matrix), len({str(sorted(row.items())) for row in matrix}))


if __name__ == "__main__":
    unittest.main()
