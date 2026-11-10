"""Prevent invalid security comparisons and silent resource-unit changes."""

from copy import deepcopy
import json
import math
import unittest

from compare_attacks_common import coded_rows, list_storage, pair_rows, ROOT


def example_pair():
    data = json.loads((ROOT / "results/j2/run-002/modern-attacks.json").read_text(encoding="utf-8"))
    return [row for row in data["results"]
            if row["job"]["scenario"] in ("baseline-1024", "q7681-eta3")
            and row["job"]["sample_budget"] == "key"
            and row["job"]["algorithm"] == "dual_hybrid"
            and row["job"]["cost_model"] == "MATZOV-classical"]


class CommonAttackContractTests(unittest.TestCase):
    def test_classical_and_quantum_cannot_be_subtracted(self):
        rows = example_pair()
        rows[1]["job"]["cost_model"] = "BCSS23-quantum-asymptotic"
        with self.assertRaisesRegex(ValueError, "unpaired"):
            pair_rows(rows)

    def test_no_silent_sample_oracle_or_target_substitution(self):
        for field, value in (("samples", 1792), ("oracle", "failure"), ("targets", 256)):
            with self.subTest(field=field):
                rows = example_pair()
                rows[1]["job"][field] = value
                with self.assertRaisesRegex(ValueError, "contract mismatch"):
                    pair_rows(rows)

    def test_duplicate_results_are_an_error_not_a_cheaper_minimum(self):
        rows = example_pair()
        duplicate = deepcopy(rows[1])
        duplicate["log2_cost"]["rop"] = 1.0
        with self.assertRaisesRegex(ValueError, "duplicate"):
            pair_rows(rows + [duplicate])

    def test_storage_counts_bytes_and_does_not_reprice_the_attack(self):
        point = {"lattice_dimension": 1672, "inputs": {"q": 3329}}
        storage = list_storage(point, 10.0, caps=(20, 22))
        self.assertEqual(storage["bytes_per_vector"], 2508)
        self.assertEqual([r["fits"] for r in storage["fixed_representation_cap_sensitivity"]], [False, True])
        self.assertAlmostEqual(storage["log2_list_bytes"], math.log2(1024 * 2508))
        self.assertIsNone(storage["bounded_memory_attack_cost"])
        self.assertFalse(storage["universal_memory_lower_bound"])

    def test_coded_dual_diagnostic_cannot_attach_to_another_configuration(self):
        study = json.loads((ROOT / "results/j2/run-009/study.json").read_text(encoding="utf-8"))
        diagnostic = json.loads((ROOT / "results/j2/run-016/study.json").read_text(encoding="utf-8"))
        diagnostic["points"][0]["inputs"]["samples"] += 1
        with self.assertRaisesRegex(ValueError, "mismatch"):
            coded_rows(study["minima"], diagnostic["points"])


if __name__ == "__main__":
    unittest.main()
