"""Frozen 40-job replay plus semantic rejection of altered comparison contracts."""
import json
import unittest

from m10_parameters_report import RESULT, analyze, bounded_members, sha, verify


class ParameterEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.members = bounded_members(RESULT / "evidence.tar.gz")

    def test_complete_frozen_comparison_and_no_final_freeze(self):
        report = verify(RESULT)
        self.assertEqual(report["completed_finite_jobs"], 40)
        self.assertEqual(len(report["strict_pairs"]), 20)
        self.assertEqual(report["unfavorable_R1_pair_count"], 0)
        self.assertTrue(report["decision"]["continue_R1_engineering"])
        self.assertFalse(report["decision"]["final_cryptographic_parameter_freeze"])
        self.assertFalse(report["memory_constrained_optimization_complete"])
        self.assertIsNone(report["global_security_level_claimed"])

    def test_infinite_sample_budget_is_rejected_even_after_hash_update(self):
        members = dict(self.members)
        plan = json.loads(members["plan.json"])
        plan["jobs"][0]["samples"] = float("inf")
        members["plan.json"] = json.dumps(plan).encode()
        launch = json.loads(members["launch.json"])
        launch["plan_sha256"] = sha(members["plan.json"])
        members["launch.json"] = json.dumps(launch).encode()
        with self.assertRaises(ValueError):
            analyze(members)

    def test_partial_or_timed_out_result_is_not_accepted_as_finite(self):
        members = dict(self.members)
        receipt = json.loads(members["jobs/receipt-000.json"])
        receipt["expired"] = True
        members["jobs/receipt-000.json"] = json.dumps(receipt).encode()
        report = analyze(members)
        self.assertEqual(report["completed_finite_jobs"], 39)
        self.assertEqual(report["missing_or_nonfinite_jobs"], [0])
        self.assertTrue(report["decision"]["incomplete_or_unfavorable_panel_blocks_automatic_final_selection"])

    def test_M05_input_cannot_be_silently_relabelled(self):
        members = dict(self.members)
        members["inputs/m05-comparison.json"] = b'{"results": []}'
        with self.assertRaises(ValueError):
            analyze(members)

    def test_raw_worker_output_mutation_is_rejected(self):
        members = dict(self.members)
        members["jobs/stdout-000.log"] += b"altered"
        with self.assertRaises(ValueError):
            analyze(members)


if __name__ == "__main__":
    unittest.main()
