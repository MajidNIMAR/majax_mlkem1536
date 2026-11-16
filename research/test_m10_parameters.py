"""The preregistered panel must keep finite sample games and contracts separate."""
import unittest

from m10_parameters import ESTIMATOR_COMMIT, jobs


class PlanTests(unittest.TestCase):
    def test_exactly_twenty_strict_pairs_and_finite_samples(self):
        panel = jobs()
        self.assertEqual(len(panel), 40)
        grouped = {}
        for job in panel:
            self.assertEqual(job["estimator_commit"], ESTIMATOR_COMMIT)
            self.assertEqual(job["dimension"], job["degree"] * job["rank"])
            extra = job["sample_game"] == "ideal_k_plus_1"
            self.assertEqual(job["samples"], job["degree"] * (job["rank"] + extra))
            self.assertFalse(job["real_MLWE_claimed_IID_LWE"])
            self.assertFalse(job["real_ciphertext_rows_claimed_independent"])
            self.assertEqual(job["targets"], 1)
            key = job["sample_game"], job["cost_model"], job["family"], job["success_contract"]
            grouped.setdefault(key, []).append(job["profile"])
        self.assertEqual(len(grouped), 20)
        self.assertTrue(all(sorted(profiles) == ["ML-KEM-1024", "R1"] for profiles in grouped.values()))

    def test_no_global_success_or_RAM_cap_is_invented(self):
        for job in jobs():
            self.assertIsNone(job["memory_cap"])
            self.assertEqual(job["leakage_oracle"], "none")
            if job["family"] == "dual_hybrid_matzov":
                self.assertIn("not a certified", job["success_contract"])
            if job["family"] == "primal_hybrid_mitm":
                self.assertIn("MITM=True", job["success_contract"])
                self.assertIn("Babai=False", job["success_contract"])


if __name__ == "__main__":
    unittest.main()
