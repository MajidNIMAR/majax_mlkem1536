"""Guard the mathematical instances and avoid unjustified rounding transfers."""

from collections import Counter
from fractions import Fraction
import unittest

from compare_experimental_kems_m05 import (distribution_law, from_rational, law_moments,
                                         plan, profiles, quantizer_diagnostic)


class ExperimentalKEMComparisonTests(unittest.TestCase):
    def test_kindi_two_bit_source_is_uniform_not_cbd(self):
        observed = Counter(word - 2 for word in range(4))
        actual = {x: Fraction(count, 4) for x, count in observed.items()}
        kindi = next(row for row in profiles() if row["id"].startswith("KINDI"))
        self.assertEqual(actual, distribution_law(kindi["secret"]))
        self.assertEqual(actual, distribution_law(kindi["error"]))
        moments = law_moments(actual)
        self.assertEqual(from_rational(moments["mean"]), Fraction(-1, 2))
        self.assertEqual(from_rational(moments["variance"]), Fraction(5, 4))

    def test_kindi_truncation_error_depends_on_signal_even_with_matching_marginal(self):
        kindi = next(row for row in profiles() if row["id"].startswith("KINDI"))
        diagnostic = quantizer_diagnostic(kindi)
        # Independently enumerate exact integer floor constraints at the two
        # parities. This does not call the comparison quantizer implementation.
        expected_variances = []
        for signal in (0, 1):
            values = [2 * ((signal + error) // 2) - signal for error in (-2, -1, 0, 1)]
            mean = sum(values, Fraction()) / 4
            expected_variances.append(sum((v - mean) ** 2 for v in values) / 4)
        actual_variances = [from_rational(row["moments"]["variance"])
                            for row in diagnostic["actual_error_laws_at_fixed_signals"][:2]]
        self.assertEqual(actual_variances, expected_variances)
        self.assertEqual(actual_variances, [1, 2])
        self.assertEqual(from_rational(diagnostic["independent_sum_error_moments"]["variance"]), Fraction(3, 2))
        self.assertFalse(diagnostic["actual_scheme_rounding_independence_established"])

    def test_nearest_public_key_compression_has_three_or_four_preimages(self):
        for row in profiles():
            if row["pk_quantizer"] == "nearest":
                with self.subTest(profile=row["id"]):
                    diagnostic = quantizer_diagnostic(row)
                    self.assertEqual(diagnostic["preimage_size_histogram"], {"3": 511, "4": 1537})
                    self.assertEqual(diagnostic["rounding_error_under_uniform_input"]["support"], [-2, 2])
                    self.assertTrue(diagnostic["actual_conditional_laws_differ"])

    def test_rank_and_ring_degree_are_distinct_and_budgets_do_not_merge(self):
        jobs = plan()["jobs"]
        for name, expected in (("R1", {1536, 1792}), ("KINDI-512-3-2-1", {1536, 2048})):
            selected = [job for job in jobs if job["scenario"] == name]
            self.assertEqual({job["samples"] for job in selected}, expected)
            self.assertTrue(all(job["n"] == 1536 for job in selected))
            self.assertTrue(all(not job["ciphertext_rows_claimed_independent_samples"] for job in selected))
        self.assertEqual({tuple(job["abstract_matrix_blocks"]) for job in jobs
                          if job["scenario"] == "R1"}, {(6, 6), (7, 6)})
        self.assertEqual({job["degree"] for job in jobs if job["scenario"].startswith("KINDI")}, {512})

    def test_no_duplicate_or_missing_convention_and_pilot_is_a_true_subset(self):
        full, pilot = plan(), plan(pilot=True)
        key = lambda job: (job["scenario"], job["panel"], job["sample_budget"], job["cost_model"], job["algorithm"])
        self.assertEqual(len(full["jobs"]), 108)
        self.assertEqual(len({key(job) for job in full["jobs"]}), 108)
        self.assertEqual(len(pilot["jobs"]), 15)
        self.assertTrue({key(job) for job in pilot["jobs"]}.issubset({key(job) for job in full["jobs"]}))
        self.assertEqual({job["algorithm"] for job in pilot["jobs"]}, {"usvp", "bdd", "dual_hybrid"})

    def test_asymmetric_aigis_and_gaussian_sensitivity_are_not_silently_relabelled(self):
        jobs = plan()["jobs"]
        for job in jobs:
            self.assertIsNone(job["memory_cap"])
            self.assertFalse(job["actual_compressed_scheme_attack_cost"])
            if job["scenario"] == "Aigis-Enc-mode4":
                self.assertEqual(job["secret"], {"kind": "CBD", "eta": 3})
                if job["panel"] == "before_serialization_LWE_proxy":
                    self.assertEqual(job["error"], {"kind": "CBD", "eta": 8})
                else:
                    self.assertEqual(job["error"]["kind"], "Gaussian-moments")


if __name__ == "__main__":
    unittest.main()
