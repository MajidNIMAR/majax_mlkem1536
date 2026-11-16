"""Concrete counterexamples protect the interpretation of generic/resource costs."""
from fractions import Fraction
import unittest

from m10_parameters_model import bounded_memory_counterexample, common_mapping_bounds, finite_search_checks, grover_success, independent_key_message_hit, memory_diagnostic, wire_sizes


class ResourceModelTests(unittest.TestCase):
    def test_common_mapping_versus_per_key_predicate_accounting(self):
        lower, upper = common_mapping_bounds(8, 1, 2)
        self.assertEqual(lower, Fraction(15, 64))
        self.assertEqual(upper, Fraction(1, 4))
        self.assertEqual(independent_key_message_hit(8, (1, 0)), Fraction(1, 8))
        self.assertEqual(independent_key_message_hit(8, (1, 1)), Fraction(15, 64))

    def test_known_Grover_exact_amplitudes_and_overshoot(self):
        self.assertEqual(grover_success(4, 1, 1), 1)
        self.assertEqual(grover_success(4, 1, 2), Fraction(1, 4))
        self.assertEqual(grover_success(16, 1, 1), Fraction(121, 256))

    def test_complete_small_domains(self):
        checks = finite_search_checks()
        self.assertEqual(checks["common_domain_exact_panels"], 108)
        self.assertEqual(checks["cross_key_message_allocations"], 286)
        self.assertEqual(checks["exact_Grover_panels"], 162)
        self.assertFalse(checks["general_quantum_search_optimality_proved_here"])

    def test_N_is_never_promoted_to_RAM_and_mem_is_not_a_cap_optimization(self):
        absent = memory_diagnostic("dual_hybrid_matzov", {"N": 200})
        self.assertIsNone(absent["inside_declared_storage_cap"])
        present = memory_diagnostic("dual", {"mem": 50})
        self.assertEqual(present["log2_dense_u16_storage_bytes"], 51)
        self.assertFalse(present["inside_declared_storage_cap"]["40"])
        self.assertFalse(present["constrained_RAM_optimum_recomputed"])

    def test_filtering_unconstrained_optima_can_hide_the_better_feasible_attack(self):
        case = bounded_memory_counterexample()
        self.assertGreater(case["unconstrained"]["A"][1], case["cap"])
        self.assertLess(case["constrained"]["A"][0], case["constrained"]["B"][0])

    def test_wire_lengths_are_profile_specific_and_not_security_bits(self):
        sizes = wire_sizes()
        self.assertEqual((sizes["R1"]["encapsulation_key_bytes"], sizes["R1"]["ciphertext_bytes"], sizes["R1"]["expanded_decapsulation_key_bytes"]), (2528, 2656, 5088))
        self.assertEqual((sizes["ML-KEM-1024"]["encapsulation_key_bytes"], sizes["ML-KEM-1024"]["ciphertext_bytes"], sizes["ML-KEM-1024"]["expanded_decapsulation_key_bytes"]), (1568, 1568, 3168))
        self.assertEqual(sizes["difference_R1_minus_reference"]["one_key_and_ciphertext_bytes"], 2048)
        self.assertEqual(sizes["key_and_ciphertext_ratio"], {"numerator_hex": "51", "denominator_hex": "31"})


if __name__ == "__main__":
    unittest.main()
