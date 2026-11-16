"""M10 exact-law, oracle-cost and false-security-claim regression tests."""
from collections import Counter
from copy import deepcopy
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from m10_security import ROOT, build_report, contract, serialize, verify
from m10_security_bounds import (controlled_coordinate_cost, gyy_message_floor, mre_alternative_ledger,
    noise_gap_qrom, noise_gap_rom, ow_from_cpa, pke_cpa_bound, qrom_gyy_ledger, rom_cca_ledger, rom_cca_counted, sqrt_interval)
from m10_security_quantum import finite_controlled_oracle_checks, finite_quantum_checks
from m10_security_resources import CountedImplicitSimulator,finite_adaptive_correctness_checks,finite_simulator_law_checks,rom_resource_envelope
from m10_security_sampler import (certified_inverse_power, conditional_prefix_probability,
    finite_law_checks, finite_tail_checks, matrix_simulation_gap, parsed_prefix, rejection_tail, rewrite_prefix)

HERE=Path(__file__).resolve().parent
SOURCE=(HERE/"dev_kem.rs") if (HERE/"dev_kem.rs").is_file() else ROOT/"crates/kem1536/src/dev_kem.rs"
CERTIFICATE=(HERE/"correctness-certificate.json") if (HERE/"correctness-certificate.json").is_file() else ROOT/"results/j2/run-004/correctness-certificate.json"


class InverseSamplerTests(unittest.TestCase):
    def test_complete_small_conditional_laws_and_uniform_mixture(self):
        result=finite_law_checks()
        self.assertEqual(result["panels"],40)
        self.assertEqual(result["rewritten_raw_traces"],203360)
        self.assertTrue(result["uniform_target_mixture_exact"])

    def test_all_three_unused_bits_rejections_and_suffix_are_preserved(self):
        raw=(7681+7*8192, 1+3*8192, 8191+2*8192, 2+6*8192, 3+5*8192)
        rewritten,stop=rewrite_prefix(raw,(21,24))
        self.assertEqual(stop,4)
        self.assertEqual(parsed_prefix(rewritten,2),(21,24))
        self.assertEqual(rewritten[0],raw[0])
        self.assertEqual(rewritten[2],raw[2])
        self.assertEqual(rewritten[4],raw[4])
        self.assertEqual(rewritten[1]//8192,3)
        self.assertEqual(rewritten[3]//8192,6)
        self.assertEqual(raw[1],1+3*8192)
        # Zeroing high bits would let one query distinguish the faulty simulation.
        highs=Counter(rewrite_prefix((a+high*8192,),(11,))[0][0]//8192
                      for a in range(3) for high in range(8))
        self.assertEqual(highs,Counter({i:3 for i in range(8)}))

    def test_incomplete_and_odd_byte_prefixes_keep_one_stream(self):
        raw=(8191, 7+5*8192, 7682, 2+7*8192, 3+2*8192)
        complete,stop=rewrite_prefix(raw,(13,14))
        self.assertEqual(stop,4)
        incomplete,none=rewrite_prefix(raw[:3],(13,14))
        self.assertIsNone(none)
        self.assertEqual(incomplete,complete[:3])
        data=b"".join(word.to_bytes(2,"little") for word in complete)
        for length in range(len(data)+1):
            prefix=b"".join(word.to_bytes(2,"little") for word in complete[:(length+1)//2])[:length]
            self.assertEqual(prefix,data[:length])

    def test_raw_trace_conditional_probability_is_not_uniform_at_fixed_target(self):
        self.assertEqual(conditional_prefix_probability((1,), (1,),3,2,1),Fraction(3,8))
        self.assertEqual(conditional_prefix_probability((3,), (1,),3,2,1),Fraction(1,8))
        self.assertEqual(conditional_prefix_probability((2,), (1,),3,2,1),0)

    def test_binomial_tail_by_independent_raw_enumeration(self):
        result=finite_tail_checks()
        self.assertEqual(result["panels"],63)
        self.assertEqual(result["enumerated_raw_candidate_traces"],49149)

    def test_matrix_cap_resource_and_exact_probability(self):
        panel=matrix_simulation_gap(word_limit=512)
        self.assertEqual(panel["maximum_candidate_words"],18432)
        self.assertEqual(panel["maximum_matrix_stream_bytes"],36864)
        self.assertEqual(certified_inverse_power(panel["truncation_gap"]),539)
        self.assertGreater(panel["truncation_gap"],Fraction(1,1<<540))
        self.assertLessEqual(panel["truncation_gap"],Fraction(1,1<<539))
        self.assertEqual(rejection_tail(7681,256,13,255),1)
        self.assertEqual(rejection_tail(8192,256,13,256),0)
        self.assertEqual(matrix_simulation_gap(preseed_queries=3)["preseed_classical_gap"],Fraction(3,1<<256))

    def test_malformed_and_silent_quantum_preprocessing_are_refused(self):
        for kwargs in ({"raw_words":(65536,),"target":(1,)},{"raw_words":(1,),"target":(7681,)},
                       {"raw_words":(True,),"target":(1,)},{"raw_words":(1,),"target":()}):
            with self.assertRaises(ValueError):
                rewrite_prefix(**kwargs)
        with self.assertRaises(ValueError):
            pke_cpa_bound("QROM",0,0,1,1,preseed_queries=1)

    def test_uniform_raw_scalar_stays_message_independent_after_compression(self):
        for q,width in ((5,2),(17,3),(7681,5)):
            distributions=[]
            for message in (0,(q+1)//2,q-1):
                distributions.append(Counter((((((u+message)%q)<<width)+q//2)//q)&((1<<width)-1)
                                             for u in range(q)))
            self.assertEqual(distributions[0],distributions[1])
            self.assertEqual(distributions[0],distributions[2])
            self.assertGreater(len(set(distributions[0].values())),1)


class CompositionTests(unittest.TestCase):
    def test_adaptive_correctness_charges_discarded_searches_and_keeps_key_quantifier(self):
        result=finite_adaptive_correctness_checks()
        self.assertEqual(result["adaptive_policies"],32)
        self.assertEqual(result["enumerated_key_and_oracle_tables"],288)
        self.assertEqual(result["discarded_query_search_success"],Fraction(5,9))
        self.assertGreater(result["discarded_query_search_success"],result["incorrect_final_query_only_bound"])
        self.assertTrue(result["max_m_after_key_average_is_required"])

    def test_classical_joint_transcripts_and_cache_count_envelope(self):
        result=finite_simulator_law_checks()
        self.assertTrue(result["exact_joint_transcript_laws_equal"])
        self.assertEqual(result["panels"],781)
        self.assertEqual(result["enumerated_true_and_simulator_tapes"],6248)

    def test_noninjective_toy_refutes_a_simulator_claim_without_error_charge(self):
        real_equal=0
        for first in (0,1):
            for second in (0,1):
                real_equal+=first==second
                tape=iter((first,second))
                sim=CountedImplicitSimulator(lambda _m,_r:0,lambda:next(tape),lambda m:m)
                self.assertEqual(sim.g512_target(0)[1],sim.g512_target(1)[1])
        self.assertEqual(real_equal,2)

    def test_classical_auxiliary_query_map_is_substituted_in_ROM_bound(self):
        resource=rom_resource_envelope(37,41,43,47,53)
        self.assertEqual(resource["public_encryptions_max"],37)
        self.assertEqual(resource["KG_queries_max"],37)
        self.assertEqual(resource["N_queries_max"],41+13*37)
        self.assertEqual(resource["A_cell_reads_max"],43+36*37)
        self.assertEqual(resource["Hpk_queries_max"],48)
        self.assertEqual(resource["distinct_F_oracle_queries_max"],38)
        value=rom_cca_counted(Fraction(0),0,0,37,41,53,43,47)
        self.assertEqual(value["resources"],resource)
        self.assertEqual(value["pke"]["seeded_noise"],noise_gap_rom(37,41+13*37))
        self.assertEqual(value["correctness_coefficient"],8*(37+41+53+1))
        self.assertTrue(value["classical_CPA_oracle_count_map_supplied"])
        self.assertFalse(value["C01_closed"])

    def test_classical_noise_retains_collision_and_exact_count(self):
        self.assertEqual(noise_gap_rom(0,0,4),Fraction(1,16))
        self.assertEqual(noise_gap_rom(2,3,4),1-Fraction(14*13*12,16**3))
        self.assertEqual(noise_gap_rom(100,0,4),1)

    def test_quantum_noise_is_a_separate_norm_bound_not_the_classical_formula(self):
        self.assertEqual(noise_gap_qrom(0,0),Fraction(1,1<<256))
        self.assertGreater(noise_gap_qrom(1,1),noise_gap_rom(1,1))
        self.assertLessEqual(noise_gap_qrom(1,1),Fraction(1,1<<256)+Fraction(6,1<<128))
        self.assertEqual(noise_gap_qrom(1<<128,0),1)

    def test_dyadic_sqrt_encloses_large_small_and_irrational_inputs(self):
        for value in (Fraction(0),Fraction(1),Fraction(13),Fraction(1,1<<256),Fraction(2,1<<256),Fraction(1,3)):
            lower,upper=sqrt_interval(value)
            self.assertLessEqual(lower*lower,value)
            self.assertGreaterEqual(upper*upper,value)
            self.assertLessEqual(upper-lower,Fraction(1,1<<512))
        with self.assertRaises(ValueError):
            sqrt_interval(-1)
        with self.assertRaises(ValueError):
            sqrt_interval(0.5)

    def test_two_MLWE_assumptions_and_four_matrix_branch_charges_are_retained(self):
        bound=pke_cpa_bound("ROM",Fraction(1,1<<200),Fraction(1,1<<199),5,7)
        matrix=matrix_simulation_gap()
        self.assertEqual(bound["matrix_simulation"],4*matrix["total_gap"])
        self.assertEqual(bound["cpa_bias_upper"],Fraction(3,1<<200)+noise_gap_rom(5,7)+4*matrix["total_gap"])
        self.assertIs(bound["C01_closed"],False)
        self.assertIs(bound["concrete_primitive_security_proved"],False)

    def test_OW_versus_CPA_normalization_includes_trivial_guess(self):
        self.assertEqual(ow_from_cpa(Fraction(1,2)),1)
        self.assertEqual(ow_from_cpa(Fraction(0)),Fraction(1,1<<256))
        self.assertEqual(ow_from_cpa(Fraction(1,8),4),Fraction(5,16))

    def test_GYY_proof_margin_failure_is_not_removed_by_zero_network_advantage(self):
        floor=gyy_message_floor(1<<64,1<<64,1<<64)
        self.assertGreater(floor["lower"],Fraction(1,1<<128))
        result=qrom_gyy_ledger(Fraction(0),Fraction(0),1<<64,1<<64,1<<64,0)
        self.assertEqual(result["ow_term"],floor["upper"])
        self.assertFalse(result["C01_closed"])

    def test_MRE_does_not_claim_a_completed_resource_map_or_randomness_recovery(self):
        result=mre_alternative_ledger(Fraction(0),Fraction(1,1024),4,4,1,Fraction(0),16)
        self.assertEqual(result["pke_coefficient_upper"],140)
        self.assertEqual(result["guessing"],Fraction(16*2*41,1<<16))
        self.assertFalse(result["directly_resource_qualified_for_R1"])
        self.assertFalse(result["unique_randomness_recovery_assumed"])
        self.assertFalse(result["C01_closed"])

    def test_rejection_zero_queries_and_inclusive_ROM_counts(self):
        result=rom_cca_ledger(Fraction(0),Fraction(0),3,4,0,100)
        self.assertEqual(result["rejection_upper"],0)
        self.assertEqual(result["queries"]["inclusive_classical_qro"],12)
        self.assertEqual(result["message_guessing"],Fraction(36,1<<256))
        result=rom_cca_ledger(Fraction(0),Fraction(0),3,4,1,100)
        self.assertEqual(result["rejection_upper"],Fraction(100,1<<256))

    def test_coordinate_bridge_charges_oracle_calls_and_inverse_encryption(self):
        result=controlled_coordinate_cost(37,recovered_key=True)
        self.assertEqual((result["F_queries"],result["K_queries"],result["auxiliary_queries"]),(74,74,74))
        self.assertEqual(result["reversible_encryption_or_inverse_calls"],74)
        self.assertFalse(result["full_FO_reduction_resources_closed"])
        self.assertEqual(finite_controlled_oracle_checks()["exact_basis_cases"],1536)

    def test_finite_exact_quantum_norm_hybrid(self):
        result=finite_quantum_checks()
        self.assertEqual(result["panels"],5056)
        self.assertEqual(result["exact_oracle_circuit_pairs"],40320)
        self.assertTrue(result["all_exact_squared_norm_and_probability_bounds_pass"])

    def test_probability_inputs_reject_float_bool_and_unknown_model(self):
        for value in (0.1,True,-1,Fraction(3,2)):
            with self.assertRaises(ValueError):
                ow_from_cpa(value)
        with self.assertRaises(ValueError):
            pke_cpa_bound("CONCRETE",0,0,0,0)


class SecurityClaimTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source=SOURCE.read_text(encoding="utf-8")
        cls.certificate=json.loads(CERTIFICATE.read_text(encoding="utf-8"))
        cls.report=serialize(build_report(cls.certificate,cls.source))

    def test_current_source_contract_and_changed_matrix_mask(self):
        self.assertEqual(contract(self.source)["anchor_count"],17)
        with self.assertRaises(ValueError):
            contract(self.source.replace("u16::from_le_bytes(pair) & 8191","u16::from_le_bytes(pair) & 4095"))

    def test_test_only_old_helper_cannot_satisfy_production_domain_anchor(self):
        modified=self.source.replace('derive_into(b"KG\\0", &[d, &[6]], &mut expanded);',
                                     'derive_into(b"BAD\\0", &[d, &[6]], &mut expanded);',1)
        modified+='\n#[cfg(test)]\nfn fake() { derive_into(b"KG\\0", &[d, &[6]], &mut expanded); }\n'
        with self.assertRaises(ValueError):
            contract(modified)

    def test_full_report_preserves_open_gate_and_finite_sample_counts(self):
        self.assertFalse(self.report["C01_closed"])
        self.assertFalse(self.report["cryptographic_parameter_freeze_supported"])
        self.assertFalse(self.report["external_audit"])
        self.assertEqual(self.report["required_MLWE_instances"][1]["flattened_scalar_samples"],1792)
        self.assertTrue(self.report["flattened_rotations_are_not_independent_LWE_samples"])

    def test_falsified_C01_conclusion_is_rejected_even_with_updated_file_hash(self):
        with tempfile.TemporaryDirectory(prefix="m10-security-claim-") as temporary:
            directory=Path(temporary)
            bad=deepcopy(self.report)
            bad["C01_closed"]=True
            payloads={"report.json":json.dumps(bad).encode(),"dev_kem.rs":self.source.encode(),
                      "correctness-certificate.json":json.dumps(self.certificate).encode()}
            for name,raw in payloads.items():
                (directory/name).write_bytes(raw)
            provenance=dict(schema="m10-security-capsule-v1",C01_closed=False,external_audit=False,
                output_sha256={name:hashlib.sha256(raw).hexdigest() for name,raw in payloads.items()})
            (directory/"provenance.json").write_text(json.dumps(provenance))
            with self.assertRaisesRegex(ValueError,"recomputed security conclusion"):
                verify(directory)

    def test_incorrect_R1_certificate_population_is_rejected(self):
        bad=deepcopy(self.certificate)
        bad["parameters"]["k"]=4
        with self.assertRaises(ValueError):
            build_report(bad,self.source)


if __name__=="__main__":
    unittest.main()
