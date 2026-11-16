"""Finite independent checks for the M09 classical hidden-label hybrid.

The tests enumerate bad-event labels and adaptive query transcripts, not a
general cryptographic adversary. They do not prove security of SHAKE or R1.
"""
from fractions import Fraction
from itertools import product
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from m09_security_noise import (BASELINE_SHA, ROOT, create, deterministic_cbd_distance_lower,
                                enumerate_bad, finite_checks, fresh_rom_obligation,
                                hybrid_gap, make_report, sha, source_contract,
                                symmetric_query_limit, union_gap, verify)


BASELINE = next((path for path in (
    Path(__file__).with_name("dev_kem.rs"),
    ROOT / "results/security/m09-001/sources/dev_kem.rs",
    ROOT / "artifacts/generated/m08-001/candidate-source/crates/kem1536/src/dev_kem.rs",
) if path.is_file()), ROOT / "missing-m09-study-baseline")


class HiddenNoiseHybridTests(unittest.TestCase):
    def test_collision_is_charged_even_with_no_oracle_queries(self):
        self.assertEqual(hybrid_gap(0, 0), Fraction(1, 1 << 256))
        for bits in range(1, 5):
            self.assertEqual(hybrid_gap(0, 0, bits), Fraction(1, 1 << bits))

    def test_all_small_count_pairs_against_independent_label_enumeration(self):
        for bits in range(1, 4):
            space = 1 << bits
            for g in range(space + 1):
                for n in range(space + 1):
                    with self.subTest(bits=bits, g=g, n=n):
                        self.assertEqual(hybrid_gap(g, n, bits), enumerate_bad(space, range(g), range(n)))

    def test_queries_after_saturation_and_edges(self):
        for bits in (1, 4, 256):
            space = 1 << bits
            self.assertEqual(hybrid_gap(space, 0, bits), 1)
            self.assertEqual(hybrid_gap(0, space-1, bits), 1)
            self.assertEqual(hybrid_gap(0, 2*space, bits), 1)
            self.assertEqual(hybrid_gap(2*space, 0, bits), 1)

    def test_exact_expression_improves_union_and_is_monotone(self):
        for bits in range(1, 6):
            space = 1 << bits
            for g in range(space):
                for n in range(space):
                    self.assertLessEqual(hybrid_gap(g, n, bits), union_gap(g, n, bits))
                    self.assertLessEqual(hybrid_gap(g, n, bits), hybrid_gap(g+1, n, bits))
                    self.assertLessEqual(hybrid_gap(g, n, bits), hybrid_gap(g, n+1, bits))
        self.assertLess(hybrid_gap(1, 1, 4), union_gap(1, 1, 4))

    def test_adaptive_query_sets_from_independent_ideal_transcripts(self):
        # Public bit, KG table and N table determine queries; hidden labels
        # are enumerated only afterwards. Even overlapping adaptive N queries
        # are charged by their distinct seed count, not their number of calls.
        space = 4
        total_bad, total_predicted, paths = Fraction(0), Fraction(0), 0
        saw_duplicate = False
        for public in (0, 1):
            for kg in product((0, 1), repeat=space):
                for noise in product((0, 1), repeat=space):
                    g = (public + 1) % space
                    n0 = (kg[g] + public) % space
                    n1 = (noise[n0] + 1) % space
                    gs, ns = {g}, {n0, n1}
                    saw_duplicate |= n0 == n1
                    total_bad += enumerate_bad(space, gs, ns)
                    total_predicted += hybrid_gap(len(gs), len(ns), 2)
                    paths += 1
        self.assertEqual(paths, 512)
        self.assertTrue(saw_duplicate)
        self.assertEqual(total_bad, total_predicted)

    def test_nonuniform_or_revealed_label_cannot_use_uniform_bound(self):
        # If sigma is known to be 0, querying 0 always hits. The uniform
        # expression at M=16 is less than one, so the premise is necessary.
        self.assertLess(hybrid_gap(0, 1, 4), 1)
        sigma, query = 0, {0}
        self.assertTrue(sigma in query)

    def test_fresh_rom_substitution_keeps_reduction_cost_explicit(self):
        target, known = Fraction(1, 1 << 128), Fraction(1, 1 << 200)
        requirement = fresh_rom_obligation(target, known, 1 << 64, 1 << 64)
        self.assertIsNotNone(requirement)
        self.assertEqual(6*requirement + known + 6*hybrid_gap(1 << 64, 1 << 64), target)
        self.assertIsNone(fresh_rom_obligation(target, known, 1 << 128, 1 << 128))
        self.assertIsNone(fresh_rom_obligation(0, 0, 0, 0))

    def test_symmetric_query_limit_is_exact_and_tight(self):
        for bits in range(1, 4):
            for target in (Fraction(0), Fraction(1, 16), Fraction(1, 4), Fraction(1, 2)):
                for coefficient in (1, 2, 6):
                    allowed = [q for q in range((1 << bits)+1)
                               if coefficient*enumerate_bad(1 << bits, range(q), range(q)) <= target]
                    self.assertEqual(symmetric_query_limit(target, coefficient, bits), max(allowed) if allowed else None)
        for exponent in (128, 192, 224):
            target = Fraction(1, 1 << exponent)
            q = symmetric_query_limit(target)
            self.assertLessEqual(6*hybrid_gap(q, q), target)
            self.assertGreater(6*hybrid_gap(q+1, q+1), target)
        self.assertIsNone(symmetric_query_limit(Fraction(1, 1 << 256)))

    def test_fixed_sampler_statistical_obstruction_by_support_count(self):
        # Independent CBD law from all 64 six-bit strings.
        counts = {}
        for bits in product((0, 1), repeat=6):
            value = sum(bits[:3])-sum(bits[3:])
            counts[value] = counts.get(value, 0)+1
        self.assertEqual(max(counts.values()), 20)
        self.assertEqual(Fraction(max(counts.values()), 64), Fraction(5, 16))
        distance = deterministic_cbd_distance_lower()
        self.assertGreater(distance, 1-Fraction(1, 1 << 4898))
        self.assertEqual(deterministic_cbd_distance_lower(256, 0), 0)

    def test_rejects_invalid_budget_types_and_ranges(self):
        for bad in (-1, True, 1.0, Fraction(1, 2), "1"):
            for function in (hybrid_gap, union_gap):
                with self.assertRaises(ValueError):
                    function(bad, 0)
                with self.assertRaises(ValueError):
                    function(0, bad)
        for bad in (0, -1, True, 4097):
            with self.assertRaises(ValueError):
                hybrid_gap(0, 0, bad)
        for target, term in ((Fraction(3, 4), 0), (0, -1), (True, 0), (0, 0.1)):
            with self.assertRaises(ValueError):
                fresh_rom_obligation(target, term, 0, 0)

    def test_baseline_contract_and_report_keep_limits(self):
        self.assertTrue(BASELINE.is_file(), "the copied study baseline is required")
        contract = source_contract(BASELINE)
        self.assertEqual(contract["sha256"], BASELINE_SHA)
        self.assertEqual(contract["literal_anchors"], 12)
        report = make_report(BASELINE)
        self.assertFalse(report["complete_C01_closed"])
        self.assertFalse(report["quantum_bound_provided"])
        self.assertTrue(report["queries_are_of_pke_reduction_not_original_cca_adversary"])
        self.assertEqual(len(report["panels"]), 8)

    def test_frozen_m09_realization_keeps_the_referenced_sampling_semantics(self):
        active = ROOT / "crates/kem1536/src/dev_kem.rs"
        if not active.is_file():
            self.skipTest("standalone frozen finite tests do not contain the later active realization")
        import hashlib
        import tarfile
        folder = ROOT / "results/engine/m09-001"
        member = "source/crates/kem1536/src/dev_kem.rs"
        manifest = json.loads((folder / "provenance.json").read_text("utf-8"))
        with tarfile.open(folder / "qualification.tar.gz") as archive:
            source = archive.extractfile(member).read()
        self.assertEqual(hashlib.sha256(source).hexdigest(),
                         manifest["groups"]["qualification"]["files"][member]["sha256"])
        from verify_r1_certificate_bridge import verify_static_contract
        contract = verify_static_contract(source.decode("utf-8-sig"))
        self.assertEqual(contract["realization"], "M09-typed-noise-destination-message-1")
        self.assertFalse(contract["formal_program_verification"])
        # The existing bridge checks role wrappers, fixed seed widths,
        # nonce schedules, framing, CBD bits and unchanged arithmetic callers.
        self.assertGreater(contract["reviewed_source_anchors"], 36)

    def test_finite_counts_are_not_reported_as_adversary_enumeration(self):
        checks = finite_checks()
        self.assertTrue(checks["all_equal"])
        self.assertEqual(checks["count_panels"], sum((m+1)**2 for m in range(2, 10)))
        self.assertIn("not enumerating R1", checks["scope"])

    def test_capsule_inventory_hash_and_recalculation_reject_tampering(self):
        capsule = ROOT if (ROOT / "report.json").is_file() else ROOT / "results/security/m09-001"
        if not capsule.is_dir():
            self.skipTest("capsule not sealed yet")
        self.assertEqual(verify(capsule)["status"], "PASS")
        with tempfile.TemporaryDirectory() as temporary:
            copied = Path(temporary) / "capsule"
            shutil.copytree(capsule, copied)
            report_path = copied / "report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["complete_C01_closed"] = True
            report_path.write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaises(ValueError):
                verify(copied)
            # Even a matching member hash cannot bypass mathematical replay.
            manifest_path = copied / "provenance.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"]["report.json"] = dict(sha256=sha(report_path), bytes=report_path.stat().st_size)
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(ValueError):
                verify(copied)


if __name__ == "__main__":
    unittest.main()
