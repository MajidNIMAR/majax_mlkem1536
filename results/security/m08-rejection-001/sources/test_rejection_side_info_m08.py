"""Independent finite nonuniform-key games and exact M08 arithmetic checks.

These fixtures do not enumerate a general quantum adversary or measure R1.
"""
from collections import Counter
from fractions import Fraction
from itertools import product
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from rejection_security_m06 import rejection_bounds
from rejection_side_info_m08 import (ROOT, SOURCE_NAMES, gap_bounds, guessing_probability,
                                     make_report, sha, sqrt_interval, verify)


def finite_laws(counts, alphabet, strategy):
    """Enumerate all tiny H/R and the correlated classical pair (E,Z)."""
    keys, total = len(counts[0]), sum(map(sum, counts))
    real, ideal = Counter(), Counter()
    for table in product(range(alphabet), repeat=keys):
        h = lambda key: table[key]
        for e, row in enumerate(counts):
            for z, count in enumerate(row):
                if count == 0:
                    continue
                real[e, strategy(h, lambda: table[z], e)] += Fraction(count, total * alphabet**keys)
                for independent_response in range(alphabet):
                    ideal[e, strategy(h, lambda: independent_response, e)] += Fraction(
                        count, total * alphabet ** (keys + 1))
    return real, ideal


def variation(first, second):
    return sum((abs(first[item] - second[item]) for item in first.keys() | second.keys()), Fraction(0)) / 2


class RejectionSideInfoTests(unittest.TestCase):
    def test_exact_posterior_guessing_probability_uses_joint_not_unweighted_rows(self):
        self.assertEqual(guessing_probability([[3, 1, 0], [0, 1, 3]]), Fraction(3, 4))
        # Unequal E probabilities: average posterior maxima is 7/10, not 5/8.
        self.assertEqual(guessing_probability([[6, 2], [1, 1]]), Fraction(7, 10))
        self.assertEqual(guessing_probability([[0, 4, 0]]), 1)
        for invalid in ([], [[]], [[0, 0]], [[1, 0], [1]], [[1, -1]], [[True, 1]], [[1.5, 2]]):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                guessing_probability(invalid)

    def test_uniform_256_exactly_recovers_m06_for_all_edge_budgets(self):
        for q, d in ((0, 0), (0, 7), (1, 0), (1, 1), (1 << 64, 2),
                     (1 << 128, 1), (1 << 300, 0), (1 << 300, 1)):
            self.assertEqual(gap_bounds(q, d, Fraction(1, 1 << 256)), rejection_bounds(q, d))

    def test_no_indexed_query_has_zero_gap_even_for_known_key(self):
        def public_only(h, f, e):
            return tuple(h(z) for z in range(3))
        counts = [[5, 0, 0], [0, 0, 2]]
        real, ideal = finite_laws(counts, 2, public_only)
        self.assertEqual(real, ideal)
        self.assertEqual(gap_bounds(1 << 300, 0, Fraction(1)), dict(rom=0, qrom=0))

    def test_one_candidate_exact_nonuniform_transcript_gap(self):
        counts = [[3, 1, 0], [0, 1, 3]]
        for alphabet in (2, 3, 4):
            def choose_map(h, f, e):
                return f(), h(0 if e == 0 else 2)
            real, ideal = finite_laws(counts, alphabet, choose_map)
            gap = variation(real, ideal)
            expected = Fraction(3, 4) * (1 - Fraction(1, alphabet))
            self.assertEqual(gap, expected)
            self.assertLessEqual(gap, gap_bounds(1, 1, Fraction(3, 4))["rom"])

    def test_adaptive_candidate_transcripts_obey_nonuniform_rom_bound(self):
        counts = [[2, 1, 1, 1, 1], [1, 1, 1, 1, 2]]
        def adaptive(h, f, e):
            response = f()
            first = 0 if e == 0 else 4
            public = h(first)
            second = 1 if response == public else 2
            return response, first, public, second, h(second)
        real, ideal = finite_laws(counts, 2, adaptive)
        gap = variation(real, ideal)
        self.assertGreater(gap, 0)
        self.assertLessEqual(gap, Fraction(2, 3))
        self.assertEqual(gap_bounds(2, 2, guessing_probability(counts))["rom"], Fraction(2, 3))

    def test_known_key_has_near_unit_gap_despite_valid_key_alphabet(self):
        # Giving E=z reveals the key. No entropy conclusion follows from the
        # key's merely having the expected length/label set.
        counts = [[1, 0], [0, 1]]
        real, ideal = finite_laws(counts, 8, lambda h, f, e: (f(), h(e)))
        self.assertEqual(variation(real, ideal), Fraction(7, 8))
        self.assertEqual(gap_bounds(1, 1, guessing_probability(counts)), dict(rom=1, qrom=1))

    def test_query_row_weight_with_classical_side_information(self):
        counts = [[3, 1, 0], [0, 1, 3]]
        total = sum(map(sum, counts))
        weights = [tuple(Fraction(n, 4) for n in row) for row in product(range(5), repeat=3)
                   if sum(row) <= 4]  # Missing weight can belong to non-J domains.
        largest = Fraction(0)
        for first, second in product(weights, repeat=2):
            hit = sum((Fraction(count, total) * weight
                       for row, distribution in zip(counts, (first, second))
                       for count, weight in zip(row, distribution)), Fraction(0))
            self.assertLessEqual(hit, Fraction(3, 4))
            # A row phase flip on |-> gives squared difference 4*hit.
            self.assertLessEqual(4 * hit, 4 * guessing_probability(counts))
            largest = max(largest, hit)
        self.assertEqual(largest, Fraction(3, 4))

    def test_outward_sqrt_and_non_square_probabilities(self):
        for value in (Fraction(1), Fraction(1, 4), Fraction(1, 3), Fraction(7, 10), Fraction(1, 1 << 255)):
            lower, upper = sqrt_interval(value)
            self.assertLessEqual(lower * lower, value)
            self.assertGreaterEqual(upper * upper, value)
            self.assertLessEqual(upper - lower, Fraction(1, 1 << 256))
            result = gap_bounds(1, 1, value)
            self.assertEqual(result["qrom"], min(1, 2 * upper))
        lower, upper = sqrt_interval(Fraction(1, 1 << 256))
        self.assertEqual(lower, upper)
        self.assertEqual(upper, Fraction(1, 1 << 128))

    def test_nonuniform_one_query_coherent_measurement_keeps_cross_terms(self):
        # Prepare sum_z a_z |z>|0>, query the full table, and project back
        # onto that same key state with answer r. Acceptance is the square
        # of total matching key weight, retaining all cross terms.
        keys = 8
        counts = [[2] + [1] * 7, [1] * 7 + [2]]
        total = sum(map(sum, counts))
        real, ideal = Fraction(0), Fraction(0)
        for table in product(range(2), repeat=keys):
            for e, row in enumerate(counts):
                amplitudes = list(range(1, 9)) if e == 0 else list(range(8, 0, -1))
                squared_norm = sum(a * a for a in amplitudes)
                acceptance = [sum((Fraction(a * a, squared_norm)
                                   for a, bit in zip(amplitudes, table) if bit == response), Fraction(0)) ** 2
                              for response in range(2)]
                for z, count in enumerate(row):
                    real += Fraction(count, total * 2**keys) * acceptance[table[z]]
                ideal += Fraction(sum(row), total * 2 ** (keys + 1)) * sum(acceptance)
        gap = abs(real - ideal)
        self.assertEqual(guessing_probability(counts), Fraction(2, 9))
        self.assertGreater(gap, 0)
        self.assertLessEqual(gap, gap_bounds(1, 1, Fraction(2, 9))["qrom"])
        self.assertLess(gap_bounds(1, 1, Fraction(2, 9))["qrom"], 1)

    def test_invalid_inputs_and_entropy_monotonicity(self):
        for invalid in (-1, True, 0.5):
            with self.assertRaises(ValueError):
                gap_bounds(invalid, 1, Fraction(1, 2))
            with self.assertRaises(ValueError):
                gap_bounds(1, invalid, Fraction(1, 2))
        for invalid in (-1, 0, True, 0.5, Fraction(3, 2), Fraction(1, 1 << 257)):
            with self.assertRaises(ValueError):
                gap_bounds(1, 1, invalid)
        for invalid in (0, -1, True, 4097):
            with self.assertRaises(ValueError):
                gap_bounds(1, 1, Fraction(1, 2), invalid)
        last = None
        for bits in range(0, 257, 8):
            result = gap_bounds(1 << 32, 1, Fraction(1, 1 << bits))
            if last is not None:
                self.assertLessEqual(result["rom"], last["rom"])
                self.assertLessEqual(result["qrom"], last["qrom"])
            last = result

    def snapshot_fixture(self, destination):
        (destination / "sources").mkdir()
        for name in SOURCE_NAMES:
            category = ("docs" if name.endswith(".md") else
                        "crates/kem1536/src" if name == "dev_kem.rs" else "research")
            shutil.copyfile(ROOT / category / name, destination / "sources" / name)
        (destination / "bounds.json").write_text(json.dumps(make_report(destination / "sources/dev_kem.rs")), encoding="utf-8")
        provenance = dict(schema="m08-j-side-info-provenance-v1", new_fuzz_or_benchmark_performed=False,
                          output_sha256={path.relative_to(destination).as_posix(): sha(path)
                                         for path in destination.rglob("*") if path.is_file()})
        (destination / "provenance.json").write_text(json.dumps(provenance), encoding="utf-8")
        return provenance

    def test_snapshot_replay_rejects_changed_or_resealed_wrong_bound(self):
        parent = ROOT / "target"
        parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="m08-side-info-test-", dir=parent) as temporary:
            fixture = Path(temporary)
            self.assertEqual(fixture.resolve().parent, parent.resolve())
            provenance = self.snapshot_fixture(fixture)
            self.assertEqual(verify(fixture)["files_verified"], 7)
            report = json.loads((fixture / "bounds.json").read_text(encoding="utf-8"))
            report["panels"][-1]["epsilon_j_qrom_upper"]["numerator_hex"] = "0x123"
            (fixture / "bounds.json").write_text(json.dumps(report), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "source/output differs"):
                verify(fixture)
            provenance["output_sha256"]["bounds.json"] = sha(fixture / "bounds.json")
            (fixture / "provenance.json").write_text(json.dumps(provenance), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "rational replay differs"):
                verify(fixture)

    def test_snapshot_replay_rejects_missing_required_input_or_extra_member(self):
        parent = ROOT / "target"
        parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="m08-side-info-test-", dir=parent) as temporary:
            fixture = Path(temporary)
            self.assertEqual(fixture.resolve().parent, parent.resolve())
            provenance = self.snapshot_fixture(fixture)
            (fixture / "unexpected.txt").write_text("fixture extra", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "inventory differs"):
                verify(fixture)
            provenance["output_sha256"].pop("sources/rejection_security_m06.py")
            (fixture / "provenance.json").write_text(json.dumps(provenance), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "required source inventory"):
                verify(fixture)


if __name__ == "__main__":
    unittest.main()
