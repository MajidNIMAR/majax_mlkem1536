"""Mutation tests for coverage and corpus ledgers; no compiler/oracle is run."""
from copy import deepcopy
import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import postprocess_m08_fuzz as coverage
import replay_m08_fuzz_corpus as replay
import run_m08_fuzz as campaign


def toy_export(covered=1, function_count=0, zero_true=0):
    name = "/fixture/crates/kem1536/src/dev_kem.rs"
    summary = {kind: {"covered": covered, "count": 2, "percent": covered * 50}
               for kind in ("lines", "functions", "regions", "branches")}
    return {"type": "llvm.coverage.json.export", "data": [{
        "files": [{"filename": name, "summary": summary,
                   "segments": [[10, 1, 0, True, True, False], [11, 1, 0, False, True, False]],
                   "branches": [[10, 1, 10, 20, zero_true, 3, 0, 0, 4]]}],
        "functions": [{"name": "fixture_validate", "count": function_count, "filenames": [name]}]}]}


class M08CoverageTests(unittest.TestCase):
    def request_fixture(self):
        config = {"source_sha256": {"core.rs": "source hash"}, "candidate_source_manifest_sha256": "manifest",
                  "controller_sha256": {"postprocess_m08_fuzz.py": "post tool", "replay_m08_fuzz_corpus.py": "replay tool"},
                  "ASAN_OPTIONS": "test ASAN", "versions": {"rustc": "release: 1.91.1\nLLVM version: 21.1.2\n",
                      "compiler_binary_sha256": "compiler", "cargo_fuzz_binary_sha256": "driver"}}
        request = {"schema": "m08-coverage-request-v1", "source_sha256": config["source_sha256"],
                   "candidate_source_manifest_sha256": "manifest", "standard_library_rebuilt_for_coverage": False,
                   "rustflags_extra": "-Zcoverage-options=branch", "native_CPU": 8,
                   "controllers_sha256": config["controller_sha256"], "rustc": config["versions"]["rustc"],
                   "compiler_binary_sha256": "compiler", "cargo_fuzz_binary_sha256": "driver",
                   "ASAN_OPTIONS": "test ASAN:detect_odr_violation=0", "llvm_cov": "LLVM version 21.1.2-rust",
                   "llvm_profdata": "LLVM version 21.1.2-rust"}
        return request, config

    def test_coverage_request_binds_tools_controllers_and_instrumentation_scope(self):
        request, config = self.request_fixture()
        coverage.check_request(request, config)
        for mutation in ({"controllers_sha256": {}}, {"compiler_binary_sha256": "other compiler"},
                         {"standard_library_rebuilt_for_coverage": True}, {"rustflags_extra": ""},
                         {"llvm_profdata": "LLVM version 20.0.0"}):
            bad = deepcopy(request)
            bad.update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                coverage.check_request(bad, config)

    def test_coverage_command_uses_declared_cpu_and_exact_harvested_target(self):
        request, _ = self.request_fixture()
        row = {"coverage_command": ["taskset", "-c", "8", "/tool/cargo", "fuzz", "coverage", "import_public",
                                    "/run/harvested-corpus/import_public"],
               "export_command": ["/tool/llvm-cov", "export", "/run/bin/import_public"],
               "standard_library_rebuilt": False, "LLVM_source_and_branch_coverage": True,
               "libFuzzer_edges_are_not_source_coverage": True}
        coverage.check_coverage_command(row, "import_public", request)
        for index, value in ((2, "10"), (7, "/run/harvested-corpus/import_private")):
            bad = deepcopy(row)
            bad["coverage_command"][index] = value
            with self.subTest(index=index), self.assertRaises(ValueError):
                coverage.check_coverage_command(bad, "import_public", request)
        bad = deepcopy(row)
        bad["export_command"].append("-summary-only")
        with self.assertRaisesRegex(ValueError, "full LLVM"):
            coverage.check_coverage_command(bad, "import_public", request)

    def test_preserves_zero_functions_regions_and_uncovered_branch_sides(self):
        result = coverage.core_summary(toy_export())
        self.assertEqual(result["zero_count_functions"][0]["LLVM_name"], "fixture_validate")
        unmapped = result["uncovered_source_mappings"][0]
        self.assertEqual(len(unmapped["zero_count_region_entries"]), 1)
        self.assertTrue(unmapped["branch_sides_not_observed"][0]["zero_true"])
        self.assertFalse(unmapped["branch_sides_not_observed"][0]["zero_false"])

    def test_rejects_summary_only_missing_functions_and_invalid_counts(self):
        for change in ("functions", "counts", "duplicate", "type"):
            data = toy_export()
            if change == "functions":
                data["data"][0]["functions"] = []
            elif change == "counts":
                data["data"][0]["files"][0]["summary"]["lines"]["covered"] = 3
            elif change == "duplicate":
                data["data"][0]["files"] *= 2
            else:
                data["type"] = "pretended coverage"
            with self.subTest(change=change), self.assertRaises(ValueError):
                coverage.core_summary(data)

    def test_union_must_be_a_superset_not_a_sum_of_overlapping_counts(self):
        first = coverage.core_summary(toy_export(1))
        union = coverage.core_summary(toy_export(2))
        coverage.require_union_superset(union, {"first": first, "second": first})
        with self.assertRaisesRegex(ValueError, "not a superset"):
            coverage.require_union_superset(first, {"larger": union})


class M08CorpusLedgerTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parents[1] / "target"
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="m08-ledger-test-", dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        if self.root.parent != parent.resolve():
            raise ValueError("temporary fixture escaped its owned target parent")
        (self.root / "source/fuzz/fixtures").mkdir(parents=True)
        (self.root / "source/fuzz/fixtures/cases.bin").write_bytes(bytes(164864))
        (self.root / "source/oracle").mkdir()
        (self.root / "source/oracle/kem_r1_reference.py").write_text("# independent oracle guard fixture\n")
        self.oracle = campaign.sha(self.root / "source/oracle/kem_r1_reference.py")
        for name, values in zip(campaign.TARGETS, ((b"a", b"a"), (b"b",), (b"\x01xx",),
                                                  (b"\x00\x03\x00\x00\x00",))):
            folder = self.root / name / "corpus"
            folder.mkdir(parents=True)
            for index, value in enumerate(values):
                (folder / str(index)).write_bytes(value)
        (self.root / "fuzz-summary.json").write_text('{"fixture_only":true}')
        campaign.harvest(self.root)

    def test_harvest_deduplicates_bytes_without_deleting_raw_inputs(self):
        result = campaign.verify_harvest(self.root)
        self.assertEqual(result["import_public"], 1)
        self.assertEqual(len(list((self.root / "import_public/corpus").iterdir())), 2)
        ledger = campaign.read(self.root / "harvest.json")
        self.assertEqual(ledger["targets"]["import_public"]["raw_file_count"], 2)
        self.assertEqual(ledger["targets"]["import_public"]["unique_content_count"], 1)

    def test_changed_raw_or_harvested_inputs_are_refused(self):
        (self.root / "import_public/corpus/0").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "provenance differs"):
            campaign.verify_harvest(self.root)

    def test_request_builder_separates_fresh_steps_and_ignores_truncated_steps(self):
        requests, counts, fresh, _, hashes = replay.requests_from_corpus(self.root)
        self.assertEqual(len(requests), 3)
        self.assertEqual(fresh, 1)
        self.assertEqual(counts["api_sequence"], 1)
        (self.root / "harvested-corpus/api_sequence/truncated").write_bytes(b"\x01\x03\x00")
        requests, _, fresh, _, _ = replay.requests_from_corpus(self.root)
        self.assertEqual(len(requests), 3)
        self.assertEqual(fresh, 1)

    def transcript_fixture(self):
        requests, counts, fresh, _, hashes = replay.requests_from_corpus(self.root)
        transcript = self.root / "oracle-transcript.jsonl.gz"
        digest = hashlib.sha256()
        with transcript.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as stream:
            for identity in requests:
                request = replay.request_value(identity)
                result = {"accepted": False}
                entry = {"request": request, "Rust": result, "Python": result,
                         "oracle_reencryption_accepted": None}
                stream.write(replay.canonical(entry) + b"\n")
                digest.update(replay.canonical([request, result]))
        config = {"oracle_sha256": self.oracle,
                  "controller_sha256": {"replay_m08_fuzz_corpus.py": "fixture tool hash"}}
        receipt = {"profile": campaign.PROFILE, "corpus_files": counts, "corpus_sha256": hashes,
                   "fresh_operations_encoded_in_corpus_not_recreated_by_oracle": fresh,
                   "all_Rust_Python_outputs_equal": True, "numpy": "2.3.5", "oracle_sha256": self.oracle,
                   "replay_binary_sha256": "fixture binary hash", "replay_controller_sha256": "fixture tool hash",
                   "transcript_sha256": campaign.sha(transcript), "distinct_deterministic_requests": len(requests),
                   "cumulative_sha256": digest.hexdigest(), "accepted_private_import_requests_with_independent_decapsulation_probe": 0,
                   "oracle_reencryption_acceptances": 0}
        for name, value in (("config.json", config), ("replay-build.json", {"binary_sha256": "fixture binary hash"}),
                            ("oracle-replay.json", receipt)):
            (self.root / name).write_text(json.dumps(value))
        return transcript, receipt

    def test_transcript_replays_exactly_the_deduplicated_request_panel(self):
        _, _ = self.transcript_fixture()
        result = replay.verify(self.root)
        self.assertEqual(result["independent_replay_requests_verified"], 3)
        self.assertFalse(result["new_oracle_execution_by_verifier"])

    def test_forged_summary_count_or_omitted_transcript_is_refused(self):
        path, receipt = self.transcript_fixture()
        receipt["distinct_deterministic_requests"] += 1
        (self.root / "oracle-replay.json").write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, "incomplete or changed"):
            replay.verify(self.root)
        receipt["distinct_deterministic_requests"] -= 1
        path.write_bytes(gzip.compress(b""))
        receipt["transcript_sha256"] = campaign.sha(path)
        (self.root / "oracle-replay.json").write_text(json.dumps(receipt))
        with self.assertRaisesRegex(ValueError, "incomplete or changed"):
            replay.verify(self.root)


if __name__ == "__main__":
    unittest.main()
