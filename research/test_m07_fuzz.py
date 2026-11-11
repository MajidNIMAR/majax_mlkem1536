"""M07 campaign guards use tiny owned fixtures; no compiler or fuzzer is run."""
from contextlib import redirect_stdout
from copy import deepcopy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import run_m07_fuzz as campaign

PROJECT = Path(__file__).resolve().parents[1]


class M07FuzzGuards(unittest.TestCase):
    def setUp(self):
        parent = PROJECT / "target"
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent, prefix="m07-fuzz-unit-")
        self.fixture = Path(self.temporary.name).resolve()
        if self.fixture.parent != parent.resolve():
            raise ValueError("refusing fixture outside the owned target directory")
        self.addCleanup(self.temporary.cleanup)
        self.root = self.fixture / "repo"
        (self.root / "artifacts/generated").mkdir(parents=True)
        (self.root / "target").mkdir()
        self.measurements = self.root / "artifacts/generated/m07-001"
        self.source = self.measurements / "candidate-source"
        (self.source / "fuzz/fixtures").mkdir(parents=True)
        (self.source / "crates/kem1536/src").mkdir(parents=True)
        (self.source / "fuzz/fixtures/cases.bin").write_bytes(b"synthetic fixture only")
        (self.source / "crates/kem1536/src/dev_kem.rs").write_text("// metadata guard fixture\n")
        for name in ("Cargo.toml", "Cargo.lock", "src/lib.rs", "fixtures/cases.bin",
                     *(f"fuzz_targets/{target}.rs" for target in campaign.TARGETS)):
            path = self.root / "fuzz" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"synthetic fixture only" if name == "fixtures/cases.bin" else b"// guard fixture\n")
        self.manifest = self.measurements / "candidate-source.json"
        self.manifest.write_text(json.dumps({"profile": campaign.PROFILE,
            "source_sha256": campaign.inventory(self.source)}))
        self.marker = self.measurements / "MEMORY_AND_LATENCY_ACCEPTED.json"
        self.accepted = {"profile": campaign.PROFILE, "accepted": True,
                         "candidate_source_manifest_sha256": campaign.sha(self.manifest)}
        self.marker.write_text(json.dumps(self.accepted))
        self.root_patch = patch.object(campaign, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def test_missing_acceptance_gate_precedes_output_and_compiler(self):
        self.marker.unlink()
        output = self.root / "artifacts/generated/m07-fuzz-001"
        target = self.root / "target/m07-fuzz-001"
        with patch.object(campaign.sys, "platform", "linux"), \
             patch.object(campaign.os, "sched_getaffinity", return_value={10}, create=True), \
             patch.object(campaign.subprocess, "run") as process, \
             patch.object(campaign.subprocess, "check_output") as versions:
            with self.assertRaisesRegex(ValueError, "wait for MEMORY_AND_LATENCY_ACCEPTED"):
                campaign.execute(output, self.measurements, target, 10, 60)
            process.assert_not_called()
            versions.assert_not_called()
        self.assertFalse(output.exists())
        self.assertFalse(target.exists())

    def test_acceptance_is_bound_to_exact_manifest(self):
        self.accepted["candidate_source_manifest_sha256"] = "0" * 64
        self.marker.write_text(json.dumps(self.accepted))
        with self.assertRaisesRegex(ValueError, "not bound"):
            campaign.bind_inputs(self.measurements)

    def test_changed_measured_source_is_refused(self):
        (self.source / "crates/kem1536/src/dev_kem.rs").write_text("// changed fixture\n")
        with self.assertRaisesRegex(ValueError, "measured candidate source changed"):
            campaign.bind_inputs(self.measurements)

    def test_existing_fixture_cannot_be_replaced_by_fuzz_attachment(self):
        (self.root / "fuzz/fixtures/cases.bin").write_bytes(b"conflicting fixture")
        with self.assertRaisesRegex(ValueError, "attachment conflicts"):
            campaign.bind_inputs(self.measurements)

    def test_complete_fuzz_attachment_preserves_all_measured_members(self):
        bound = campaign.bind_inputs(self.measurements)
        self.assertEqual(bound["source_sha256"], campaign.inventory(self.source))
        self.assertTrue(all(f"fuzz/fuzz_targets/{name}.rs" in bound["fuzz_sha256"] for name in campaign.TARGETS))
        self.assertEqual(bound["source_sha256"]["fuzz/fixtures/cases.bin"], bound["fuzz_sha256"]["fuzz/fixtures/cases.bin"])

    def test_output_paths_must_be_direct_owned_m07_children(self):
        for name in ("m06-fuzz-001", "m07-parent/nested", "../../outside"):
            with self.subTest(path=name), self.assertRaises(ValueError):
                campaign.owned(self.root / "artifacts/generated" / name, self.root / "artifacts/generated")

    def test_initialization_only_and_invalid_execution_counters_are_refused(self):
        post = {"all_four_have_post_INITED_execution": True, "targets": {
            name: {"executions_after_INITED": 5, "segments": [{"INITED_line_unique": True,
                "INITED_counter": 7, "final_executed_units_counter": 12}]} for name in campaign.TARGETS}}
        campaign.require_post_init(post)
        for change in ({"final_executed_units_counter": 7}, {"INITED_line_unique": False},
                       {"final_executed_units_counter": None}, {"final_executed_units_counter": 6}):
            bad = deepcopy(post)
            bad["targets"]["api_sequence"]["segments"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                campaign.require_post_init(bad)

    def segment_fixture(self, user=30.0, system=30.0):
        folder = self.root / "segment-test"
        folder.mkdir()
        log = "#7 INITED cov: 5 ft: 7\n#12 DONE cov: 5 ft: 7\nstat::number_of_executed_units: 12\nstat::peak_rss_mb: 1\n"
        (folder / "segment-000.log").write_text(log)
        usage = {"user_seconds": user, "system_seconds": system, "wall_seconds": 60.0, "exit_code": 0}
        row = {"segment": 0, "exit_code": 0, "resource_usage": usage,
               **campaign.fuzz_statistics(folder / "segment-000.log")}
        item = {"status": "complete", "budget_CPU_seconds": 60, "sequential_affinity_CPU": 10,
                "defects_observed": False, "CPU_seconds": 60.0, "segments": [row],
                "executions_including_repeated_seeds": 12}
        (folder / "segment-000-usage.json").write_text(json.dumps(usage))
        (folder / "segment-000-result.json").write_text(json.dumps(row))
        (folder / "summary.json").write_text(json.dumps(item))
        return folder, item

    def test_duplicate_segment_cannot_credit_same_cpu_twice(self):
        folder, item = self.segment_fixture()
        self.assertEqual(campaign.verify_segments(folder, item, 60, 10), 60)
        item["segments"].append(deepcopy(item["segments"][0]))
        with self.assertRaisesRegex(ValueError, "unique and contiguous"):
            campaign.verify_segments(folder, item, 60, 10)

    def test_omitted_segment_file_is_rejected(self):
        folder, item = self.segment_fixture()
        (folder / "segment-000-result.json").unlink()
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            campaign.verify_segments(folder, item, 60, 10)

    def test_negative_cpu_cannot_be_hidden_by_positive_system_time(self):
        folder, item = self.segment_fixture(user=-1.0, system=61.0)
        with self.assertRaisesRegex(ValueError, "invalid CPU"):
            campaign.verify_segments(folder, item, 60, 10)

    def test_read_only_cli_verify_accepts_an_archived_results_path(self):
        archived = self.root / "results/engine/m07-001/fuzz"
        with patch.object(campaign.sys, "argv", ["run_m07_fuzz.py", "verify", "--output", str(archived)]), \
             patch.object(campaign, "verify", return_value={"fixture_only": True}) as verify, \
             patch.object(campaign, "owned") as writer_guard, redirect_stdout(io.StringIO()):
            campaign.main()
        verify.assert_called_once_with(archived.resolve())
        writer_guard.assert_not_called()


if __name__ == "__main__":
    unittest.main()
