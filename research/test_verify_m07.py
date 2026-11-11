"""Small mutation checks for the M07 evidence verifier; no engine execution."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import verify_m07 as verify
from run_m07 import MEMORY_NUMBERS, MEMORY_OPERATIONS, OPERATIONS, summarize, validate_memory


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def memory_rows(depth=10000):
    rows = []
    for operation in MEMORY_OPERATIONS:
        for pattern in (0xa5, 0x5a):
            row = dict.fromkeys(MEMORY_NUMBERS, 0)
            row.update(schema=1, profile=verify.PROFILE, operation=operation, paint_pattern=pattern,
                       native_stack_size_requested=1024 * 1024, paint_top_margin_bytes=512,
                       paint_search_bytes=256 * 1024 - 512, touched_stack_high_water_bytes=depth,
                       saturated=False, functional_validation=True, secrets_printed=False)
            if operation.startswith("calibration_"):
                size = int(operation.split("_")[1])
                row.update(calibration_written_array_bytes=size,
                           known_written_calibration_depth_bytes=size + 24,
                           touched_stack_high_water_bytes=size + 72)
            if operation == "noop":
                row["touched_stack_high_water_bytes"] = 0
            rows.append(row)
    return rows


class M07VerifierTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parents[1] / "target"
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent, prefix="m07-verifier-test-")
        self.root = Path(self.temporary.name).resolve()
        if self.root.parent != parent.resolve():
            raise ValueError("test fixture escaped owned target")
        self.addCleanup(self.temporary.cleanup)

    def latency_fixture(self):
        folder = self.root / "latency"
        folder.mkdir()
        rows, runs = [], []
        builds = {label: {"windows": {"latency": {"path": f"{label}/windows/bin/latency.exe"}}}
                  for label in verify.LABELS}
        instant = datetime(2026, 11, 11, tzinfo=timezone.utc)
        for series in range(2):
            labels = verify.LABELS if series % 2 == 0 else verify.LABELS[::-1]
            for label in labels:
                parsed = [{"operation": op, "series": series, "iteration": iteration,
                           "nanoseconds": 100 + index + (5 if label == "candidate" else 0)}
                          for index, op in enumerate(OPERATIONS) for iteration in range(2)]
                raw = b"".join((json.dumps(row) + "\n").encode() for row in parsed)
                (folder / f"{label}-{series}.stdout.gz").write_bytes(gzip.compress(raw))
                (folder / f"{label}-{series}.stderr").write_bytes(b"")
                runs.append({"version": label, "series": series,
                             "command": [builds[label]["windows"]["latency"]["path"], str(series), "2", "1"],
                             "stdout_sha256": hashlib.sha256(raw).hexdigest(),
                             "stderr_sha256": hashlib.sha256(b"").hexdigest(), "exit_code": 0,
                             "started_utc": instant.isoformat(),
                             "finished_utc": (instant + timedelta(microseconds=500000)).isoformat()})
                instant += timedelta(seconds=1)
                rows.extend(dict(version=label, **row) for row in parsed)
        schedule = {"samples": 2, "warmup": 1, "series": 2, "CPU": 10,
                    "OS_randomness_included": True, "drop_and_validation_outside_timing": True,
                    "frequency_fixed": False, "physical_core_exclusive": False,
                    "host_activity_isolated": False, "schedule": runs}
        save(folder / "schedule.json", schedule)
        self.write_observations(folder, rows)
        save(folder / "statistics.json", summarize(rows, verify.LABELS, 2, 2))
        return folder, builds, rows, schedule

    def write_observations(self, folder, rows):
        raw = b"".join((json.dumps(row) + "\n").encode() for row in rows)
        (folder / "observations.jsonl.gz").write_bytes(gzip.compress(raw))

    def check_latency(self, folder, builds):
        return verify.check_latency(folder, builds, verify.LABELS, 2, 1, 2, 10, "windows")

    def test_memory_grid_omission_and_duplicate_are_invalid(self):
        rows = memory_rows()
        self.assertEqual(len(validate_memory(rows, 1)), 14)
        for changed in (rows[:-1], rows[:-1] + [deepcopy(rows[0])]):
            with self.subTest(count=len(changed)), self.assertRaises(ValueError):
                validate_memory(changed, 1)

    def test_memory_bad_counters_and_calibration_are_invalid(self):
        for key, value in (("tracker_overflows", 1), ("retained_requested_bytes_at_api_return", 1),
                           ("saturated", True), ("sample", True)):
            rows = memory_rows()
            rows[0][key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                validate_memory(rows, 1)
        rows = memory_rows()
        rows[2]["known_written_calibration_depth_bytes"] = 1
        with self.assertRaises(ValueError):
            validate_memory(rows, 1)

    def test_valid_data_can_fail_memory_budget_without_becoming_invalid(self):
        raw = {label: {host: memory_rows(10000 if label == "baseline" else 7000)
                       for host in verify.HOSTS} for label in verify.LABELS}
        summaries = {label: {host: validate_memory(rows, 1) for host, rows in hosts.items()}
                     for label, hosts in raw.items()}
        self.assertTrue(all(row["pass"] for row in verify.compare_memory(summaries, raw, verify.EXPECTED_BUDGETS)))
        for row in raw["candidate"]["windows"]:
            if row["operation"] == "keygen":
                row["touched_stack_high_water_bytes"] = 9000
        summaries["candidate"]["windows"] = validate_memory(raw["candidate"]["windows"], 1)
        checks = verify.compare_memory(summaries, raw, verify.EXPECTED_BUDGETS)
        self.assertFalse(all(row["pass"] for row in checks))
        self.assertEqual(sum(not row["pass"] for row in checks), 1)

    def test_heap_increase_is_a_budget_failure(self):
        raw = {label: {host: memory_rows(10000 if label == "baseline" else 7000)
                       for host in verify.HOSTS} for label in verify.LABELS}
        for row in raw["candidate"]["linux"]:
            if row["operation"] == "encaps":
                row.update(alloc_calls=1, total_requested_bytes=64, peak_live_requested_bytes=64,
                           retained_requested_bytes_at_api_return=64)
        summaries = {label: {host: validate_memory(rows, 1) for host, rows in hosts.items()}
                     for label, hosts in raw.items()}
        checks = verify.compare_memory(summaries, raw, verify.EXPECTED_BUDGETS)
        self.assertEqual(sum(not row["pass"] for row in checks), 4)

    def test_hash_mutation_and_path_escape_are_rejected(self):
        (self.root / "payload.bin").write_bytes(b"recorded\0bytes")
        hashes = {"payload.bin": verify.sha(self.root / "payload.bin")}
        verify.check_hashes(self.root, hashes)
        (self.root / "payload.bin").write_bytes(b"changed\0bytes")
        with self.assertRaises(verify.InvalidData):
            verify.check_hashes(self.root, hashes)
        for name in ("../outside", "/absolute", "a\\b", "C:/outside", "a/../b"):
            with self.subTest(name=name), self.assertRaises(verify.InvalidData):
                verify.member(self.root, name)

    def test_real_stdout_reconstructs_retained_latency_and_statistics(self):
        folder, builds, _, _ = self.latency_fixture()
        result = self.check_latency(folder, builds)
        self.assertEqual(result["candidate/encaps"]["count"], 4)
        self.assertTrue(all(row["pass"] for row in verify.compare_latency({"windows": result}, verify.EXPECTED_BUDGETS)))

    def test_false_latency_summary_is_rejected(self):
        folder, builds, _, _ = self.latency_fixture()
        saved = verify.read(folder / "statistics.json")
        saved["candidate/keygen"]["median_ns"] = 1
        save(folder / "statistics.json", saved)
        with self.assertRaises(verify.InvalidData):
            self.check_latency(folder, builds)

    def test_changed_aggregate_is_rejected_even_if_saved_summary_changes(self):
        folder, builds, rows, _ = self.latency_fixture()
        rows[0]["nanoseconds"] += 20
        self.write_observations(folder, rows)
        save(folder / "statistics.json", summarize(rows, verify.LABELS, 2, 2))
        with self.assertRaises(verify.InvalidData):
            self.check_latency(folder, builds)

    def test_changed_stdout_hash_and_nonzero_exit_are_rejected(self):
        folder, builds, _, schedule = self.latency_fixture()
        original = deepcopy(schedule)
        for key, value in (("stdout_sha256", "0" * 64), ("exit_code", 7)):
            changed = deepcopy(original)
            changed["schedule"][0][key] = value
            save(folder / "schedule.json", changed)
            with self.subTest(field=key), self.assertRaises(verify.InvalidData):
                self.check_latency(folder, builds)

    def test_non_alternating_schedule_is_rejected(self):
        folder, builds, _, schedule = self.latency_fixture()
        schedule["schedule"][2:] = schedule["schedule"][2:][::-1]
        save(folder / "schedule.json", schedule)
        with self.assertRaises(verify.InvalidData):
            self.check_latency(folder, builds)

    def test_latency_budget_failure_is_valid_comparison(self):
        folder, builds, _, _ = self.latency_fixture()
        stats = self.check_latency(folder, builds)
        stats["candidate/keygen"]["median_ns"] = 112
        checks = verify.compare_latency({"windows": stats}, verify.EXPECTED_BUDGETS)
        self.assertEqual(sum(not row["pass"] for row in checks), 1)

    def test_forged_saved_report_is_rejected(self):
        with self.assertRaises(verify.InvalidData):
            verify.checked_summary({"data_valid": True, "candidate_within_budgets": True},
                                   {"data_valid": True, "candidate_within_budgets": False}, "saved report")


if __name__ == "__main__":
    unittest.main()
