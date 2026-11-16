"""Synthetic byte-only negative tests of the final M09 measurement reader.

No executable, compiler, benchmark or historical acquisition is started.
Fixture durations and binaries are intentionally artificial parser inputs.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import m09_final_measure as model
from run_m07 import MEMORY_NUMBERS


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True)+"\n").encode()


def memory_rows():
    rows = []
    for operation in model.MEMORY_OPERATIONS:
        for paint in (0xa5, 0x5a):
            for sample in range(3):
                row = {name: 0 for name in MEMORY_NUMBERS}
                row.update(schema=1, profile="KEM1536-DEV-Q7681-R1", operation=operation,
                           paint_pattern=paint, sample=sample, saturated=False, functional_validation=True,
                           secrets_printed=False, native_stack_size_requested=1048576,
                           paint_top_margin_bytes=512, paint_search_bytes=262144,
                           touched_stack_high_water_bytes=1024)
                if operation.startswith("calibration_"):
                    size = int(operation.split("_")[1])
                    row.update(calibration_written_array_bytes=size, known_written_calibration_depth_bytes=size,
                               touched_stack_high_water_bytes=size)
                rows.append(row)
    return rows


def fixture():
    raws = {}
    put = lambda name, value: raws.__setitem__(name, encoded(value))
    checksum = lambda name: digest(raws[name])
    subset = lambda prefix: {name[len(prefix)+1:]: digest(raw) for name, raw in raws.items() if name.startswith(prefix+"/")}
    raws["source/core.rs"] = b"candidate fixture"
    raws["source/docs/PROTOCOLE_M09_QUALIFICATION.md"] = b"fixed protocol fixture"
    for name in model.HELPERS:
        raws["source/research/"+name] = ("fixture:"+name).encode()
        raws["measurements/controls/"+name] = raws["source/research/"+name]
    put("source.json", dict(source_sha256=subset("source")))
    raws["measurements/baseline-source/core.rs"] = b"M08 fixture"
    put("measurements/baseline-source.json", dict(source_sha256=subset("measurements/baseline-source")))
    base_hash = checksum("measurements/baseline-source.json")
    candidate_hash = checksum("source.json")
    raws["measurements/controller.py"] = b"controller fixture"
    raws["measurements/protocol.md"] = raws["source/docs/PROTOCOLE_M09_QUALIFICATION.md"]
    raws["measurements/baseline-memory-controller.py"] = b"baseline controller fixture"
    baseline_controller = checksum("measurements/baseline-memory-controller.py")
    rows = memory_rows()
    memory = b"".join(encoded(row) for row in rows)
    memory_summary = model.validate_memory(rows, 3)
    images, output_hashes = {}, {}
    for host in ("windows", "linux"):
        suffix = ".exe" if host == "windows" else ""
        base_image = "reference-latency/"+host+"/latency"+suffix
        candidate_image = host+"/bin/latency"+suffix
        probe = host+"/bin/probe"+suffix
        for name in (base_image, candidate_image, probe):
            raws[name] = ("binary fixture:"+name).encode()
        common = dict(exit_code=0, rustc="release: 1.91.1\n", emit_stack_metadata=False)
        base_build = dict(common, binary="latency"+suffix, sha256=checksum(base_image), source_manifest_sha256=base_hash)
        base_build_path = "reference-latency/"+host+"/build.json"
        put(base_build_path, base_build)
        raws["reference-latency/"+host+"/build.log"] = b"reference build fixture"
        candidate_build = dict(source_manifest_sha256=candidate_hash, binaries=dict(
            latency=dict(common, path=candidate_image, sha256=checksum(candidate_image)),
            probe=dict(common, path=probe, sha256=checksum(probe))))
        candidate_build["binaries"]["probe"]["emit_stack_metadata"] = host == "linux"
        put(host+"/build.json", candidate_build)
        images[host] = {}
        for label, name, receipt in (("baseline", base_image, base_build_path), ("candidate", candidate_image, host+"/build.json")):
            prefix = ["C:/project/"+name] if host == "windows" else ["wsl", "-d", "Ubuntu-22.04", "--", "taskset", "-c", "10", "/mnt/c/project/"+name]
            images[host][label] = dict(path=name, sha256=checksum(name), build_receipt=receipt,
                                       build_receipt_sha256=checksum(receipt), command_prefix=prefix)
        folder = "measurements/baseline-memory/"+host+"/"
        raws[folder+"probe"+suffix] = b"memory probe fixture"
        raws[folder+"build.log"] = b"memory build fixture"
        raws[folder+"memory.jsonl"] = memory
        raws[folder+"memory.stderr"] = b""
        put(folder+"summary.json", memory_summary)
        put(folder+"build.json", dict(common, source_manifest_sha256=base_hash,
            controller_sha256=baseline_controller, binary_sha256=checksum(folder+"probe"+suffix),
            build_log_sha256=checksum(folder+"build.log"), emit_stack_metadata=host == "linux"))
        put(folder+"run.json", dict(command=["fixture-probe", "3"], exit_code=0, repetitions=3,
            binary_sha256=checksum(folder+"probe"+suffix), raw_sha256=checksum(folder+"memory.jsonl"),
            stderr_sha256=checksum(folder+"memory.stderr")))
        folder = "validation/"+host+"/"
        raws[folder+"memory.stdout"] = memory
        raws[folder+"memory.stderr"] = b""
        put(folder+"memory.receipt.json", dict(command=["fixture-probe", "3"], binary_sha256=checksum(probe), exit_code=0, expected_exit_code=0))
        for name in ("memory.stdout", "memory.stderr", "memory.receipt.json"):
            output_hashes[host+"/"+name] = checksum(folder+name)
    after_path = "qualification-adapter/validate-001/after.json"
    put(after_path, dict(status="PASS", child_exit_code=0, exit_code_known=True,
                         after=dict(binding=dict(source_manifest_sha256=candidate_hash)), output_sha256=output_hashes))
    put("measurements/reference-origin.json", dict(reference_inventory=subset("reference-latency"),
        baseline_memory_inventory=subset("measurements/baseline-memory"), new_reference_builds_performed=0,
        new_baseline_memory_acquisitions=0, historical_campaign_credit_seconds=0, baseline_memory_reused_observations=216))
    plan = dict(source_manifest_sha256=candidate_hash, baseline_manifest_sha256=base_hash, series=5, samples=500,
                warmup=100, CPU=10, stack_max_additional_bytes=1024, median_ratio_max=1.05, p95_ratio_max=1.20,
                minimum_gain_each_OS=.05, no_exclusions=True, controller_sha256=checksum("measurements/controller.py"),
                protocol_sha256=checksum("measurements/protocol.md"),
                helpers={name: checksum("measurements/controls/"+name) for name in model.HELPERS},
                baseline_memory_controller_sha256=baseline_controller,
                reference_origin_sha256=checksum("measurements/reference-origin.json"), images=images,
                candidate_memory_validation_after_sha256=checksum(after_path), created_utc="2026-11-16T00:00:00+00:00")
    put("measurements/plan.json", plan)
    runs = []
    for host in ("windows", "linux"):
        for series in range(5):
            for label in (("baseline", "candidate") if series % 2 == 0 else ("candidate", "baseline")):
                stem = f"{host}-{series}-{label}"
                name = "measurements/"+stem
                raws[name+".jsonl"] = b"".join(encoded(dict(operation=op, series=series, iteration=i,
                                                          nanoseconds=100 if label == "baseline" else 90))
                                                 for op in model.OPS for i in range(500))
                raws[name+".stderr"] = b""
                started = datetime(2026, 11, 16, tzinfo=timezone.utc)+timedelta(seconds=len(runs)+1)
                run = dict(host=host, series=series, label=label, raw=stem+".jsonl", raw_sha256=checksum(name+".jsonl"),
                           stderr_sha256=checksum(name+".stderr"), binary_sha256=images[host][label]["sha256"],
                           command=images[host][label]["command_prefix"]+[str(series), "500", "100"], exit_code=0,
                           started_utc=started.isoformat(), finished_utc=(started+timedelta(milliseconds=1)).isoformat())
                put(name+".receipt.json", run)
                runs.append(run)
    put("measurements/runs.json", runs)
    return raws


class FinalMeasurementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.good = fixture()

    def setUp(self):
        self.patched_core = patch.dict(model.M08_CORE, {"core.rs": digest(b"M08 fixture")}, clear=True)
        self.patched_core.start()
        self.addCleanup(self.patched_core.stop)

    def changed(self, path, change):
        raws = dict(self.good)
        item = json.loads(raws[path])
        change(item)
        raws[path] = encoded(item)
        return raws

    def reject(self, raws):
        with self.assertRaises((ValueError, KeyError)):
            model.evaluate_raws(raws)

    def test_positive_fixture_replays_without_execution(self):
        with patch("subprocess.run", side_effect=AssertionError("execution forbidden")):
            report = model.evaluate_raws(self.good)
        self.assertTrue(report["all_budgets_passed"])
        self.assertEqual(report["latency_observations"], 40000)
        self.assertEqual(report["baseline_memory_reused_observations"], 216)
        self.assertEqual(report["historical_campaign_credit_seconds"], 0)

    def test_plan_threshold_cpu_or_type_changes_are_rejected(self):
        for key, value in (("minimum_gain_each_OS", .04), ("CPU", 11), ("series", True),
                           ("samples", 499), ("no_exclusions", False), ("stack_max_additional_bytes", 2048)):
            self.reject(self.changed("measurements/plan.json", lambda item: item.__setitem__(key, value)))

    def test_source_controller_protocol_helper_and_images_are_bound(self):
        for name in ("source/core.rs", "measurements/baseline-source/core.rs", "measurements/controller.py",
                     "measurements/protocol.md", "measurements/controls/run_m07.py", "windows/bin/latency.exe",
                     "reference-latency/linux/latency", "reference-latency/windows/build.log"):
            raws = dict(self.good)
            raws[name] += b"mutation"
            self.reject(raws)

    def test_changed_build_source_is_rejected_even_if_plan_hash_is_repaired(self):
        for host in ("windows", "linux"):
            path = host+"/build.json"
            raws = self.changed(path, lambda item: item.__setitem__("source_manifest_sha256", "wrong"))
            plan = json.loads(raws["measurements/plan.json"])
            plan["images"][host]["candidate"]["build_receipt_sha256"] = digest(raws[path])
            raws["measurements/plan.json"] = encoded(plan)
            self.reject(raws)

    def test_order_individual_receipts_image_hash_arguments_and_stderr_are_bound(self):
        self.reject(self.changed("measurements/runs.json", lambda runs: runs.reverse()))
        for key, value in (("binary_sha256", "wrong"), ("command", ["wrong"]), ("series", False),
                           ("raw", "../escape"), ("started_utc", "2026-11-15T00:00:00+00:00")):
            raws = self.changed("measurements/runs.json", lambda runs: runs[0].__setitem__(key, value))
            runs = json.loads(raws["measurements/runs.json"])
            raws["measurements/windows-0-baseline.receipt.json"] = encoded(runs[0])
            self.reject(raws)
        raws = dict(self.good)
        raws["measurements/windows-0-baseline.stderr"] = b"changed"
        self.reject(raws)
        self.reject(self.changed("measurements/windows-0-baseline.receipt.json", lambda row: row.__setitem__("exit_code", 1)))

    def test_observation_bool_duplicates_missing_and_nonpositive_are_rejected(self):
        path = "measurements/windows-0-baseline.jsonl"
        for key, value in (("series", False), ("iteration", False), ("nanoseconds", 0), ("nanoseconds", True),
                           ("operation", "unknown")):
            raws = dict(self.good)
            rows = [json.loads(line) for line in raws[path].splitlines()]
            rows[0][key] = value
            raws[path] = b"".join(encoded(row) for row in rows)
            runs = json.loads(raws["measurements/runs.json"])
            runs[0]["raw_sha256"] = digest(raws[path])
            raws["measurements/runs.json"] = encoded(runs)
            raws["measurements/windows-0-baseline.receipt.json"] = encoded(runs[0])
            self.reject(raws)

    def test_memory_bytes_probe_receipts_summary_and_validation_adapter_are_bound(self):
        for name in ("measurements/baseline-memory/windows/memory.jsonl", "measurements/baseline-memory/linux/memory.stderr",
                     "measurements/baseline-memory/windows/probe.exe", "validation/windows/memory.stdout",
                     "validation/linux/memory.stderr", "windows/bin/probe.exe"):
            raws = dict(self.good)
            raws[name] += b"mutation"
            self.reject(raws)
        self.reject(self.changed("qualification-adapter/validate-001/after.json", lambda item: item.__setitem__("status", "FAIL")))

    def test_memory_source_link_rejects_self_consistent_inventory_mutant(self):
        path = "measurements/baseline-memory/windows/build.json"
        raws = self.changed(path, lambda item: item.__setitem__("source_manifest_sha256", "wrong"))
        origin = json.loads(raws["measurements/reference-origin.json"])
        origin["baseline_memory_inventory"]["windows/build.json"] = digest(raws[path])
        raws["measurements/reference-origin.json"] = encoded(origin)
        plan = json.loads(raws["measurements/plan.json"])
        plan["reference_origin_sha256"] = digest(raws["measurements/reference-origin.json"])
        raws["measurements/plan.json"] = encoded(plan)
        self.reject(raws)

    def test_paths_and_archive_traversal_are_rejected(self):
        for path in ("../escape", "/absolute", "windows\\alias", "a//b", "a/../b", "C:escape"):
            raws = dict(self.good)
            raws[path] = b"bad"
            self.reject(raws)

    def test_filesystem_reader_matches_byte_reader(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, raw in self.good.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            self.assertEqual(model.evaluate(root), model.evaluate_raws(self.good))

    def test_real_budget_failure_is_reported_without_relabeling_as_corrupt_data(self):
        raws = dict(self.good)
        runs = json.loads(raws["measurements/runs.json"])
        for run in runs:
            if run["label"] != "candidate":
                continue
            path = "measurements/"+run["raw"]
            rows = [json.loads(line) for line in raws[path].splitlines()]
            for row in rows:
                row["nanoseconds"] = 110
            raws[path] = b"".join(encoded(row) for row in rows)
            run["raw_sha256"] = digest(raws[path])
            stem = run["raw"].removesuffix(".jsonl")
            raws["measurements/"+stem+".receipt.json"] = encoded(run)
        raws["measurements/runs.json"] = encoded(runs)
        report = model.evaluate_raws(raws)
        self.assertFalse(report["all_budgets_passed"])
        self.assertFalse(report["hosts"]["windows"]["minimum_gain_passed"])
        self.assertFalse(report["hosts"]["linux"]["latency"]["keygen"]["passed"])


if __name__ == "__main__":
    unittest.main()
