"""Small offline M08 verifier mutations; no engine or campaign execution."""
from contextlib import redirect_stdout
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_m08_measurements as v
from test_m08 import panel


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class M08VerifierTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parents[1] / "target"
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="m08-verifier-test-", dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.assertEqual(self.root.resolve().parent, parent.resolve())

    def latency_fixture(self, kind="latency"):
        folder = self.root / kind
        folder.mkdir()
        ops = v.CORE_OPERATIONS if kind == "latency" else v.IMPORT_OPERATIONS
        builds = {label: {"windows": {kind: {"path": f"{label}/windows/bin/{kind}.exe", "sha256": label * 8}}}
                  for label in v.LABELS}
        instant = datetime(2026, 11, 11, tzinfo=timezone.utc)
        built = {label: {"windows": instant} for label in v.LABELS}
        rows, schedule = [], []
        for number in range(2):
            for label in (v.LABELS if number == 0 else v.LABELS[::-1]):
                instant += timedelta(seconds=1)
                stream = []
                for index, op in enumerate(ops):
                    for iteration in range(2):
                        row = dict(operation=op, series=number, iteration=iteration, nanoseconds=100 + index + iteration)
                        if kind == "consumer":
                            status = [0, 2, 2, 0, 2, 2, 2, 3, 2, 2, 2][index]
                            row.update(schema=1, profile=v.PROFILE, status=status, expected_status=status,
                                       validation_and_drop_outside_timer=True, secrets_printed=False)
                        stream.append(row)
                stream[-1]["nanoseconds"] = 999999
                raw = b"".join((json.dumps(row) + "\n").encode() for row in stream)
                (folder / f"{label}-{number}.stdout.gz").write_bytes(gzip.compress(raw))
                (folder / f"{label}-{number}.stderr").write_bytes(b"")
                args = [number, 2, 1] if kind == "latency" else ["latency", number, 2, 1]
                command = ["C:/fixture/artifacts/generated/m08-001/" + builds[label]["windows"][kind]["path"], *map(str, args)]
                item = dict(version=label, series=number, command=command, started_utc=instant.isoformat(),
                    finished_utc=(instant + timedelta(milliseconds=20)).isoformat(), exit_code=0,
                    stdout_sha256=digest(raw), stderr_sha256=digest(b""))
                attempt = dict(item, binary_sha256=builds[label]["windows"][kind]["sha256"], controller_sha256="controller")
                attempt["finished_utc"] = (instant + timedelta(milliseconds=10)).isoformat()
                save(folder / f"{label}-{number}.attempt.json", attempt)
                schedule.append(item)
                rows.extend(dict(version=label, **row) for row in stream)
        save(folder / "schedule.json", dict(samples=2, warmup=1, series=2, CPU=10, operations=list(ops),
             frequency_fixed=False, host_wide_isolation_proved=False, drop_and_validation_outside_timing=True, schedule=schedule))
        save(folder / "statistics.json", v.summarize(rows, ops, v.LABELS, 2, 2))
        (folder / "observations.jsonl.gz").write_bytes(gzip.compress(b"".join((json.dumps(row) + "\n").encode() for row in rows)))
        return folder, builds, built

    def check_latency(self, fixture, kind="latency"):
        folder, builds, built = fixture
        return v.check_latency(folder, builds, built, "windows", kind, "controller", 2, 1, 2, 10)

    def test_stdout_reconstruction_preserves_all_extremes_for_both_panels(self):
        for kind in ("latency", "consumer"):
            result = self.check_latency(self.latency_fixture(kind), kind)
            op = (v.CORE_OPERATIONS if kind == "latency" else v.IMPORT_OPERATIONS)[-1]
            self.assertEqual(result["candidate/" + op]["maximum_ns"], 999999)
            self.assertTrue(all(r["observations_excluded"] == 0 for r in result.values()))

    def test_enriched_panel_cannot_omit_a_raw_extreme(self):
        fixture = self.latency_fixture()
        path = fixture[0] / "observations.jsonl.gz"
        rows = v.parsed(gzip.decompress(path.read_bytes()))
        path.write_bytes(gzip.compress(b"".join((json.dumps(row) + "\n").encode() for row in rows[:-1])))
        with self.assertRaisesRegex(v.InvalidData, "enriched observations"):
            self.check_latency(fixture)

    def test_statistics_cannot_claim_a_different_median(self):
        fixture = self.latency_fixture()
        path = fixture[0] / "statistics.json"
        stats = v.read(path)
        stats["baseline/keygen"]["median_ns"] += 1
        save(path, stats)
        with self.assertRaisesRegex(v.InvalidData, "saved summary differs"):
            self.check_latency(fixture)

    def test_abba_order_and_cpu_are_required(self):
        fixture = self.latency_fixture()
        path = fixture[0] / "schedule.json"
        original = v.read(path)
        changed = deepcopy(original)
        changed["schedule"][0], changed["schedule"][1] = changed["schedule"][1], changed["schedule"][0]
        save(path, changed)
        with self.assertRaisesRegex(v.InvalidData, "AB/BA"):
            self.check_latency(fixture)
        changed = deepcopy(original)
        changed["CPU"] = 9
        save(path, changed)
        with self.assertRaisesRegex(v.InvalidData, "panel scope"):
            self.check_latency(fixture)

    def test_attempt_controller_executable_exit_and_times_are_bound(self):
        fixture = self.latency_fixture()
        path = fixture[0] / "baseline-0.attempt.json"
        original = v.read(path)
        for key, value in (("controller_sha256", "wrong"), ("binary_sha256", "wrong"),
                           ("exit_code", 1), ("finished_utc", "2025-01-01T00:00:00+00:00")):
            changed = dict(original, **{key: value})
            save(path, changed)
            with self.subTest(key=key), self.assertRaises(v.InvalidData):
                self.check_latency(fixture)
        save(path, original)
        (fixture[0] / "extra.attempt.json").write_text("{}")
        with self.assertRaisesRegex(v.InvalidData, "file inventory"):
            self.check_latency(fixture)

    def test_import_status_and_flags_are_checked_after_rebinding_raw_hashes(self):
        fixture = self.latency_fixture("consumer")
        folder = fixture[0]
        original = v.parsed(gzip.decompress((folder / "baseline-0.stdout.gz").read_bytes()))
        schedule = v.read(folder / "schedule.json")
        attempt = v.read(folder / "baseline-0.attempt.json")
        for key, value in (("status", False), ("expected_status", False), ("schema", True),
                           ("profile", "wrong"), ("validation_and_drop_outside_timer", False), ("secrets_printed", True)):
            changed = deepcopy(original)
            changed[0][key] = value
            raw = b"".join((json.dumps(row) + "\n").encode() for row in changed)
            (folder / "baseline-0.stdout.gz").write_bytes(gzip.compress(raw))
            schedule["schedule"][0]["stdout_sha256"] = attempt["stdout_sha256"] = digest(raw)
            save(folder / "schedule.json", schedule)
            save(folder / "baseline-0.attempt.json", attempt)
            with self.subTest(key=key), self.assertRaisesRegex(v.InvalidData, "import status/profile"):
                self.check_latency(fixture, "consumer")

    def test_source_matching_rejects_any_other_compiled_change(self):
        baseline = {name: digest(name.encode()) for name in v.SOURCE_NAMES}
        baseline.update(v.CORE)
        baseline["crates/kem1536/src/secret_box.rs"] = "08d6ba7accadb46dc66b780a396dc418950641b29a91d365e12537001c40d28e"
        candidate = dict(baseline)
        candidate["crates/kem1536/src/dev_kem.rs"] = "1" * 64
        candidate["research/run_m08.py"] = "2" * 64
        manifests = dict(baseline={}, candidate=dict(measurement_control_change=v.CONTROL_CHANGE))
        v.matched_sources(dict(baseline=baseline, candidate=candidate), manifests)
        for name in ("research/m08-import-consumer/src/main.rs", "research/m08-memory-probe/src/main.rs", "Cargo.lock"):
            wrong = dict(candidate, **{name: "3" * 64})
            with self.subTest(name=name), self.assertRaisesRegex(v.InvalidData, "matched compiled"):
                v.matched_sources(dict(baseline=baseline, candidate=wrong), manifests)
        with self.assertRaisesRegex(v.InvalidData, "source surface"):
            v.matched_sources(dict(baseline=baseline, candidate={k: h for k, h in candidate.items() if k != "Cargo.lock"}), manifests)

    def test_strict_acceptance_and_nested_flags_do_not_accept_bool_integer_alias(self):
        accepted = deepcopy(v.EXPECTED_ACCEPTANCE)
        v.exact_fields(accepted, v.EXPECTED_ACCEPTANCE, "fixture")
        accepted["heap_request_increase_allowed"] = 0
        with self.assertRaises(v.InvalidData):
            v.exact_fields(accepted, v.EXPECTED_ACCEPTANCE, "fixture")
        with self.assertRaises(v.InvalidData):
            v.exact_fields(dict(fixture=dict(secrets_printed=0)), dict(fixture=dict(secrets_printed=False)), "fixture")

    def test_recipe_rejects_research_features_in_the_default_consumer(self):
        command = ["C:/fixture/.tools/cargo/bin/cargo.exe", "build", "--release", "--locked", "--offline", "--manifest-path",
                   "C:/fixture/artifacts/generated/m08-001/baseline-source/research/m08-import-consumer/Cargo.toml"]
        v.recipe(command, "baseline", "windows", "consumer")
        with self.assertRaisesRegex(v.InvalidData, "selection/features"):
            v.recipe(command + ["--features", "research-vectors"], "baseline", "windows", "consumer")
        with self.assertRaisesRegex(v.InvalidData, "selection/features"):
            v.recipe([x for x in command if x != "--locked"], "baseline", "windows", "consumer")

    def test_memory_raw_receipt_and_summary_are_both_required(self):
        folder = self.root / "baseline/windows"
        folder.mkdir(parents=True)
        rows = panel()
        raw = b"".join((json.dumps(row) + "\n").encode() for row in rows)
        (folder / "memory.jsonl").write_bytes(raw)
        (folder / "memory.stderr").write_bytes(b"")
        binary = dict(path="baseline/windows/bin/probe.exe", sha256="expected")
        receipt = dict(exit_code=0, binary_sha256="expected", raw_sha256=digest(raw), stderr_sha256=digest(b""),
             executed_utc="2026-11-11T01:00:01+00:00", command=["C:/fixture/" + binary["path"], "1"])
        save(folder / "memory-run.json", receipt)
        summary = v.validate_memory(rows, 1)
        save(folder / "memory-summary.json", summary)
        built = datetime(2026, 11, 11, 1, tzinfo=timezone.utc)
        self.assertEqual(v.check_memory(self.root, "baseline", "windows", binary, built, 1)[0], summary)
        summary["keygen"]["count"] -= 1
        save(folder / "memory-summary.json", summary)
        with self.assertRaisesRegex(v.InvalidData, "saved summary"):
            v.check_memory(self.root, "baseline", "windows", binary, built, 1)

    def test_latency_missed_budget_is_a_valid_negative_comparison(self):
        stats = {host: {label + "/keygen": dict(median_ns=(111 if label == "candidate" else 100), p95_ns=100)
                       for label in v.LABELS} for host in v.HOSTS}
        checks = v.compare_latency(stats, ("keygen",), v.EXPECTED_ACCEPTANCE, "core")
        self.assertEqual(len(checks), 4)
        self.assertEqual(sum(not row["pass"] for row in checks), 2)

    def test_cli_separates_invalid_data_and_valid_missed_budget(self):
        with patch.object(v.sys, "argv", ["verify_m08_measurements.py", "verify", "--output", str(self.root)]), \
             patch.object(v, "analyze", return_value=dict(data_valid=True, candidate_within_budgets=False)), redirect_stdout(io.StringIO()):
            self.assertEqual(v.main(), 2)
        with patch.object(v.sys, "argv", ["verify_m08_measurements.py", "analyze", "--output", str(self.root)]), \
             patch.object(v, "analyze", side_effect=v.InvalidData("fixture data error")), redirect_stdout(io.StringIO()):
            self.assertEqual(v.main(), 1)

    def test_exact_wsl_launcher_warning_is_retained_but_panic_is_not_whitelisted(self):
        warning = b"wsl: Failed to start the systemd user session for 'majid'. See journalctl for more details.\n"
        v.runtime_stderr(b"", "windows")
        v.runtime_stderr(warning, "linux")
        for errors, host in ((warning, "windows"), (b"panic: fixture\n", "linux"), (warning + b"panic: fixture\n", "linux"),
                             (warning.replace(b"majid", b"unreviewed-user"), "linux")):
            with self.subTest(host=host, errors=errors), self.assertRaisesRegex(v.InvalidData, "unclassified"):
                v.runtime_stderr(errors, host)

    def consumer_fixture(self):
        folder = self.root / "candidate/windows/validation"
        folder.mkdir(parents=True)
        binary = dict(path="candidate/windows/bin/consumer.exe", sha256="fixture-binary")
        smoke = dict(schema=1, profile=v.PROFILE, host="windows", architecture="x86_64",
            research_vectors_feature_requested=False, fixtures=v.FIXTURE,
            fresh_imported_key_round_trips=1, fresh_rejections=1, repeat_rejection_equal=True,
            fresh_private_with_fixed_z_imported=True, fixed_z_import_is_syntax_not_entropy_validation=True,
            secrets_printed=False, cases=[dict(operation=op, status=status, expected=status)
                for op, status in zip(v.IMPORT_OPERATIONS + ("public_short", "private_short"),
                                      (0, 2, 2, 0, 2, 2, 2, 3, 2, 2, 2, 1, 1))])
        exhaustive = dict(schema=1, profile=v.PROFILE, mode="exhaustive single-coefficient probes", fixture=v.FIXTURE,
            single_coefficient_value_alignment_cases=65536, boundary_position_cases=23040, total_cases=88576,
            complete_vector_space_exhausted=False, all_expected_statuses_and_accepted_encodings_match=True,
            formal_program_verification=False, secrets_printed=False)
        for mode, data in (("smoke", smoke), ("fixture-digests", v.FIXTURE), ("exhaustive", exhaustive)):
            raw = json.dumps(data).encode()
            (folder / (mode + ".stdout")).write_bytes(raw)
            (folder / (mode + ".stderr")).write_bytes(b"")
            save(folder / (mode + ".json"), dict(command=["C:/fixture/" + binary["path"], mode],
                exit_code=0, binary_sha256=binary["sha256"], stdout_sha256=digest(raw), stderr_sha256=digest(b""),
                executed_utc="2026-11-11T00:00:01+00:00", data=data))
        return folder, binary, datetime(2026, 11, 11, tzinfo=timezone.utc)

    def test_consumer_counts_and_statuses_cannot_be_resealed_as_success(self):
        folder, binary, built = self.consumer_fixture()
        self.assertEqual(v.check_consumer(self.root, "candidate", "windows", binary, built)["exhaustive_cases"], 88576)
        receipt = v.read(folder / "exhaustive.json")
        receipt["data"]["total_cases"] = 88575
        raw = json.dumps(receipt["data"]).encode()
        receipt["stdout_sha256"] = digest(raw)
        (folder / "exhaustive.stdout").write_bytes(raw)
        save(folder / "exhaustive.json", receipt)
        with self.assertRaisesRegex(v.InvalidData, "exhaustive coverage/status"):
            v.check_consumer(self.root, "candidate", "windows", binary, built)

    def test_consumer_fixture_digest_and_entropy_flag_are_bound(self):
        folder, binary, built = self.consumer_fixture()
        receipt = v.read(folder / "smoke.json")
        for field, value in (("fixtures", dict(v.FIXTURE, public_sha3_256="0" * 64)),
                             ("fixed_z_import_is_syntax_not_entropy_validation", False)):
            changed = deepcopy(receipt)
            changed["data"][field] = value
            raw = json.dumps(changed["data"]).encode()
            changed["stdout_sha256"] = digest(raw)
            (folder / "smoke.stdout").write_bytes(raw)
            save(folder / "smoke.json", changed)
            with self.subTest(field=field), self.assertRaisesRegex(v.InvalidData, "consumer smoke scope"):
                v.check_consumer(self.root, "candidate", "windows", binary, built)

    def test_linux_build_recipe_has_exact_clean_environment_and_isolated_target(self):
        prefix = ["wsl", "-d", "Ubuntu-22.04", "--", "env", "-i",
            "CARGO_HOME=/fixture/.tools/linux-cargo", "RUSTUP_HOME=/fixture/.tools/linux-rustup",
            "RUSTUP_TOOLCHAIN=1.91.1-x86_64-unknown-linux-gnu", "RUSTUP_AUTO_INSTALL=0", "CARGO_BUILD_JOBS=2",
            "CARGO_TARGET_DIR=/fixture/target/m08-001/baseline/linux",
            "PATH=/fixture/.tools/linux-cargo/bin:/usr/local/bin:/usr/bin:/bin"]
        tail = ["/fixture/.tools/linux-cargo/bin/cargo", "build", "--release", "--locked", "--offline", "-p", "kem1536-cli", "--bin", "kem1536"]
        v.recipe(prefix + tail, "baseline", "linux", "delivered")
        wrong = [x.replace("/baseline/linux", "/candidate/linux") for x in prefix] + tail
        with self.assertRaisesRegex(v.InvalidData, "environment/target"):
            v.recipe(wrong, "baseline", "linux", "delivered")
        with self.assertRaisesRegex(v.InvalidData, "environment/target"):
            v.recipe(prefix + ["RUSTFLAGS=-Ctarget-cpu=native"] + tail, "baseline", "linux", "delivered")


if __name__ == "__main__":
    unittest.main()
