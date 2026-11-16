"""Pure synthetic publication guards; no Git, credentials, network or native runs."""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import zipfile

import capture_m08_ci_receipt as capture
import freeze_m08_publication as freeze


class PublicationGuards(unittest.TestCase):
    def setUp(self):
        parent = freeze.ROOT / "target/m08-publication-helper-tests"
        if not parent.resolve().is_relative_to(freeze.ROOT.resolve()):
            raise ValueError("publication fixture escapes NIST")
        parent.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="guards-", dir=parent)
        self.root = Path(self.temporary.name).resolve()
        if self.root.parent != parent.resolve():
            raise ValueError("publication fixture escapes owned parent")
        self.addCleanup(self.temporary.cleanup)
        self.source = self.root / "capture"
        self.source.mkdir()
        self.config = {"schema": "m08-publication-config-v1", "run_id": 17, "public_commit": "a" * 40,
                       "source_commit": "b" * 40, "branch": "main", "python_test_count": 345,
                       "candidate_source_manifest_sha256": "c" * 64,
                       "runners": {runner: {"host": host, "original_CLI_sha256": str(i + 1) * 64,
                                            "original_default_consumer_sha256": str(i + 3) * 64}
                                   for i, (runner, (host, _)) in enumerate(freeze.RUNNERS.items())}}
        self.run = {"id": 17, "head_sha": "a" * 40, "head_branch": "main", "status": "completed", "conclusion": "success",
                    "run_attempt": 1, "html_url": "https://github.com/" + freeze.REPOSITORY + "/actions/runs/17",
                    "repository": {"full_name": freeze.REPOSITORY}}
        self.jobs = {"total_count": 2, "jobs": []}
        for i, (runner, (_, label)) in enumerate(freeze.RUNNERS.items()):
            self.jobs["jobs"].append({"id": i + 101, "run_id": 17, "head_sha": "a" * 40, "run_attempt": 1,
                "name": "check (" + runner + ")", "labels": [runner], "status": "completed", "conclusion": "success",
                "steps": [{"name": name, "status": "completed", "conclusion": "success"} for name in (
                    "Bootstrap " + label, "Prepare " + label + " research tools", "Check " + label,
                    "Run the original M08 package and import consumer on " + label)]})
        self.manifest = {"schema": 2, "profile": freeze.PROFILE, "local_source_commit": "b" * 40,
                         "sha256": {"README.md": "1" * 64, "scripts/dev.ps1": "2" * 64},
                         "git_blob_sha256": {"README.md": "1" * 64, "scripts/dev.ps1": "3" * 64}}
        self.raw = json.dumps(self.manifest, indent=2).encode()
        self.integrity = {"schema": "m08-source-integrity-v1", "public_commit": "a" * 40, "source_commit": "b" * 40,
                          "canonical_git_blobs_verified": 2, "exported_files_verified": 2, "all_equal": True,
                          "source_provenance_sha256": hashlib.sha256(self.raw).hexdigest(),
                          "git_blob_map_sha256": freeze.canonical_sha(self.manifest["git_blob_sha256"]),
                          "export_map_sha256": freeze.canonical_sha(self.manifest["sha256"]),
                          "attribute_converted_paths": ["scripts/dev.ps1"]}
        self.logs()
        self.capture_files()

    def smoke(self, runner):
        wanted = self.config["runners"][runner]
        value = {"schema": "m08-native-smoke-v1", "profile": freeze.PROFILE, "host": wanted["host"],
                 "candidate_source_manifest_sha256": self.config["candidate_source_manifest_sha256"],
                 "original_CLI_sha256": wanted["original_CLI_sha256"],
                 "original_default_consumer_sha256": wanted["original_default_consumer_sha256"],
                 "started_utc": "2026-11-11T01:00:00+00:00", "finished_utc": "2026-11-11T01:00:01+00:00",
                 "CLI_fresh_round_trips": 16, "CLI_implicit_rejections_checked": 16, "consumer_import_cases": 13,
                 "consumer_fresh_imported_key_round_trips": 1, "consumer_fresh_rejections": 1,
                 "consumer_single_coefficient_and_boundary_probes": 88576,
                 "checks": [{"operation": name, "exit_code": 0, "stdout_sha256": "4" * 64, "stderr_sha256": freeze.EMPTY_SHA}
                            for name in ("dev-self-test", "smoke", "exhaustive")],
                 "research_commands_rejected": [{"arguments": args, "exit_code": 1, "stdout_sha256": freeze.EMPTY_SHA,
                                                  "stderr_sha256": "5" * 64} for args in freeze.RESEARCH_COMMANDS]}
        value.update({name: False for name in ("new_compilation_performed", "new_benchmark_performed", "new_disassembly_performed",
                                               "constant_time_proved", "universal_erasure_proved", "secrets_printed")})
        return value

    def logs(self, count=345, ok=True, extra=False):
        with zipfile.ZipFile(self.source / "ci-logs.zip", "w") as archive:
            for i, runner in enumerate(freeze.RUNNERS):
                text = f"Ran {count} tests in 1.234s\n\n" + ("OK\n" if ok else "FAILED (errors=1)\n")
                text += json.dumps(self.smoke(runner), indent=2) + "\n"
                text = "\n".join("2026-11-11T01:00:00.0000000Z " + line for line in text.splitlines()) + "\n"
                archive.writestr(str(i) + "_check (" + runner + ").txt", text)
            if extra:
                archive.writestr("99_check (windows-latest).txt", text)

    def capture_files(self):
        for name, value in (("run.json", self.run), ("jobs.json", self.jobs)):
            (self.source / name).write_text(json.dumps(value), encoding="utf-8")
        receipt = {"schema": "m08-ci-capture-v1", "run_id": 17, "public_commit": "a" * 40, "run_url": self.run["html_url"],
                   "credentials_retained": False, "signed_log_storage_URL_retained": False,
                   "sha256": {name: freeze.sha(self.source / name) for name in ("run.json", "jobs.json", "ci-logs.zip")}}
        (self.source / "receipt.json").write_text(json.dumps(receipt), encoding="utf-8")

    def test_explicit_future_identities_counts_and_hashes_are_required(self):
        freeze.config_check(self.config)
        for field in ("run_id", "public_commit", "source_commit", "python_test_count", "candidate_source_manifest_sha256"):
            changed = deepcopy(self.config);changed.pop(field)
            with self.subTest(field=field), self.assertRaises(ValueError):
                freeze.config_check(changed)

    def test_api_run_and_two_distinct_runner_jobs_bind_the_exact_commit(self):
        freeze.check_run(self.run, self.jobs, 17, "a" * 40)
        changed = deepcopy(self.jobs);changed["jobs"][1]["id"] = changed["jobs"][0]["id"]
        with self.assertRaisesRegex(ValueError, "job ID"):
            freeze.check_run(self.run, changed, 17, "a" * 40)
        for field, value in (("head_sha", "f" * 40), ("labels", ["windows-latest"]), ("run_attempt", 2)):
            changed = deepcopy(self.jobs);changed["jobs"][1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                freeze.check_run(self.run, changed, 17, "a" * 40)

    def test_consumer_hash_count_and_research_crash_are_not_accepted(self):
        good = self.smoke("windows-latest")
        freeze.check_smoke(good, "windows-latest", self.config)
        for field, value in (("original_default_consumer_sha256", "0" * 64),
                             ("consumer_single_coefficient_and_boundary_probes", 88575), ("constant_time_proved", True)):
            changed = deepcopy(good);changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                freeze.check_smoke(changed, "windows-latest", self.config)
        changed = deepcopy(good);changed["research_commands_rejected"][0]["exit_code"] = -11
        with self.assertRaisesRegex(ValueError, "exit1"):
            freeze.check_smoke(changed, "windows-latest", self.config)

    def test_missing_run_and_job_attempts_cannot_match_as_None(self):
        run, jobs = deepcopy(self.run), deepcopy(self.jobs)
        run.pop("run_attempt")
        for job in jobs["jobs"]:
            job.pop("run_attempt")
        with self.assertRaisesRegex(ValueError, "attempt"):
            freeze.check_run(run, jobs, 17, "a" * 40)

    def test_full_job_count_following_OK_and_unique_logs_are_required(self):
        jobs = freeze.check_run(self.run, self.jobs, 17, "a" * 40)
        self.assertEqual(set(freeze.log_summary(self.source / "ci-logs.zip", self.config, jobs)), set(freeze.RUNNERS))
        for kwargs in ({"count": 344}, {"ok": False}, {"extra": True}):
            self.logs(**kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                freeze.log_summary(self.source / "ci-logs.zip", self.config, jobs)

    def test_required_M08_native_API_step_must_have_passed(self):
        changed = deepcopy(self.jobs)
        changed["jobs"][0]["steps"][-1]["conclusion"] = "skipped"
        jobs = freeze.check_run(self.run, changed, 17, "a" * 40)
        with self.assertRaisesRegex(ValueError, "M08 native"):
            freeze.log_summary(self.source / "ci-logs.zip", self.config, jobs)

    def test_integrity_binds_both_committed_schema2_maps_without_fixed_size(self):
        freeze.check_integrity(self.integrity, self.manifest, self.raw, self.config)
        for field, value in (("source_commit", "f" * 40), ("git_blob_map_sha256", "0" * 64),
                             ("canonical_git_blobs_verified", 1932)):
            changed = dict(self.integrity, **{field: value})
            with self.subTest(field=field), self.assertRaises(ValueError):
                freeze.check_integrity(changed, self.manifest, self.raw, self.config)

    def test_three_captured_member_hashes_and_exact_inventory_are_required(self):
        result = freeze.evidence(self.source, self.config, self.integrity, self.raw)
        self.assertEqual(result["run_id"], 17)
        path = self.source / "ci-logs.zip";path.write_bytes(path.read_bytes() + b"tampered")
        with self.assertRaisesRegex(ValueError, "captured API/log"):
            freeze.evidence(self.source, self.config, self.integrity, self.raw)

    def test_storage_redirect_never_receives_authorization(self):
        signed = "https://synthetic-storage.invalid/logs?signature=do-not-log"
        error = urllib.error.HTTPError("https://api.github.com/synthetic", 302, "Found", {"Location": signed}, None)
        opener = unittest.mock.Mock();opener.open.side_effect = error
        with patch.object(capture.urllib.request, "build_opener", return_value=opener), \
             patch.object(capture.urllib.request, "urlopen", return_value=io.BytesIO(b"synthetic zip bytes")) as storage:
            capture.download_logs(17, {"Authorization": "Bearer synthetic-token"}, self.root / "download.zip")
        request = storage.call_args.args[0]
        self.assertIsNone(request.get_header("Authorization"))
        self.assertEqual(request.full_url, signed)
        self.assertEqual((self.root / "download.zip").read_bytes(), b"synthetic zip bytes")

    def test_storage_error_suppresses_private_URL_details(self):
        opener = unittest.mock.Mock();opener.open.side_effect = urllib.error.URLError("synthetic-private-url?signature=secret")
        with patch.object(capture.urllib.request, "build_opener", return_value=opener):
            with self.assertRaises(ValueError) as caught:
                capture.download_logs(17, {}, self.root / "failure.zip")
        self.assertNotIn("signature", str(caught.exception))
        self.assertNotIn("synthetic-private-url", str(caught.exception))

    def test_frozen_verifier_replays_data_without_Git_network_or_native_calls(self):
        snapshot = self.root / "frozen";snapshot.mkdir()
        (snapshot / "main").mkdir()
        for path in self.source.iterdir():
            (snapshot / "main" / path.name).write_bytes(path.read_bytes())
        for name, value in (("config.json", self.config), ("source-integrity.json", self.integrity),
                            ("verification.json", freeze.evidence(self.source, self.config, self.integrity, self.raw))):
            freeze.save(snapshot / name, value)
        (snapshot / "tested-source-provenance.json").write_bytes(self.raw)
        (snapshot / "README.md").write_text("synthetic evidence only\n")
        files = {p.relative_to(snapshot).as_posix(): freeze.sha(p) for p in snapshot.rglob("*") if p.is_file()}
        freeze.save(snapshot / "provenance.json", {"schema": "m08-publication-receipt-v1", "created_utc": "2026-11-11T02:00:00+00:00",
                    "public_tested_commit": "a" * 40, "source_commit": "b" * 40, "output_sha256": files})
        with patch.object(freeze.subprocess, "check_output", side_effect=AssertionError("Git prohibited")), \
             patch.object(capture, "authentication", side_effect=AssertionError("credentials prohibited")), \
             patch.object(capture.urllib.request, "urlopen", side_effect=AssertionError("network prohibited")):
            result = freeze.verify(snapshot)
        self.assertEqual(result["run_id"], 17)
        self.assertFalse(result["new_network_or_native_execution_performed"])


if __name__ == "__main__":
    unittest.main()
