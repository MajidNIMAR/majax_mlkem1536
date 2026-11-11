"""Pure M08 archive/shard/chronology guards; no builds or executable calls."""
from copy import deepcopy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
from types import ModuleType
import unittest
from unittest.mock import Mock, patch

import archive_m08 as a


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, bytes):
        path.write_bytes(value)
    else:
        path.write_text(json.dumps(value), encoding="utf-8")


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        parent = a.ROOT / "target/m08-archive-tests"
        a.require(parent.resolve().is_relative_to(a.ROOT.resolve()), "test temporary parent escapes NIST")
        parent.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="guards-", dir=parent)
        self.root = Path(self.temp.name)
        a.require(self.root.resolve().parent == parent.resolve(), "test temporary directory escapes owned parent")
        self.source, self.out = self.root / "source", self.root / "out"
        self.source.mkdir();self.out.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def sample(self):
        (self.source / "empty-failures").mkdir()
        write(self.source / "nested/raw.bin", bytes(range(256)) * 8)
        write(self.source / ("long-" + "é" * 55 + ".txt"), b"long UTF-8 PAX path")
        write(self.source / "zero", b"")

    def test_deterministic_roundtrip_preserves_empty_dirs_and_pax(self):
        self.sample()
        first = a.pack_stage(self.source, self.out, "toy")
        second_out = self.root / "again";second_out.mkdir()
        second = a.pack_stage(self.source, second_out, "toy")
        self.assertEqual(first, second)
        self.assertEqual({p.name: p.read_bytes() for p in self.out.iterdir()},
                         {p.name: p.read_bytes() for p in second_out.iterdir()})
        a.unpack_stage(self.out, "toy", first, self.root / "restored")
        self.assertEqual(a.inventory(self.source), a.inventory(self.root / "restored"))
        self.assertTrue((self.root / "restored/empty-failures").is_dir())

    def test_large_member_and_inventory_split_without_loss(self):
        write(self.source / "single-large.bin", os.urandom(8192))
        for i in range(80):
            write(self.source / (str(i) + ".txt"), os.urandom(16))
        record = a.pack_stage(self.source, self.out, "toy", part_limit=256)
        self.assertGreater(len(record["archive"]["parts"]), 2)
        self.assertGreater(len(record["inventory"]["stream"]["parts"]), 2)
        self.assertTrue(all(p.stat().st_size <= 256 for p in self.out.iterdir()))
        a.unpack_stage(self.out, "toy", record, self.root / "restored")
        self.assertEqual(a.inventory(self.source), a.inventory(self.root / "restored"))

    def test_25001_members_have_padding_budget_without_old_cap(self):
        value = {"directories": [], "files": {f"f{i:05d}": {"bytes": 1, "sha256": "a" * 64} for i in range(25001)}}
        a.validate_inventory(value)
        self.assertGreaterEqual(a.tar_byte_budget(value), 25001 * 2 * 512 + tarfile.RECORDSIZE)
        self.assertLess(a.tar_byte_budget(value), a.MAX_PAYLOAD_BYTES)

    def test_member_and_payload_limits_reject_instead_of_truncate(self):
        value = {"directories": [], "files": {"x": {"bytes": a.MAX_PAYLOAD_BYTES + 1, "sha256": "a" * 64}}}
        with self.assertRaisesRegex(ValueError, "payload"):
            a.validate_inventory(value)
        value["files"]["x"]["bytes"] = 0
        with patch.object(a, "MAX_MEMBERS", 0), self.assertRaisesRegex(ValueError, "member count"):
            a.validate_inventory(value)

    def test_reordered_missing_tampered_and_oversized_shards_fail(self):
        write(self.source / "raw", os.urandom(2048))
        record = a.pack_stage(self.source, self.out, "toy", part_limit=256)
        for modify in (lambda r: r["archive"]["parts"].reverse(),
                       lambda r: r["archive"]["parts"].pop(),
                       lambda r: r["archive"]["parts"][0].update(bytes=257),
                       lambda r: r["archive"].update(sha256="0" * 64)):
            changed = deepcopy(record);modify(changed)
            with self.assertRaises(ValueError):
                a.unpack_stage(self.out, "toy", changed, self.root / ("bad" + str(len(list(self.root.iterdir())))))
        first = self.out / record["archive"]["parts"][0]["name"]
        raw = first.read_bytes();first.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
        with self.assertRaises((ValueError, gzip.BadGzipFile)):
            a.unpack_stage(self.out, "toy", record, self.root / "changed")
        first.unlink()
        with self.assertRaises(FileNotFoundError):
            a.unpack_stage(self.out, "toy", record, self.root / "missing")

    def test_inventory_length_checksum_and_compressed_limit_fail(self):
        self.sample();record = a.pack_stage(self.source, self.out, "toy")
        for field, value in (("json_bytes", record["inventory"]["json_bytes"] - 1), ("json_sha256", "0" * 64)):
            changed = deepcopy(record);changed["inventory"][field] = value
            with self.assertRaises(ValueError):
                a.read_inventory(self.out, "toy", changed["inventory"])
        changed = deepcopy(record);changed["archive"]["part_limit_bytes"] = a.PART_BYTES + 1
        with self.assertRaises(ValueError):
            a.check_parts(changed["archive"], "toy.tar.gz")

    def test_path_case_parent_and_device_aliases_rejected(self):
        for name in ("../x", "/x", "C:/x", "a\\b", "nul.txt", "x/CON", "x ", "a//b", "x/../y"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                a.validate_inventory({"files": {name: {"bytes": 0, "sha256": "0" * 64}}, "directories": []})
        for files, dirs in ((["A", "a"], []), (["x/y"], []), (["x"], ["x"])):
            with self.assertRaises(ValueError):
                a.validate_inventory({"files": {name: {"bytes": 0, "sha256": "0" * 64} for name in files}, "directories": dirs})

    def crafted(self, members, inventory, padding=0):
        record = {"inventory": a.write_inventory(self.out, "crafted", inventory, a.PART_BYTES),
                  "file_count": len(inventory["files"]), "directory_count": len(inventory["directories"]),
                  "payload_bytes": sum(row["bytes"] for row in inventory["files"].values())}
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for info, data in members:
                tar.addfile(info, io.BytesIO(data) if data is not None else None)
        writer = a.ShardWriter(self.out, "crafted.tar.gz")
        writer.write(gzip.compress(raw.getvalue() + b"\0" * padding, mtime=0))
        record["archive"] = writer.finish()
        return record

    def test_tar_duplicate_unlisted_link_and_traversal_fail(self):
        value = {"files": {"raw": {"bytes": 1, "sha256": hashlib.sha256(b"x").hexdigest()}}, "directories": []}
        for mode in ("duplicate", "unlisted", "symlink", "hardlink", "traversal"):
            with self.subTest(mode=mode):
                info = tarfile.TarInfo("raw");info.size = 1
                members = [(info, b"x")]
                if mode == "duplicate":
                    members *= 2
                elif mode in {"unlisted", "traversal"}:
                    info.name = "elsewhere" if mode == "unlisted" else "../raw"
                else:
                    info.type = tarfile.SYMTYPE if mode == "symlink" else tarfile.LNKTYPE
                    info.linkname = "outside";members = [(info, None)]
                separate = self.root / mode;separate.mkdir()
                previous = self.out;self.out = separate
                record = self.crafted(members, value)
                with self.assertRaises(ValueError):
                    a.unpack_stage(self.out, "crafted", record, self.root / (mode + "-restored"))
                self.out = previous

    def test_decompression_bound_includes_tar_padding_but_rejects_bomb(self):
        value = {"files": {}, "directories": []}
        record = self.crafted([], value, padding=512)
        with self.assertRaisesRegex(ValueError, "exceeds budget"):
            a.unpack_stage(self.out, "crafted", record, self.root / "bomb")

    def test_second_tar_hidden_after_eof_is_rejected(self):
        value = {"files": {}, "directories": []}
        record = self.crafted([], value)
        path = self.out / record["archive"]["parts"][0]["name"]
        raw = bytearray(gzip.decompress(path.read_bytes()))
        raw[1024:1030] = b"hidden"
        compressed = gzip.compress(raw, mtime=0);path.write_bytes(compressed)
        checksum = hashlib.sha256(compressed).hexdigest()
        record["archive"].update(bytes=len(compressed), sha256=checksum)
        record["archive"]["parts"][0].update(bytes=len(compressed), sha256=checksum)
        with self.assertRaisesRegex(ValueError, "follows TAR EOF"):
            a.unpack_stage(self.out, "crafted", record, self.root / "hidden")

    def test_nonordinary_hardlink_is_rejected(self):
        write(self.source / "x", b"x")
        try:
            os.link(self.source / "x", self.source / "hard")
        except OSError as error:
            self.skipTest(str(error))
        with self.assertRaisesRegex(ValueError, "hard link"):
            a.inventory(self.source)

    def test_recursive_local_controls_are_closed(self):
        folder = self.root / "controls";folder.mkdir()
        (folder / "archive_m08.py").write_text("import json\nfrom child import f\n", encoding="utf-8")
        (folder / "child.py").write_text("from grandchild import g\n", encoding="utf-8")
        (folder / "grandchild.py").write_text("g=1\n", encoding="utf-8")
        (folder / "smoke_m08_package.py").write_text("import child\n", encoding="utf-8")
        for name in ("test_archive_m08.py", "test_smoke_m08_package.py", "test_resume_m08_postprocess.py"):
            (folder / name).write_text("pass\n", encoding="utf-8")
        (folder / "unrelated.py").write_text("pass\n", encoding="utf-8")
        self.assertEqual(a.control_closure(folder), ["archive_m08.py", "child.py", "grandchild.py", "smoke_m08_package.py",
                                                   "test_archive_m08.py", "test_resume_m08_postprocess.py", "test_smoke_m08_package.py"])

    def test_optional_recovery_is_replayed_and_reported_without_executing_data(self):
        stages = {name: self.root / name for name in (*a.STAGES, "controls")}
        measurements = {"data_valid": True, "candidate_within_budgets": True,
                        "budget_checks": [{"pass": True} for _ in range(210)], "runtime_stderr_diagnostics": {}}
        write(stages["measurements"] / "measurements-evaluation.json", measurements)
        final = stages["fuzz"] / "postprocessing/postprocess.json"
        write(final, {"recovery_receipt_sha256": "a" * 64})
        result = {"interrupted_oracle_attempt_preserved": True,
                  "original_campaign_or_coverage_rerun": False, "resumed_oracle_exit_code": 0}
        helper = ModuleType("resume_m08_postprocess")
        helper.verify_recovery = Mock(return_value=result)
        overrides = {"analyze_measurements": Mock(return_value=measurements),
                     **{name: Mock(return_value={}) for name in ("check_links", "verify_postprocessing", "check_timing",
                        "verify_imports", "verify_cli", "verify_delivery", "verify_diagnostic_notices", "check_controls")}}
        with patch.dict(sys.modules, {"resume_m08_postprocess": helper}), patch.multiple(a, **overrides), \
                patch("subprocess.run", side_effect=AssertionError("execution forbidden")), \
                patch("subprocess.check_output", side_effect=AssertionError("execution forbidden")):
            replayed = a.replay(stages)
            self.assertEqual(replayed["postprocessing_recovery"], result)
            helper.verify_recovery.assert_called_once_with(stages["fuzz"])
            helper.verify_recovery.reset_mock()
            write(final, {"source_coverage_exported": True})
            self.assertIsNone(a.replay(stages)["postprocessing_recovery"])
            helper.verify_recovery.assert_not_called()

    def test_recovery_rejection_and_incorrect_scope_stop_archive_replay(self):
        campaign = self.root / "campaign"
        write(campaign / "postprocessing/postprocess.json", {"recovery_receipt_sha256": "a" * 64})
        helper = ModuleType("resume_m08_postprocess")
        helper.verify_recovery = Mock(side_effect=ValueError("preserved interruption changed"))
        with patch.dict(sys.modules, {"resume_m08_postprocess": helper}):
            with self.assertRaisesRegex(ValueError, "interruption changed"):
                a.postprocessing_recovery(campaign)
            helper.verify_recovery.side_effect = None
            for changed in ({"interrupted_oracle_attempt_preserved": False,
                             "original_campaign_or_coverage_rerun": False, "resumed_oracle_exit_code": 0},
                            {"interrupted_oracle_attempt_preserved": True,
                             "original_campaign_or_coverage_rerun": True, "resumed_oracle_exit_code": 0},
                            {"interrupted_oracle_attempt_preserved": True,
                             "original_campaign_or_coverage_rerun": False, "resumed_oracle_exit_code": -1},
                            {"interrupted_oracle_attempt_preserved": True,
                             "original_campaign_or_coverage_rerun": False, "resumed_oracle_exit_code": False}):
                helper.verify_recovery.return_value = changed
                with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, "recovery result/scope"):
                    a.postprocessing_recovery(campaign)

    def test_recovery_evidence_without_final_marker_is_not_silently_ignored(self):
        campaign = self.root / "campaign"
        folder = campaign / "postprocessing"
        write(folder / "postprocess.json", {"source_coverage_exported": True})
        helper = ModuleType("resume_m08_postprocess")
        helper.verify_recovery = Mock(side_effect=AssertionError("unmarked recovery must reject before verifier"))
        with patch.dict(sys.modules, {"resume_m08_postprocess": helper}):
            self.assertIsNone(a.postprocessing_recovery(campaign))
            for name in ("recovery-request.json", "recovery.json", "recovery-adapter.py", "interrupted-oracle-001"):
                path = folder / name
                if name == "interrupted-oracle-001":
                    path.mkdir()
                else:
                    write(path, {"preserved": True})
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, "recovery evidence lacks"):
                    a.postprocessing_recovery(campaign)
                path.rmdir() if path.is_dir() else path.unlink()
            helper.verify_recovery.assert_not_called()

    def selected_fixture(self):
        self.sample()
        controls = self.root / "controls";controls.mkdir()
        for name in a.CONTROL_ROOTS:
            (controls / name).write_text("# frozen pure toy control\n", encoding="utf-8")
        records = {name: a.pack_stage(self.source, self.out, name) for name in a.STAGES}
        records["controls"] = a.pack_stage(controls, self.out, "controls")
        write(self.out / "summary.json", {"toy": True});(self.out / "README.md").write_text("toy", encoding="utf-8")
        provenance = {"schema": "m08-sharded-evidence-v1", "profile": a.PROFILE,
                      "created_utc": "2026-11-11T00:00:00+00:00", "stages": records,
                      "sidecar_sha256": {name: a.sha(self.out / name) for name in ("summary.json", "README.md")}}
        write(self.out / "provenance.json", provenance)
        return provenance

    def test_selected_stage_extracts_only_it_and_exact_controls_without_execution(self):
        self.selected_fixture()
        with patch.object(a, "unpack_stage", wraps=a.unpack_stage) as unpack, \
                patch("subprocess.run", side_effect=AssertionError("execution forbidden")), \
                patch("subprocess.check_output", side_effect=AssertionError("execution forbidden")):
            with a.extracted_stage(self.out, "imports") as stage:
                self.assertEqual(stage.name, "imports")
                self.assertTrue(stage.resolve().is_relative_to((a.ROOT / "target/m08-archive-temp").resolve()))
                self.assertEqual(a.inventory(stage), a.inventory(self.source))
            self.assertEqual([call.args[1] for call in unpack.call_args_list], ["controls", "imports"])

    def test_top_inventory_and_selected_control_tampering_fail(self):
        provenance = self.selected_fixture()
        write(self.out / "extra.txt", b"extra")
        with self.assertRaisesRegex(ValueError, "file inventory"):
            a.snapshot_provenance(self.out)
        (self.out / "extra.txt").unlink()
        shard = self.out / provenance["stages"]["controls"]["archive"]["parts"][0]["name"]
        raw = shard.read_bytes();shard.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
        with self.assertRaises((ValueError, gzip.BadGzipFile)):
            with a.extracted_stage(self.out, "imports"):
                self.fail("corrupt controls reached consumer")

    def launch_fixture(self):
        measurements, imports, fuzz = (self.root / name for name in ("measurements", "imports", "fuzz"))
        for path in (measurements / "candidate-source.json", measurements / "m08-fuzz-plan.json", imports / "provenance.json"):
            write(path, {"test": path.name})
        write(measurements / "MEMORY_AND_LATENCY_ACCEPTED.json", {"created_utc": "2026-11-11T00:00:00+00:00"})
        write(fuzz / "controls/run_m08_fuzz.py", b"# frozen controller\n")
        gate = {"profile": a.PROFILE, "accepted": True, "targeted_import_spill_correction_qualified": True,
                "created_utc": "2026-11-11T00:01:00+00:00",
                "candidate_source_manifest_sha256": a.sha(measurements / "candidate-source.json"),
                "fuzz_plan_sha256": a.sha(measurements / "m08-fuzz-plan.json"),
                "memory_acceptance_sha256": a.sha(measurements / "MEMORY_AND_LATENCY_ACCEPTED.json"),
                "import_review_receipt_sha256": a.sha(imports / "provenance.json")}
        write(measurements / "LONG_CAMPAIGN_ACCEPTED.json", gate)
        command = ["wsl.exe", "-d", "Ubuntu-22.04", "--", "python3", "/historic/research/run_m08_fuzz.py", "run",
                   "--measurements", "/historic/artifacts/generated/m08-001", "--plan", "/historic/research/m08-fuzz-plan.json",
                   "--output", "/historic/artifacts/generated/m08-fuzz-001", "--target-dir", "/historic/target/m08-fuzz-001"]
        launch = {"created_utc": "2026-11-11T00:02:00+00:00", "long_campaign_acceptance_sha256": a.sha(measurements / "LONG_CAMPAIGN_ACCEPTED.json"),
                  "controller_sha256": a.sha(fuzz / "controls/run_m08_fuzz.py"), "command": command}
        write(measurements / "long-campaign-launch.json", launch)
        write(measurements / "long-campaign-exit.json", {"finished_utc": "2026-11-11T03:00:01+00:00", "exit_code": 0,
              "launch_receipt_sha256": a.sha(measurements / "long-campaign-launch.json")})
        write(fuzz / "config.json", {"started_utc": "2026-11-11T00:02:01+00:00", "controller_sha256": {"run_m08_fuzz.py": launch["controller_sha256"]},
              "build_command": ["taskset", "-c", "8,10,12,14", "/historic/cargo", "fuzz", "build", "--fuzz-dir",
                                "/historic/artifacts/generated/m08-fuzz-001/source/fuzz", "--target-dir", "/historic/target/m08-fuzz-001", "--build-std"]})
        write(fuzz / "fuzz-summary.json", {"finished_utc": "2026-11-11T03:00:00+00:00"})
        return measurements, imports, fuzz

    def test_root_gate_separately_binds_review_controller_command_and_exit(self):
        paths = self.launch_fixture()
        result = a.check_launch(*paths)
        self.assertTrue(result["root_launch_gate_bound_to_sealed_review"])
        self.assertTrue(result["controller_enforces_quantitative_gate_only"])
        self.assertFalse(result["external_timestamp_attestation"])
        measurements, imports, fuzz = paths
        mutations = [(measurements / "LONG_CAMPAIGN_ACCEPTED.json", "import_review_receipt_sha256", "0" * 64),
                     (measurements / "long-campaign-launch.json", "controller_sha256", "0" * 64),
                     (measurements / "long-campaign-exit.json", "exit_code", 1),
                     (fuzz / "config.json", "started_utc", "2026-11-11T00:01:01+00:00")]
        for path, field, changed in mutations:
            original = path.read_bytes();value = a.read(path);value[field] = changed;write(path, value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                a.check_launch(*paths)
            path.write_bytes(original)

    def test_same_basename_launch_from_mixed_historical_roots_fails(self):
        paths = self.launch_fixture()
        measurements, _, fuzz = paths
        launch_path = measurements / "long-campaign-launch.json"
        launch, finished = a.read(launch_path), a.read(measurements / "long-campaign-exit.json")
        launch["command"][8] = "/other/artifacts/generated/m08-001"
        write(launch_path, launch)
        finished["launch_receipt_sha256"] = a.sha(launch_path);write(measurements / "long-campaign-exit.json", finished)
        with self.assertRaisesRegex(ValueError, "argument/root"):
            a.check_launch(*paths)
        launch["command"][8] = "/historic/artifacts/generated/m08-001";write(launch_path, launch)
        finished["launch_receipt_sha256"] = a.sha(launch_path);write(measurements / "long-campaign-exit.json", finished)
        config = a.read(fuzz / "config.json");config["build_command"][7] = "/other/artifacts/generated/m08-fuzz-001/source/fuzz"
        write(fuzz / "config.json", config)
        with self.assertRaisesRegex(ValueError, "build paths"):
            a.check_launch(*paths)

    def test_timestamp_requires_explicit_utc(self):
        for value in ("2026-11-11T00:00:00", "2026-11-11T00:00:00+01:00"):
            with self.assertRaises(ValueError):
                a.moment(value)

    def link_fixture(self):
        measurements, imports, fuzz = self.launch_fixture()
        stages = {name: self.root / name for name in a.STAGES}
        stages.update(measurements=measurements, imports=imports, fuzz=fuzz)
        cli, delivery, notices = (stages[name] for name in ("cli", "delivery", "diagnostic-notices"))
        for label in ("baseline", "candidate"):
            write(measurements / (label + "-source.json"), {"source_sha256": {"compiled.rs": label}})
        timing = {"created_utc": "2026-11-10T23:59:59+00:00"}
        for name in ("measurements-evaluation.json", "m08-acceptance.json", "m08-fuzz-plan.json",
                     "regression/summary.json", "helper-bindings.json"):
            write(measurements / name, {"test": name})
        write(measurements / "timing/capture.json", timing)
        memory = {"profile": a.PROFILE, "accepted": True, "created_utc": "2026-11-11T00:00:00+00:00",
                  "candidate_source_manifest_sha256": a.sha(measurements / "candidate-source.json")}
        for field, name in (("evaluation_sha256", "measurements-evaluation.json"), ("acceptance_sha256", "m08-acceptance.json"),
                ("fuzz_plan_sha256", "m08-fuzz-plan.json"), ("regression_receipt_sha256", "regression/summary.json"),
                ("helper_bindings_sha256", "helper-bindings.json"), ("timing_capture_sha256", "timing/capture.json")):
            memory[field] = a.sha(measurements / name)
        write(measurements / "MEMORY_AND_LATENCY_ACCEPTED.json", memory)
        review = {"memory_acceptance_sha256": a.sha(measurements / "MEMORY_AND_LATENCY_ACCEPTED.json"),
                  "source_manifest_sha256": {}, "build_receipt_sha256": {}, "binaries": {}}
        inventory = {"memory_acceptance_sha256": review["memory_acceptance_sha256"], "source_manifest_sha256": memory["candidate_source_manifest_sha256"],
                     "build_receipt_sha256": {}, "binaries": {}}
        originals = {}
        for label in ("baseline", "candidate"):
            source = measurements / (label + "-source.json")
            review["source_manifest_sha256"][label] = a.sha(source)
            write(imports / "inputs" / source.name, source.read_bytes())
            for host in ("windows", "linux"):
                build = {"binaries": {kind: {"sha256": hashlib.sha256((label + host + kind).encode()).hexdigest()}
                                      for kind in ("consumer", "research", "delivered")}}
                path = measurements / label / host / "build.json";write(path, build)
                key = label + "-" + host
                review["build_receipt_sha256"][key] = a.sha(path)
                review["binaries"][key] = build["binaries"]["consumer"]
                write(imports / "inputs" / (key + "-build.json"), path.read_bytes())
                if label == "candidate":
                    inventory["build_receipt_sha256"][host] = a.sha(path)
                    for kind in ("research", "delivered"):
                        inventory["binaries"][host + "-" + kind] = build["binaries"][kind]
                    originals[host] = build["binaries"]["delivered"]["sha256"]
                    write(cli / "inputs" / (host + "-build.json"), path.read_bytes())
                    write(delivery / "validation" / (host + "-original-build.json"), path.read_bytes())
        write(imports / "collection.json", review);write(cli / "collection.json", inventory)
        write(imports / "inputs/memory-accepted.json", (measurements / "MEMORY_AND_LATENCY_ACCEPTED.json").read_bytes())
        write(cli / "inputs/memory-accepted.json", (measurements / "MEMORY_AND_LATENCY_ACCEPTED.json").read_bytes())
        write(cli / "inputs/candidate-source.json", (measurements / "candidate-source.json").read_bytes())
        write(cli / "provenance.json", {"test": "CLI receipt"})
        accepted = {"profile": a.PROFILE, "accepted": True, "candidate_source_manifest_sha256": memory["candidate_source_manifest_sha256"],
                    "import_review_receipt_sha256": a.sha(imports / "provenance.json"), "cli_inventory_receipt_sha256": a.sha(cli / "provenance.json"),
                    "timing_capture_sha256": a.sha(measurements / "timing/capture.json"), "delivered_binary_sha256": originals}
        write(measurements / "DELIVERY_ACCEPTED.json", accepted)
        for name, source in (("memory-accepted.json", measurements / "MEMORY_AND_LATENCY_ACCEPTED.json"),
                ("delivery-accepted.json", measurements / "DELIVERY_ACCEPTED.json"), ("candidate-source.json", measurements / "candidate-source.json"),
                ("import-review.json", imports / "provenance.json"), ("import-review-collection.json", imports / "collection.json"),
                ("cli-inventory.json", cli / "provenance.json"), ("cli-inventory-collection.json", cli / "collection.json"),
                ("timing-capture.json", measurements / "timing/capture.json")):
            write(delivery / "validation" / name, source.read_bytes())
        for name, source in (("accepted-marker.json", measurements / "MEMORY_AND_LATENCY_ACCEPTED.json"),
                             ("candidate-source.json", measurements / "candidate-source.json"), ("fuzz-plan.json", measurements / "m08-fuzz-plan.json")):
            write(fuzz / name, source.read_bytes())
        config = a.read(fuzz / "config.json");config["measured_source_sha256"] = {"compiled.rs": "candidate"}
        write(fuzz / "config.json", config);write(notices / "inputs/campaign-config.json", (fuzz / "config.json").read_bytes())
        write(fuzz / "source/fuzz/Cargo.lock", b"fresh lock\n")
        write(notices / "inputs/fuzz-Cargo.lock", (fuzz / "source/fuzz/Cargo.lock").read_bytes())
        built, binaries = {}, {}
        for i in range(4):
            name = "h" + str(i)
            for prefix, directory in (("fuzz", "bin"), ("coverage", "postprocessing/bin")):
                path = fuzz / directory / name;write(path, (prefix + name).encode())
                binaries[prefix + "/" + name] = a.sha(path)
                if prefix == "fuzz":
                    built[name] = a.sha(path)
        write(fuzz / "built.json", {"binary_sha256": built})
        write(fuzz / "bin/m08-replay", b"deterministic replay")
        binaries["deterministic-replay"] = a.sha(fuzz / "bin/m08-replay")
        write(notices / "notices.json", {"diagnostic_binary_sha256": binaries})
        gate = a.read(measurements / "LONG_CAMPAIGN_ACCEPTED.json")
        gate.update(candidate_source_manifest_sha256=memory["candidate_source_manifest_sha256"], fuzz_plan_sha256=memory["fuzz_plan_sha256"],
                    memory_acceptance_sha256=review["memory_acceptance_sha256"], import_review_receipt_sha256=accepted["import_review_receipt_sha256"])
        write(measurements / "LONG_CAMPAIGN_ACCEPTED.json", gate)
        launch = a.read(measurements / "long-campaign-launch.json")
        launch["long_campaign_acceptance_sha256"] = a.sha(measurements / "LONG_CAMPAIGN_ACCEPTED.json")
        write(measurements / "long-campaign-launch.json", launch)
        finished = a.read(measurements / "long-campaign-exit.json")
        finished["launch_receipt_sha256"] = a.sha(measurements / "long-campaign-launch.json")
        write(measurements / "long-campaign-exit.json", finished)
        return stages

    def test_cross_stage_original_consumer_cli_and_nine_notice_images(self):
        stages = self.link_fixture()
        self.assertTrue(a.check_links(stages)["recorded_UTC_order_verified"])
        paths = [stages["measurements"] / "candidate/windows/build.json", stages["delivery"] / "validation/import-review.json",
                 stages["fuzz"] / "candidate-source.json", stages["diagnostic-notices"] / "inputs/campaign-config.json"]
        for path in paths:
            raw = path.read_bytes();path.write_bytes(raw + b" ")
            with self.subTest(path=path.name), self.assertRaises(ValueError):
                a.check_links(stages)
            path.write_bytes(raw)
        notice = stages["diagnostic-notices"] / "notices.json"
        original = notice.read_bytes()
        for name in a.read(notice)["diagnostic_binary_sha256"]:
            changed = a.read(notice);changed["diagnostic_binary_sha256"][name] = "0" * 64;write(notice, changed)
            with self.subTest(binary=name), self.assertRaisesRegex(ValueError, "nine notice"):
                a.check_links(stages)
            notice.write_bytes(original)


if __name__ == "__main__":
    unittest.main()
