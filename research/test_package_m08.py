"""Delivery guards and archive comparisons use toy bytes, never a real CLI."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import package_m08 as delivery

PROJECT = Path(__file__).resolve().parents[1]


def toy_pe(timestamp=1, checksum=2):
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 128)
    data[128:132] = b"PE\0\0"
    struct.pack_into("<H", data, 132, 0x8664)
    struct.pack_into("<H", data, 152, 0x20B)
    struct.pack_into("<I", data, 136, timestamp)
    struct.pack_into("<I", data, 216, checksum)
    return bytes(data)


class M08DeliveryGuards(unittest.TestCase):
    def setUp(self):
        parent = PROJECT / "target"
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent, prefix="m08-delivery-unit-")
        self.fixture = Path(self.temporary.name).resolve()
        if self.fixture.parent != parent.resolve():
            raise ValueError("refusing fixture outside owned target directory")
        self.addCleanup(self.temporary.cleanup)
        self.root = self.fixture / "repo"
        (self.root / "artifacts/generated").mkdir(parents=True)
        (self.root / "target").mkdir()
        self.measurements = self.root / "artifacts/generated/m08-001"
        source = self.measurements / "candidate-source"
        source.mkdir(parents=True)
        (source / "Cargo.toml").write_text("# metadata-only guard fixture\n")
        for index in range(45):
            (source / ("fixture-%02d.txt" % index)).write_text("# metadata fixture only\n")
        self.manifest = self.measurements / "candidate-source.json"
        self.manifest.write_text(json.dumps({"profile": delivery.PROFILE, "source_sha256": delivery.inventory(source)}))
        marker = {"profile": delivery.PROFILE, "accepted": True,
                  "candidate_source_manifest_sha256": delivery.sha(self.manifest)}
        self.memory_marker = self.measurements / "MEMORY_AND_LATENCY_ACCEPTED.json"
        self.memory_marker.write_text(json.dumps(marker))
        hashes, consumers, cli_images, build_hashes = {}, {}, {}, {}
        for host in delivery.TARGETS:
            suffix = ".exe" if host == "windows" else ""
            triple = delivery.TARGETS[host]
            version = "release: 1.91.1\nhost: " + triple + "\n"
            binaries = {}
            for kind in ("delivered", "research", "consumer"):
                relative = f"candidate/{host}/bin/{kind}{suffix}"
                path = self.measurements / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(toy_pe() if host == "windows" else ("ELF " + kind + " metadata fixture").encode())
                if kind == "consumer":
                    command = ["cargo", "build", "--release", "--locked", "--offline", "--manifest-path",
                               "/fixture/research/m08-import-consumer/Cargo.toml"]
                else:
                    command = ["cargo", "build", "--release", "--locked", "--offline", "-p", "kem1536-cli", "--bin", "kem1536"]
                    if kind == "research":
                        command += ["--features", "research-vectors"]
                binaries[kind] = {"path": relative, "sha256": delivery.sha(path), "emit_stack_metadata": False,
                                  "command": command, "rustc": version}
            receipt = {"profile": delivery.PROFILE, "host": host,
                       "source_manifest_sha256": delivery.sha(self.manifest), "binaries": binaries}
            receipt_path = self.measurements / "candidate" / host / "build.json"
            receipt_path.write_text(json.dumps(receipt))
            build_hashes[host] = delivery.sha(receipt_path)
            hashes[host] = binaries["delivered"]["sha256"]
            for label in ("baseline", "candidate"):
                consumers[label + "-" + host] = binaries["consumer"]
            for kind in ("research", "delivered"):
                cli_images[host + "-" + kind] = binaries[kind]
        review_dir = self.root / "artifacts/generated/m08-import-review-001"
        cli_dir = self.root / "artifacts/generated/m08-cli-inventory-001"
        review_dir.mkdir(); cli_dir.mkdir()
        self.review, self.collection = review_dir / "provenance.json", review_dir / "collection.json"
        self.cli_inventory, self.cli_collection = cli_dir / "provenance.json", cli_dir / "collection.json"
        self.timing = self.root / "artifacts/generated/timing.json"
        self.collection.write_text(json.dumps({"schema": "m08-import-review-collection-v1", "profile": delivery.PROFILE,
            "source_manifest_sha256": {"candidate": delivery.sha(self.manifest), "baseline": "unused fixture"},
            "memory_acceptance_sha256": delivery.sha(self.memory_marker),
            "build_receipt_sha256": {label + "-" + host: checksum for host, checksum in build_hashes.items()
                                     for label in ("baseline", "candidate")}, "binaries": consumers}))
        self.review.write_text(json.dumps({"schema": "m08-import-review-receipt-v1",
                                          "files_sha256": {"collection.json": delivery.sha(self.collection)}}))
        self.cli_collection.write_text(json.dumps({"schema": "m08-cli-inventory-collection-v1", "profile": delivery.PROFILE,
            "source_manifest_sha256": delivery.sha(self.manifest), "memory_acceptance_sha256": delivery.sha(self.memory_marker),
            "build_receipt_sha256": build_hashes, "binaries": cli_images}))
        self.cli_inventory.write_text(json.dumps({"schema": "m08-cli-inventory-receipt-v1",
            "files_sha256": {"collection.json": delivery.sha(self.cli_collection)}}))
        self.timing.write_text(json.dumps({"scope": "metadata-only guard fixture"}))
        marker.update(delivered_binary_sha256=hashes,
                      import_review_receipt_sha256=delivery.sha(self.review),
                      cli_inventory_receipt_sha256=delivery.sha(self.cli_inventory),
                      timing_capture_sha256=delivery.sha(self.timing))
        self.delivery_marker = self.measurements / "DELIVERY_ACCEPTED.json"
        self.delivery_marker.write_text(json.dumps(marker))
        self.root_patch = patch.object(delivery, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def test_delivery_marker_precedes_any_build_or_output(self):
        self.delivery_marker.unlink()
        out = self.root / "artifacts/generated/m08-delivery-001"
        target = self.root / "target/m08-repeat-001"
        with patch.object(delivery.sys, "platform", "win32"), \
             patch.object(delivery.subprocess, "run") as build, \
             patch.object(delivery.subprocess, "check_output") as commands:
            with self.assertRaisesRegex(ValueError, "wait for DELIVERY_ACCEPTED"):
                delivery.run(out, self.measurements, target, self.review, self.cli_inventory, self.timing)
            build.assert_not_called()
            commands.assert_not_called()
        self.assertFalse(out.exists())
        self.assertFalse(target.exists())

    def test_bound_originals_match_review_and_both_markers(self):
        bound = delivery.bindings(self.measurements, self.review, self.cli_inventory, self.timing)
        self.assertEqual(set(bound["originals"]), {"windows", "linux"})
        for host, path in bound["originals"].items():
            self.assertEqual(delivery.sha(path), bound["receipts"][host]["binaries"]["delivered"]["sha256"])

    def test_altered_original_is_refused(self):
        (self.measurements / "candidate/windows/bin/delivered.exe").write_bytes(toy_pe(timestamp=5))
        with self.assertRaisesRegex(ValueError, "inventoried original binary changed"):
            delivery.bindings(self.measurements, self.review, self.cli_inventory, self.timing)

    def test_review_receipt_is_bound_by_hash(self):
        self.review.write_text("{}")
        with self.assertRaisesRegex(ValueError, "review or timing receipt differs"):
            delivery.bindings(self.measurements, self.review, self.cli_inventory, self.timing)

    def test_review_collection_chain_refuses_tampering_and_wrong_binary_identity(self):
        collection = json.loads(self.collection.read_text())
        collection["binaries"]["candidate-windows"]["sha256"] = "0" * 64
        self.collection.write_text(json.dumps(collection))
        with self.assertRaisesRegex(ValueError, "review collection hash differs"):
            delivery.bindings(self.measurements, self.review, self.cli_inventory, self.timing)
        # Reseal only this toy fixture to test the deeper binary identity check.
        receipt = json.loads(self.review.read_text())
        receipt["files_sha256"]["collection.json"] = delivery.sha(self.collection)
        self.review.write_text(json.dumps(receipt))
        marker = json.loads(self.delivery_marker.read_text())
        marker["import_review_receipt_sha256"] = delivery.sha(self.review)
        self.delivery_marker.write_text(json.dumps(marker))
        with self.assertRaisesRegex(ValueError, "consumer import-review identity"):
            delivery.bindings(self.measurements, self.review, self.cli_inventory, self.timing)

    def test_cli_inventory_has_its_own_hash_chain_and_exact_images(self):
        data = json.loads(self.cli_collection.read_text())
        data["binaries"]["windows-delivered"]["sha256"] = "0" * 64
        self.cli_collection.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "collection hash differs"):
            delivery.bindings(self.measurements, self.review, self.cli_inventory, self.timing)
        seal = json.loads(self.cli_inventory.read_text())
        seal["files_sha256"]["collection.json"] = delivery.sha(self.cli_collection)
        self.cli_inventory.write_text(json.dumps(seal))
        marker = json.loads(self.delivery_marker.read_text())
        marker["cli_inventory_receipt_sha256"] = delivery.sha(self.cli_inventory)
        self.delivery_marker.write_text(json.dumps(marker))
        with self.assertRaisesRegex(ValueError, "CLI inventory/source/compiler identity differs"):
            delivery.bindings(self.measurements, self.review, self.cli_inventory, self.timing)

    def test_consumer_review_cannot_substitute_for_cli_inventory(self):
        marker = json.loads(self.delivery_marker.read_text())
        marker["cli_inventory_receipt_sha256"] = delivery.sha(self.review)
        self.delivery_marker.write_text(json.dumps(marker))
        with self.assertRaisesRegex(ValueError, "invalid sealed binary review receipt"):
            delivery.bindings(self.measurements, self.review, self.review, self.timing)

    def test_proof_scope_cannot_promote_import_review_into_cli_erasure(self):
        delivery.check_proof_scope(dict(delivery.PROOF_SCOPE))
        changed = dict(delivery.PROOF_SCOPE, CLI_PKE_erasure_proved=True)
        with self.assertRaisesRegex(ValueError, "may not become"):
            delivery.check_proof_scope(changed)

    def test_crash_is_not_a_normal_research_command_rejection(self):
        binary = self.measurements / "candidate/windows/bin/delivered.exe"
        folder = self.fixture / "validation-crash-fixture"
        folder.mkdir()
        test = {"profile": delivery.PROFILE, "fresh_round_trips": 16,
                "implicit_rejections_checked": 16, "secrets_printed": False}
        successful = delivery.subprocess.CompletedProcess(["fixture"], 0, stdout=json.dumps(test).encode(), stderr=b"")
        crashed = delivery.subprocess.CompletedProcess(["fixture"], -11, stdout=b"", stderr=b"fixture failure")
        with patch.object(delivery, "execute_binary", side_effect=[(successful, ["fixture"]), (crashed, ["fixture"])]):
            with self.assertRaisesRegex(ValueError, "did not reject normally"):
                delivery.validate_executable(binary, "windows", folder, "original")
        self.assertFalse((folder / "original-validation.json").exists())

    def test_diagnostic_notices_use_locked_resolved_features(self):
        metadata = {"packages": [{"id": "fuzz", "name": "kem1536-fuzz", "version": "0.0.0", "source": None,
                                   "license": None},
                                  {"id": "core", "name": "kem1536", "version": "0.1.0", "source": None,
                                   "license": "MIT"}],
                    "resolve": {"nodes": [{"id": "fuzz", "features": [], "deps": [{"pkg": "core"}]},
                                           {"id": "core", "features": [], "deps": []}]}}
        lock = {"package": [{"name": "kem1536-fuzz", "version": "0.0.0"},
                            {"name": "kem1536", "version": "0.1.0"}]}
        records = delivery.diagnostic_records(metadata, lock)
        self.assertEqual(len(records), 2)
        metadata["resolve"]["nodes"][1]["features"] = ["research-vectors"]
        with self.assertRaisesRegex(ValueError, "unexpectedly enables"):
            delivery.diagnostic_records(metadata, lock)

    def diagnostic_fixture(self, group):
        spec = delivery.DIAGNOSTIC_GROUPS[group]
        metadata = {"packages": [{"id": group, "name": spec["root_package"], "version": "0.0.0",
                                   "source": None, "license": None},
                                  {"id": "core", "name": "kem1536", "version": "0.1.0", "source": None,
                                   "license": "MIT"},
                                  {"id": "shared", "name": "shared", "version": "1.0.0", "source": "registry+fixture",
                                   "license": "MIT", "manifest_path": "/fixture/shared/Cargo.toml"}],
                    "resolve": {"nodes": [{"id": group, "features": [], "deps": [{"pkg": "core"}]},
                                           {"id": "core", "features": [], "deps": [{"pkg": "shared"}]},
                                           {"id": "shared", "features": [group], "deps": []}]}}
        lock = {"package": [{"name": spec["root_package"], "version": "0.0.0"},
                            {"name": "kem1536", "version": "0.1.0"},
                            {"name": "shared", "version": "1.0.0", "source": "registry+fixture", "checksum": "a" * 64}]}
        return metadata, lock

    def test_diagnostic_union_preserves_separate_features_and_replay_dependencies(self):
        metadatas, graphs = {}, {}
        for group, spec in delivery.DIAGNOSTIC_GROUPS.items():
            metadatas[group], lock = self.diagnostic_fixture(group)
            graphs[group] = delivery.diagnostic_records(metadatas[group], lock, spec["root_package"])
        union, _ = delivery.diagnostic_union(graphs, metadatas)
        shared = next(row for row in union if row["name"] == "shared")
        self.assertEqual(shared["features"], ["fuzz", "replay"])
        self.assertEqual(shared["binary_groups"], ["fuzz", "replay"])
        self.assertEqual(next(row for row in graphs["fuzz"] if row["name"] == "shared")["features"], ["fuzz"])
        self.assertEqual(next(row for row in graphs["replay"] if row["name"] == "shared")["features"], ["replay"])
        self.assertEqual(next(row for row in union if row["name"] == "kem1536-bench")["binary_groups"], ["replay"])
        next(row for row in graphs["replay"] if row["name"] == "shared")["lock_checksum"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "different checksum/license"):
            delivery.diagnostic_union(graphs, metadatas)

    def diagnostic_config_and_command(self, group):
        config = {"build_command": ["taskset", "-c", "8,10,12,14", "/fixture/cargo", "fuzz", "build", "--fuzz-dir",
                                    "/original/campaign/source/fuzz"]}
        command = ["wsl", "-d", "Ubuntu-22.04", "--", "env", "-i", "/fixture/cargo", "metadata", "--locked",
                   "--offline", "--format-version", "1", "--filter-platform", "x86_64-unknown-linux-gnu",
                   "--manifest-path", "/original/campaign/source/" + delivery.DIAGNOSTIC_GROUPS[group]["manifest"]]
        return config, command

    def test_diagnostic_metadata_command_binds_replay_root_manifest_and_locked_target(self):
        config, command = self.diagnostic_config_and_command("replay")
        delivery.check_diagnostic_metadata_command(command, config, "Cargo.toml")
        for change in ("manifest", "lock", "target"):
            bad = command[:]
            if change == "manifest":
                bad[-1] = "/original/campaign/source/fuzz/Cargo.toml"
            elif change == "lock":
                bad.remove("--locked")
            else:
                bad[bad.index("x86_64-unknown-linux-gnu")] = "x86_64-pc-windows-gnu"
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "exact frozen group manifest and locked target"):
                delivery.check_diagnostic_metadata_command(bad, config, "Cargo.toml")

    def test_diagnostic_replay_root_lock_is_bound_to_frozen_source_hash(self):
        group = "replay"
        folder = self.fixture / "diagnostic-replay-fixture"
        (folder / "inputs").mkdir(parents=True)
        manifest = folder / "inputs/replay-Cargo.toml"
        locked = folder / "inputs/replay-Cargo.lock"
        manifest.write_text("# replay manifest fixture\n")
        metadata, lock = self.diagnostic_fixture(group)
        locked.write_text("version = 4\n" + "".join(
            "\n[[package]]\n" + "".join(key + " = " + json.dumps(value) + "\n" for key, value in row.items())
            for row in lock["package"]))
        delivery.save(folder / "metadata-replay.json", metadata)
        config, command = self.diagnostic_config_and_command(group)
        config["source_sha256"] = {"Cargo.toml": delivery.sha(manifest), "Cargo.lock": delivery.sha(locked)}
        recorded = {**delivery.DIAGNOSTIC_GROUPS[group], "metadata_command": command,
                    "metadata_sha256": delivery.sha(folder / "metadata-replay.json"),
                    "manifest_sha256": delivery.sha(manifest), "lock_sha256": delivery.sha(locked),
                    "resolved_packages": delivery.diagnostic_records(metadata, lock, "kem1536-bench")}
        delivery.check_diagnostic_group(folder, group, recorded, config)
        with locked.open("a") as stream:
            stream.write("# altered root lock\n")
        # Resealing the local group cannot change the frozen campaign source closure.
        recorded["lock_sha256"] = delivery.sha(locked)
        with self.assertRaisesRegex(ValueError, "group manifest/lock/metadata differs"):
            delivery.check_diagnostic_group(folder, group, recorded, config)

    def test_pe_metadata_is_the_only_allowed_windows_difference(self):
        first, second = toy_pe(1, 2), toy_pe(3, 4)
        result = delivery.compare(first, second, "windows")
        self.assertFalse(result["raw_byte_identical"])
        self.assertFalse(result["raw_binaries_modified"])
        self.assertEqual(first, toy_pe(1, 2))
        modified = bytearray(second)
        modified[300] = 1
        with self.assertRaisesRegex(ValueError, "outside allowed"):
            delivery.compare(first, bytes(modified), "windows")

    def test_linux_requires_exact_raw_bytes(self):
        self.assertTrue(delivery.compare(b"same", b"same", "linux")["raw_byte_identical"])
        with self.assertRaisesRegex(ValueError, "outside allowed"):
            delivery.compare(b"first", b"second", "linux")

    def test_non_system_windows_import_is_refused(self):
        result = delivery.check_windows_imports("Import {\n Name: KERNEL32.dll\n}\n Name: bcryptprimitives.dll\n")
        self.assertEqual(len(result["libraries"]), 2)
        with self.assertRaisesRegex(ValueError, "non-system Windows DLL"):
            delivery.check_windows_imports("Name: KERNEL32.dll\nName: libwinpthread-1.dll\n")
        for module in ("evil.DLL", "evil module.dll", "other-module", ""):
            with self.subTest(module=module), self.assertRaisesRegex(ValueError, "non-system Windows DLL"):
                delivery.check_windows_imports("Name: KERNEL32.dll\nName: " + module + "\n")

    def test_uninspected_delay_imports_are_refused(self):
        raw = bytearray(toy_pe())
        struct.pack_into("<I", raw, 128 + 132, 16)
        self.assertEqual(delivery.check_windows_imports("Name: KERNEL32.dll\n", bytes(raw))["non_system_libraries"], [])
        struct.pack_into("<II", raw, 128 + 240, 4096, 32)
        with self.assertRaisesRegex(ValueError, "delay imports require separate inspection"):
            delivery.check_windows_imports("Name: KERNEL32.dll\n", bytes(raw))

    def test_archive_member_hashes_and_exact_inventory_are_checked(self):
        folder = self.fixture / "toy-package"
        folder.mkdir()
        (folder / "LICENSE").write_text("toy archive guard fixture\n")
        expected = delivery.inventory(folder)
        archive = self.fixture / "toy.zip"
        delivery.zip_package(folder, archive)
        delivery.verify_archive(archive, expected)
        with self.assertRaisesRegex(ValueError, "member changed"):
            delivery.verify_archive(archive, {"LICENSE": "0" * 64})
        with self.assertRaisesRegex(ValueError, "inventory differs"):
            delivery.verify_archive(archive, {})

    def test_read_only_cli_verify_accepts_an_archived_results_path(self):
        archived = self.root / "results/engine/m08-001/delivery"
        with patch.object(delivery.sys, "argv", ["package_m08.py", "verify", "--output", str(archived)]), \
             patch.object(delivery, "verify", return_value={"fixture_only": True}) as verify, \
             patch.object(delivery, "owned") as writer_guard, redirect_stdout(io.StringIO()):
            delivery.main()
        verify.assert_called_once_with(archived.resolve())
        writer_guard.assert_not_called()

    def test_packaged_comparison_must_match_actual_repeat(self):
        comparison = delivery.compare(toy_pe(1, 2), toy_pe(3, 4), "windows")
        provenance = {"binary_sha256": "first", "repeat_binary_sha256": "second", "comparison": comparison}
        delivery.check_comparison_binding(provenance, "first", "second", comparison)
        with self.assertRaisesRegex(ValueError, "comparison provenance differs"):
            delivery.check_comparison_binding(provenance, "first", "changed", comparison)
        changed = dict(comparison, raw_byte_identical=True)
        with self.assertRaisesRegex(ValueError, "comparison provenance differs"):
            delivery.check_comparison_binding(provenance, "first", "second", changed)

    def test_every_packaged_validation_copy_is_bound(self):
        out = self.fixture / "toy-output"
        (out / "validation").mkdir(parents=True)
        (out / "validation/gate.json").write_text("fixture gate\n")
        host = out / "windows"
        package = host / "package"
        (package / "validation").mkdir(parents=True)
        (package / "validation/gate.json").write_text("fixture gate\n")
        for name in delivery.HOST_VALIDATION_FILES:
            (host / name).write_text("fixture receipt\n")
            (package / "validation" / name).write_text("fixture receipt\n")
        delivery.check_validation_copies(out, "windows", package)
        (package / "validation/gate.json").write_text("altered fixture gate\n")
        with self.assertRaisesRegex(ValueError, "validation copy differs"):
            delivery.check_validation_copies(out, "windows", package)


if __name__ == "__main__":
    unittest.main()
