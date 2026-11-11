"""Delivery guards and archive comparisons use toy bytes, never a real CLI."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

import package_m07 as delivery

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


class M07DeliveryGuards(unittest.TestCase):
    def setUp(self):
        parent = PROJECT / "target"
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent, prefix="m07-delivery-unit-")
        self.fixture = Path(self.temporary.name).resolve()
        if self.fixture.parent != parent.resolve():
            raise ValueError("refusing fixture outside owned target directory")
        self.addCleanup(self.temporary.cleanup)
        self.root = self.fixture / "repo"
        (self.root / "artifacts/generated").mkdir(parents=True)
        (self.root / "target").mkdir()
        self.measurements = self.root / "artifacts/generated/m07-001"
        source = self.measurements / "candidate-source"
        source.mkdir(parents=True)
        (source / "Cargo.toml").write_text("# metadata-only guard fixture\n")
        self.manifest = self.measurements / "candidate-source.json"
        self.manifest.write_text(json.dumps({"profile": delivery.PROFILE, "source_sha256": delivery.inventory(source)}))
        marker = {"profile": delivery.PROFILE, "accepted": True,
                  "candidate_source_manifest_sha256": delivery.sha(self.manifest)}
        (self.measurements / "MEMORY_AND_LATENCY_ACCEPTED.json").write_text(json.dumps(marker))
        hashes, reviewed_binaries = {}, {}
        for host in delivery.TARGETS:
            suffix = ".exe" if host == "windows" else ""
            relative = f"candidate/{host}/bin/delivered{suffix}"
            path = self.measurements / relative
            path.parent.mkdir(parents=True)
            path.write_bytes(toy_pe() if host == "windows" else b"ELF metadata fixture")
            hashes[host] = delivery.sha(path)
            receipt = {"profile": delivery.PROFILE, "host": host,
                       "source_manifest_sha256": delivery.sha(self.manifest),
                       "binaries": {"delivered": {"path": relative, "sha256": hashes[host],
                           "emit_stack_metadata": False, "command": ["cargo", "build", "--release", "--locked", "--offline",
                                                                       "-p", "kem1536-cli", "--bin", "kem1536"]}}}
            (self.measurements / "candidate" / host / "build.json").write_text(json.dumps(receipt))
            reviewed_binaries[host + "-delivered"] = receipt["binaries"]["delivered"]
        self.review = self.root / "artifacts/generated/review.json"
        self.collection = self.root / "artifacts/generated/collection.json"
        self.timing = self.root / "artifacts/generated/timing.json"
        self.collection.write_text(json.dumps({"source_manifest_sha256": delivery.sha(self.manifest),
            "marker_sha256": delivery.sha(self.measurements / "MEMORY_AND_LATENCY_ACCEPTED.json"),
            "core_sha256": delivery.inventory(source), "binaries": reviewed_binaries}))
        self.review.write_text(json.dumps({"schema": "m07-binary-review-receipt-v1",
                                          "files_sha256": {"collection.json": delivery.sha(self.collection)}}))
        self.timing.write_text(json.dumps({"scope": "metadata-only guard fixture"}))
        marker.update(delivered_binary_sha256=hashes,
                      binary_review_receipt_sha256=delivery.sha(self.review),
                      timing_capture_sha256=delivery.sha(self.timing))
        self.delivery_marker = self.measurements / "DELIVERY_ACCEPTED.json"
        self.delivery_marker.write_text(json.dumps(marker))
        self.root_patch = patch.object(delivery, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def test_delivery_marker_precedes_any_build_or_output(self):
        self.delivery_marker.unlink()
        out = self.root / "artifacts/generated/m07-delivery-001"
        target = self.root / "target/m07-repeat-001"
        with patch.object(delivery.sys, "platform", "win32"), \
             patch.object(delivery.subprocess, "run") as build, \
             patch.object(delivery.subprocess, "check_output") as commands:
            with self.assertRaisesRegex(ValueError, "wait for DELIVERY_ACCEPTED"):
                delivery.run(out, self.measurements, target, self.review, self.timing)
            build.assert_not_called()
            commands.assert_not_called()
        self.assertFalse(out.exists())
        self.assertFalse(target.exists())

    def test_bound_originals_match_review_and_both_markers(self):
        bound = delivery.bindings(self.measurements, self.review, self.timing)
        self.assertEqual(set(bound["originals"]), {"windows", "linux"})
        for host, path in bound["originals"].items():
            self.assertEqual(delivery.sha(path), bound["receipts"][host]["binaries"]["delivered"]["sha256"])

    def test_altered_original_is_refused(self):
        (self.measurements / "candidate/windows/bin/delivered.exe").write_bytes(toy_pe(timestamp=5))
        with self.assertRaisesRegex(ValueError, "reviewed original binary changed"):
            delivery.bindings(self.measurements, self.review, self.timing)

    def test_review_receipt_is_bound_by_hash(self):
        self.review.write_text("{}")
        with self.assertRaisesRegex(ValueError, "review or timing receipt differs"):
            delivery.bindings(self.measurements, self.review, self.timing)

    def test_review_collection_chain_refuses_tampering_and_wrong_binary_identity(self):
        collection = json.loads(self.collection.read_text())
        collection["binaries"]["windows-delivered"]["sha256"] = "0" * 64
        self.collection.write_text(json.dumps(collection))
        with self.assertRaisesRegex(ValueError, "review collection hash differs"):
            delivery.bindings(self.measurements, self.review, self.timing)
        # Reseal only this toy fixture to test the deeper binary identity check.
        receipt = json.loads(self.review.read_text())
        receipt["files_sha256"]["collection.json"] = delivery.sha(self.collection)
        self.review.write_text(json.dumps(receipt))
        marker = json.loads(self.delivery_marker.read_text())
        marker["binary_review_receipt_sha256"] = delivery.sha(self.review)
        self.delivery_marker.write_text(json.dumps(marker))
        with self.assertRaisesRegex(ValueError, "delivered collection identity differs"):
            delivery.bindings(self.measurements, self.review, self.timing)

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
        archived = self.root / "results/engine/m07-001/delivery"
        with patch.object(delivery.sys, "argv", ["package_m07.py", "verify", "--output", str(archived)]), \
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
