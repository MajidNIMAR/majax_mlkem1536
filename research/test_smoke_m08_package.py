"""Pure guards for native M08 smoke checks; no real executable is launched."""
from contextlib import contextmanager
import gzip
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import smoke_m08_package as smoke


def consumer_smoke(host="linux"):
    return {"schema": 1, "profile": smoke.PROFILE, "host": host, "architecture": "x86_64",
            "research_vectors_feature_requested": False, "secrets_printed": False,
            "fixtures": smoke.FIXTURE,
            "cases": [{"operation": name, "expected": status, "status": status} for name, status in smoke.CASES],
            "fresh_imported_key_round_trips": 1, "fresh_rejections": 1, "repeat_rejection_equal": True,
            "fresh_private_with_fixed_z_imported": True,
            "fixed_z_import_is_syntax_not_entropy_validation": True}


def exhaustive():
    return {"schema": 1, "profile": smoke.PROFILE, "mode": "exhaustive single-coefficient probes",
            "single_coefficient_value_alignment_cases": 65536, "boundary_position_cases": 23040,
            "total_cases": 88576, "all_expected_statuses_and_accepted_encodings_match": True,
            "complete_vector_space_exhausted": False, "formal_program_verification": False,
            "secrets_printed": False, "fixture": smoke.FIXTURE}


class M08NativeSmokeGuards(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parents[1] / "target"
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="m08-smoke-unit-", dir=parent)
        self.folder = Path(self.temporary.name).resolve()
        if self.folder.parent != parent.resolve():
            raise ValueError("fixture escaped NIST target")
        self.addCleanup(self.temporary.cleanup)

    def test_expected_fresh_checks_and_all_cases_are_required(self):
        smoke.check_consumer_smoke(consumer_smoke(), "linux")
        for mutation in ("cases", "fresh_rejections", "research_vectors_feature_requested",
                         "fixed_z_import_is_syntax_not_entropy_validation", "secrets_printed"):
            changed = consumer_smoke()
            changed[mutation] = [] if mutation == "cases" else True if mutation in (
                "research_vectors_feature_requested", "secrets_printed") else False
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                smoke.check_consumer_smoke(changed, "linux")

    def test_exhaustive_scope_must_keep_bounds_and_limitations(self):
        smoke.check_consumer_exhaustive(exhaustive())
        for field, value in (("total_cases", 88575), ("complete_vector_space_exhausted", True),
                             ("formal_program_verification", True), ("secrets_printed", True)):
            altered = dict(exhaustive(), **{field: value})
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "88576"):
                smoke.check_consumer_exhaustive(altered)

    def test_cli_requires_exact_sixteen_fresh_checks(self):
        good = {"profile": smoke.PROFILE, "fresh_round_trips": 16,
                "implicit_rejections_checked": 16, "secrets_printed": False}
        smoke.check_cli_test(good)
        for field, value in (("fresh_round_trips", True), ("implicit_rejections_checked", 15),
                             ("secrets_printed", True)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                smoke.check_cli_test(dict(good, **{field: value}))

    def test_consumer_decompression_is_bounded_and_hash_checked(self):
        compressed = self.folder / "binary.gz"
        raw = b"synthetic image, never executed"
        compressed.write_bytes(gzip.compress(raw, mtime=0))
        target = self.folder / "consumer"
        smoke.recover_consumer(compressed, target, hashlib.sha256(raw).hexdigest(), limit=len(raw))
        self.assertEqual(target.read_bytes(), raw)
        with self.assertRaisesRegex(ValueError, "budget"):
            smoke.recover_consumer(compressed, self.folder / "oversized", "0" * 64, limit=len(raw) - 1)
        with self.assertRaisesRegex(ValueError, "sealed original"):
            smoke.recover_consumer(compressed, self.folder / "changed", "0" * 64)

    def test_native_headers_require_correct_architecture(self):
        path = self.folder / "header-only"
        header = bytearray(512)
        header[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", header, 18, 62)
        path.write_bytes(header)
        smoke.check_architecture(path, "linux")
        struct.pack_into("<H", header, 18, 183)
        path.write_bytes(header)
        with self.assertRaisesRegex(ValueError, "x86-64 ELF64"):
            smoke.check_architecture(path, "linux")
        header = bytearray(512)
        header[:2] = b"MZ"
        struct.pack_into("<I", header, 60, 128)
        header[128:132] = b"PE\0\0"
        struct.pack_into("<H", header, 132, 0x8664)
        struct.pack_into("<H", header, 152, 0x20B)
        path.write_bytes(header)
        smoke.check_architecture(path, "windows")
        struct.pack_into("<H", header, 132, 0xAA64)
        path.write_bytes(header)
        with self.assertRaisesRegex(ValueError, "x86-64 PE32"):
            smoke.check_architecture(path, "windows")

    def test_captured_output_is_not_revealed_in_failure(self):
        marker = b"synthetic private payload; do not log"
        for result in (subprocess.CompletedProcess([], -11, stdout=marker, stderr=marker),
                       subprocess.CompletedProcess([], 0, stdout=marker, stderr=b"")):
            with self.subTest(code=result.returncode), patch.object(smoke, "run_process", return_value=result):
                with self.assertRaises(ValueError) as caught:
                    smoke.json_result(Path("fixture"), "smoke", 120)
                self.assertNotIn(marker.decode(), str(caught.exception))

    def test_native_process_has_timeout_and_no_shell(self):
        result = subprocess.CompletedProcess([], 0, stdout=b"{}", stderr=b"")
        with patch.object(smoke.subprocess, "run", return_value=result) as run:
            smoke.run_process(Path("fixture"), ["exhaustive"], 180)
        run.assert_called_once_with(["fixture", "exhaustive"], capture_output=True, timeout=180)

    def test_stage_hash_mismatch_precedes_native_execution(self):
        # Toy receipt chain; verification helpers are mocked, no real archive or image.
        delivered, imports = self.folder / "delivery", self.folder / "imports"
        (delivered / "validation").mkdir(parents=True)
        imports.mkdir()
        (delivered / "validation/candidate-source.json").write_text("{}")
        (delivered / "validation/memory-accepted.json").write_text("{}")
        (delivered / "validation/import-review-collection.json").write_text("{}")
        (imports / "provenance.json").write_text("{}")
        (imports / "collection.json").write_text(json.dumps({"source_manifest_sha256": {"candidate": "0" * 64},
                                                            "memory_acceptance_sha256": "0" * 64}))
        (delivered / "validation/delivery-accepted.json").write_text(json.dumps({"import_review_receipt_sha256": "0" * 64}))

        @contextmanager
        def extracted(_snapshot, name):
            yield delivered if name == "delivery" else imports

        with patch.object(smoke, "native_host", return_value="linux"), \
             patch.object(smoke.archive, "extracted_stage", side_effect=extracted, create=True), \
             patch.object(smoke.delivery, "verify"), patch.object(smoke.import_review, "verify"), \
             patch.object(smoke, "run_process") as native:
            with self.assertRaisesRegex(ValueError, "same accepted M08 candidate"):
                smoke.smoke(self.folder / "snapshot")
            native.assert_not_called()


if __name__ == "__main__":
    unittest.main()
