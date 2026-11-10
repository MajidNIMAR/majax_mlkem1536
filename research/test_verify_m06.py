"""Reject incomplete or modified finite M06 evidence before certification."""

import copy
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from verify_m06 import check_files, check_regression
from confirm_m06_builds import comparison_bytes


class M06EvidenceTests(unittest.TestCase):
    def panel(self):
        row = dict(compared_to_frozen_M01={"dev-vectors": 1000, "dev-rejection-vectors": 10000},
                   all_fields_equal=True, frozen_M02_mutations_compared=10000,
                   formats=dict(inputs=20000, rejected=17))
        return dict(profile="KEM1536-DEV-Q7681-R1",
                    platforms={host: copy.deepcopy(row) for host in ("windows", "linux")})

    def test_incomplete_and_disagreeing_hosts_rejected(self):
        check_regression(self.panel())
        for change in ("missing-host", "missing-vector", "mutations", "formats", "different-decision", "inequality"):
            with self.subTest(change=change):
                panel = self.panel()
                row = panel["platforms"]["linux"]
                if change == "missing-host":
                    panel["platforms"].pop("linux")
                elif change == "missing-vector":
                    row["compared_to_frozen_M01"]["dev-vectors"] -= 1
                elif change == "mutations":
                    row["frozen_M02_mutations_compared"] -= 1
                elif change == "formats":
                    row["formats"]["inputs"] -= 1
                elif change == "different-decision":
                    row["formats"]["rejected"] += 1
                else:
                    row["all_fields_equal"] = False
                with self.assertRaises(ValueError):
                    check_regression(panel)

    def test_changed_missing_or_unlisted_bytes_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            member = root / "evidence.bin"
            member.write_bytes(b"frozen-evidence")
            expected = {"evidence.bin": hashlib.sha256(member.read_bytes()).hexdigest()}
            (root / "provenance.json").write_text("{}")
            check_files(root, expected)
            member.write_bytes(b"modified-evidence")
            with self.assertRaises(ValueError):
                check_files(root, expected)
            member.unlink()
            with self.assertRaises(ValueError):
                check_files(root, expected)
            member.write_bytes(b"frozen-evidence")
            nested = root / "nested"
            nested.mkdir()
            (nested / "provenance.json").write_text("unlisted evidence")
            with self.assertRaises(ValueError):
                check_files(root, expected)

    def test_pe_comparison_allows_only_two_metadata_fields(self):
        original = bytearray(512)
        original[:2] = b"MZ"
        struct.pack_into("<I", original, 60, 128)
        original[128:132] = b"PE\0\0"
        struct.pack_into("<H", original, 132, 0x8664)
        struct.pack_into("<H", original, 152, 0x20B)
        baseline = bytes(original)
        metadata_changed = bytearray(baseline)
        struct.pack_into("<I", metadata_changed, 136, 123456)
        struct.pack_into("<I", metadata_changed, 216, 654321)
        expected, fields = comparison_bytes(baseline, "windows")
        actual, _ = comparison_bytes(bytes(metadata_changed), "windows")
        self.assertEqual(actual, expected)
        self.assertEqual([f["offset"] for f in fields], [136, 216])
        self.assertEqual(bytes(original), baseline)
        code_changed = bytearray(metadata_changed)
        code_changed[450] = 1
        self.assertNotEqual(comparison_bytes(bytes(code_changed), "windows")[0], expected)
        self.assertNotEqual(comparison_bytes(bytes(metadata_changed), "linux")[0], baseline)
        for offset in (0, 128, 132, 152):
            invalid = bytearray(baseline)
            invalid[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                comparison_bytes(bytes(invalid), "windows")


if __name__ == "__main__":
    unittest.main()
