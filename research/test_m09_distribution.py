"""Repeat comparison limits and actual distribution data-only checks."""
from pathlib import Path
import struct
import unittest

from m09_distribution import ROOT, PROFILE, check_promotion_acceptance, compare, safe_evidence_name, verify


def pe():
    raw = bytearray(512)
    raw[:2] = b"MZ"
    struct.pack_into("<I", raw, 60, 128)
    raw[128:132] = b"PE\0\0"
    struct.pack_into("<H", raw, 132, 0x8664)
    struct.pack_into("<H", raw, 152, 0x20b)
    return bytes(raw)


class ComparisonTests(unittest.TestCase):
    def test_linux_requires_raw_identity(self):
        self.assertTrue(compare(b"abc", b"abc", "linux")["raw_byte_identical"])
        with self.assertRaises(ValueError):
            compare(b"abc", b"abd", "linux")

    def test_pe_masks_only_timestamp_and_checksum_without_mutation(self):
        original = pe()
        changed = bytearray(original)
        struct.pack_into("<I", changed, 136, 7)
        struct.pack_into("<I", changed, 216, 11)
        repeated = bytes(changed)
        result = compare(original, repeated, "windows")
        self.assertFalse(result["raw_byte_identical"])
        self.assertFalse(result["raw_binaries_modified"])
        self.assertEqual(original, pe())
        self.assertEqual(repeated, bytes(changed))
        self.assertEqual([p["offset"] for p in result["original_metadata"]], [136, 216])

    def test_pe_payload_change_rejected(self):
        original = pe()
        changed = bytearray(original)
        changed[350] ^= 1
        with self.assertRaises(ValueError):
            compare(original, bytes(changed), "windows")

    def test_invalid_and_other_abi_pe_rejected(self):
        with self.assertRaises(ValueError):
            compare(b"not a PE", b"not a PE", "windows")
        changed = bytearray(pe())
        struct.pack_into("<H", changed, 132, 0x014c)
        with self.assertRaises(ValueError):
            compare(bytes(changed), bytes(changed), "windows")

    def test_frozen_rejected_distribution_is_portable_without_local_acquisition(self):
        # Use the shipped negative evidence, including on clean hosted runners.
        # The accepted distribution is replayed separately by archive_m09.
        from archive_m09 import members, read, sha, data_reader
        capsule = ROOT / "results/engine/m09-001"
        record = read(capsule / "provenance.json")["groups"]["rejected"]
        archive = capsule / record["archive"]
        self.assertEqual(sha(archive), record["archive_sha256"])
        prefix = "m09-distribution-001/"
        raw = {name.removeprefix(prefix): value for name, value in members(archive).items()
               if name.startswith(prefix)}
        result = data_reader(raw, verify)
        self.assertTrue(result["verified"])
        self.assertEqual(result["hosts"], ["linux", "windows"])
        self.assertEqual(result["promotion_status"], "REJECTED_FOR_PROMOTION")

    def test_qualified_promotion_requires_exact_root_binding_and_all_three_gates(self):
        marker = {"profile": PROFILE, "accepted": True, "source_manifest_sha256": "a" * 64,
                  "delivered_binary_sha256": {"windows": "b" * 64, "linux": "c" * 64},
                  "checks": {"latency": True, "memory": True, "binary_review": True},
                  "evidence_sha256": {"artifacts/generated/x/" + n: "d" * 64 for n in ("latency.json", "memory.json", "review.json")}}
        check_promotion_acceptance(marker, "a" * 64, marker["delivered_binary_sha256"])
        with self.assertRaises(ValueError):
            check_promotion_acceptance(marker, "e" * 64, marker["delivered_binary_sha256"])
        marker["checks"]["binary_review"] = False
        with self.assertRaises(ValueError):
            check_promotion_acceptance(marker, "a" * 64, marker["delivered_binary_sha256"])

    def test_acceptance_evidence_cannot_escape_project(self):
        for name in ("../escape", "/absolute", "C:/escape", "a\\b", "a//b"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                safe_evidence_name(name)


if __name__ == "__main__":
    unittest.main()
