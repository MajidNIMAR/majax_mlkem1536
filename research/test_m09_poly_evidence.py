"""Tampering and bounded archive checks for the M09 isolated acquisition."""
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from m09_poly_evidence import ROOT, analyze, checked_members, sha, verify


class ArchiveTests(unittest.TestCase):
    def archive(self, names, kind=None):
        temporary = tempfile.TemporaryDirectory(dir=ROOT / "target")
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "test.tar.gz"
        with tarfile.open(path, "w:gz") as stream:
            for name in names:
                info = tarfile.TarInfo(name)
                info.size = 1
                if kind:
                    info.type = kind
                    info.linkname = "elsewhere"
                stream.addfile(info, io.BytesIO(b"x") if not kind else None)
        return path

    def test_traversal_and_absolute_are_rejected(self):
        for name in ("../escape", "/absolute", "a/../escape", "a//b"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                checked_members(self.archive([name]))

    def test_symlinks_and_duplicate_paths_are_rejected(self):
        with self.assertRaises(ValueError):
            checked_members(self.archive(["a"], tarfile.SYMTYPE))
        with self.assertRaises(ValueError):
            checked_members(self.archive(["a", "a"]))

    def test_regular_member_is_read_without_extraction(self):
        self.assertEqual(checked_members(self.archive(["a/b"])), {"a/b": b"x"})


class AcquisitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = ROOT / "results/engine/m09-poly-001"
        cls.members = checked_members(cls.folder / "acquisition.tar.gz")

    def test_real_acquisition_preserves_failed_control(self):
        result = verify(self.folder)
        self.assertEqual(result["observations"], 50_000)
        self.assertFalse(result["all_latency_budgets_passed"])
        self.assertEqual(result["failed_panels"], ["linux/multiply_add"])

    def test_duplicate_observation_rejected_even_with_updated_raw_hash(self):
        members = dict(self.members)
        runs_name = "paired-001-windows-runs.json"
        runs = json.loads(members[runs_name])
        record = runs[0]
        rows = members[record["raw"]].splitlines()
        rows[1] = rows[0]
        members[record["raw"]] = b"\n".join(rows) + b"\n"
        record["raw_sha256"] = sha(members[record["raw"]])
        members[runs_name] = json.dumps(runs).encode()
        with self.assertRaises(ValueError):
            analyze(members)

    def test_modified_table_is_rejected(self):
        members = dict(self.members)
        machine = json.loads(members["machine-review.json"])
        machine["records"][0]["tables"][0]["root"] = 5684
        members["machine-review.json"] = json.dumps(machine).encode()
        with self.assertRaises(ValueError):
            analyze(members)


if __name__ == "__main__":
    unittest.main()
