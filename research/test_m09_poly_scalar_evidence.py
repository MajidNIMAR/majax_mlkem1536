"""Independent checks reject wrong panel/CPU-warning and vectorized evidence."""
import json
import unittest

from m09_poly_scalar_evidence import ROOT, analyze, archive_members, sha, verify_archive


class ScalarEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = ROOT / "results/engine/m09-poly-002"
        cls.members = archive_members(cls.folder / "acquisition.tar.gz")

    def test_real_preserved_acquisition(self):
        result = verify_archive(self.folder)
        self.assertEqual(result["observations"], 40_000)
        self.assertTrue(result["KEM_latency_budgets_passed"])
        self.assertEqual(result["failed_KEM_panels"], [])
        self.assertTrue(all(result["five_percent_gain_per_host"].values()))

    def test_unclassified_stderr_is_rejected(self):
        members = dict(self.members)
        members["windows-0-candidate-micro.stderr"] = b"unexpected runtime warning\n"
        with self.assertRaises(ValueError):
            analyze(members)

    def test_vector_register_in_transform_is_rejected(self):
        members = dict(self.members)
        members["candidate/windows/transform.txt"] += b"\n movdqa %xmm8, 0x10(%rsp)\n"
        with self.assertRaises(ValueError):
            analyze(members)

    def test_reordered_AB_BA_panel_is_rejected(self):
        members = dict(self.members)
        records = json.loads(members["windows-runs.json"])
        records[0], records[1] = records[1], records[0]
        members["windows-runs.json"] = json.dumps(records).encode()
        with self.assertRaises(ValueError):
            analyze(members)

    def test_duplicate_duration_rejected_despite_updated_hash(self):
        members = dict(self.members)
        runs = json.loads(members["windows-runs.json"])
        record = runs[2]
        rows = members[record["raw"]].splitlines()
        rows[1] = rows[0]
        members[record["raw"]] = b"\n".join(rows) + b"\n"
        record["raw_sha256"] = sha(members[record["raw"]])
        members["windows-runs.json"] = json.dumps(runs).encode()
        with self.assertRaises(ValueError):
            analyze(members)


if __name__ == "__main__":
    unittest.main()
