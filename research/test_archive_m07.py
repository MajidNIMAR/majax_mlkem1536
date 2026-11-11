"""Archive boundary and mutation checks; no cryptographic executable is run."""
import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import archive_m07 as archive


class M07ArchiveTests(unittest.TestCase):
    def setUp(self):
        parent = Path(__file__).resolve().parents[1] / "target"
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="m07-archive-test-", dir=parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "empty-failures").mkdir()
        (self.source / "Z-upper-case").mkdir()
        (self.source / "nested").mkdir()
        (self.source / "nested/data.bin").write_bytes(b"\0\xff\r\n\n")

    def fixture(self):
        path = self.root / "evidence.tar.gz"
        return path, archive.pack(self.source, path)

    def malicious(self, infos):
        path = self.root / "malicious.tar.gz"
        with tarfile.open(path, "w:gz") as tar:
            for name, kind in infos:
                info = tarfile.TarInfo(name)
                info.type = kind
                if kind == tarfile.SYMTYPE:
                    info.linkname = "../../outside"
                tar.addfile(info, io.BytesIO(b""))
        record = {"archive_sha256": archive.sha(path), "files": {}, "directories": []}
        return path, record

    def test_roundtrip_preserves_bytes_empty_directories_and_determinism(self):
        path, record = self.fixture()
        archive.unpack(path, record, self.root / "decoded")
        self.assertEqual(archive.inventory(self.root / "decoded"), archive.inventory(self.source))
        second = self.root / "second.tar.gz"
        archive.pack(self.source, second)
        self.assertEqual(path.read_bytes(), second.read_bytes())

    def test_rejects_tampered_archive_and_member_digest(self):
        path, record = self.fixture()
        record["files"]["nested/data.bin"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "checksum"):
            archive.unpack(path, record, self.root / "changed-member")
        path.write_bytes(path.read_bytes() + b"extra")
        with self.assertRaisesRegex(ValueError, "checksum"):
            archive.unpack(path, record, self.root / "changed-archive")

    def test_rejects_traversal_even_when_listed(self):
        path, record = self.malicious([("../outside", tarfile.REGTYPE)])
        record["files"]["../outside"] = {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
        with self.assertRaisesRegex(ValueError, "unsafe"):
            archive.unpack(path, record, self.root / "traversal")
        self.assertFalse((self.root / "outside").exists())

    def test_rejects_symlink_even_when_listed_as_file(self):
        path, record = self.malicious([("link", tarfile.SYMTYPE)])
        record["files"]["link"] = {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
        with self.assertRaisesRegex(ValueError, "regular"):
            archive.unpack(path, record, self.root / "links")

    def test_rejects_duplicate_tar_members(self):
        path, record = self.malicious([("data", tarfile.REGTYPE), ("data", tarfile.REGTYPE)])
        record["files"]["data"] = {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
        with self.assertRaisesRegex(ValueError, "duplicate"):
            archive.unpack(path, record, self.root / "duplicate")

    def test_rejects_case_aliases_and_missing_inventory_entries(self):
        path, record = self.fixture()
        record["directories"].append("NESTED")
        with self.assertRaisesRegex(ValueError, "case-aliasing"):
            archive.unpack(path, record, self.root / "alias")
        record["directories"].remove("NESTED")
        del record["files"]["nested/data.bin"]
        with self.assertRaisesRegex(ValueError, "unlisted"):
            archive.unpack(path, record, self.root / "omitted")

    def test_rejects_declared_decompression_budget_and_unsafe_names(self):
        path, record = self.fixture()
        record["files"]["nested/data.bin"]["bytes"] = archive.MAX_BYTES + 1
        with self.assertRaisesRegex(ValueError, "byte budget"):
            archive.unpack(path, record, self.root / "oversize")
        for name in ("C:/outside", "/absolute", "a\\b", "a/../b", "CON.txt", "a/", "a. /b", "COM\u00b9.txt", "lpt\u00b2"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                archive.safe_name(name)

    def test_bounds_extended_metadata_before_tarfile_parses_it(self):
        path = self.root / "pax.tar.gz"
        with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as tar:
            info = tarfile.TarInfo("data")
            info.pax_headers = {"comment": "x" * 100000}
            tar.addfile(info, io.BytesIO(b""))
        record = {"archive_sha256": archive.sha(path), "directories": [],
                  "files": {"data": {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}}}
        with patch.object(archive, "METADATA_BYTES", 16384), self.assertRaisesRegex(ValueError, "decompressed"):
            archive.unpack(path, record, self.root / "pax")

    def test_bounds_member_count_before_extraction(self):
        path, record = self.fixture()
        with patch.object(archive, "MAX_MEMBERS", 1), self.assertRaisesRegex(ValueError, "member count"):
            archive.unpack(path, record, self.root / "many")


if __name__ == "__main__":
    unittest.main()
