"""Adversarial archive layouts must fail before any extraction/execution."""
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from archive_m09 import ROOT, members, safe_name


class M09ArchiveBoundaryTests(unittest.TestCase):
    def test_rejects_aliases_and_absolute_paths(self):
        for name in ("../x", "/x", "C:/x", "a\\b", "a/../b", "a//b", "a/./b", "", "x:",
                     "CON", "dir/LPT1.txt", "a. /file", "a./file", "a\0b"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                safe_name(name)

    def archived(self, entries):
        parent = ROOT / 'target'
        parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="m09-archive-boundary-", dir=parent) as folder:
            self.assertTrue(Path(folder).resolve().is_relative_to(parent.resolve()))
            path = Path(folder) / "data.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                for name, kind, size in entries:
                    entry = tarfile.TarInfo(name)
                    entry.type = kind
                    entry.size = size
                    if kind == tarfile.REGTYPE:
                        archive.addfile(entry, io.BytesIO(b"x" * size))
                    else:
                        entry.linkname = "../../outside"
                        archive.addfile(entry)
            return members(path)

    def test_rejects_link_and_duplicate(self):
        for entries in ((('a', tarfile.SYMTYPE, 0),),
                        (('a', tarfile.LNKTYPE, 0),),
                        (('a', tarfile.REGTYPE, 1), ('a', tarfile.REGTYPE, 1))):
            with self.assertRaises(ValueError):
                self.archived(entries)

    def test_rejects_non_file_and_parent_escape(self):
        for entry in (('a', tarfile.DIRTYPE, 0), ('../outside', tarfile.REGTYPE, 1)):
            with self.assertRaises(ValueError):
                self.archived((entry,))

    def test_ordinary_member_retains_exact_bytes(self):
        self.assertEqual(self.archived((('a/b', tarfile.REGTYPE, 3),)), {'a/b': b'xxx'})

    def test_rejects_parent_case_alias_and_file_directory_collision(self):
        for names in (('A/one', 'a/two'), ('a', 'a/two'), ('A/one', 'a/ONE')):
            with self.subTest(names=names), self.assertRaises(ValueError):
                self.archived(tuple((name, tarfile.REGTYPE, 1) for name in names))

    def test_bounds_empty_member_count_and_full_tar_stream(self):
        with patch('archive_m09.MAX_MEMBERS', 1), self.assertRaises(ValueError):
            self.archived((('a', tarfile.REGTYPE, 0), ('b', tarfile.REGTYPE, 0)))
        with patch('archive_m09.MAX_TOTAL', 1), patch('archive_m09.MAX_METADATA', 512), self.assertRaises(ValueError):
            self.archived((('a', tarfile.REGTYPE, 1),))


if __name__ == '__main__':
    unittest.main()
