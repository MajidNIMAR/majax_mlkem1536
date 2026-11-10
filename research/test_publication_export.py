"""Publication checks exercise tiny owned Git fixtures, never the real public clone."""

from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import export_publication as publication


PROJECT = Path(__file__).resolve().parents[1]


def git(root, *arguments, content=None):
    return subprocess.check_output(
        ["git", *arguments], cwd=root, input=content, stderr=subprocess.PIPE,
    )


def write(root, name, content):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def commit(root, message="fixture"):
    git(root, "add", "--all")
    git(root, "-c", "user.name=Publication test", "-c", "user.email=publication@example.invalid",
        "-c", "commit.gpgsign=false", "commit", "-m", message)
    return git(root, "rev-parse", "HEAD").decode("ascii").strip()


class PublicationExportTests(unittest.TestCase):
    def setUp(self):
        # TemporaryDirectory owns only a verified child of this project's target/.
        parent = PROJECT / "target"
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent, prefix="publication-export-test-")
        self.fixture = Path(self.temporary.name).resolve()
        if self.fixture.parent != parent.resolve():
            raise ValueError("refusing a test fixture outside the owned target directory")
        self.addCleanup(self.temporary.cleanup)
        self.source = self.fixture / "source"
        self.source.mkdir()
        git(self.source, "init", "--quiet")
        git(self.source, "config", "core.autocrlf", "false")
        write(self.source, ".gitignore", b"/publication/\n/artifacts/generated/\n/cache/\n")
        write(self.source, "README.md", b"committed research\n")
        write(self.source, "fuzz/fixtures/cases.bin", b"\0\xff\r\n\x01")
        for name in publication.EXCLUDED:
            write(self.source, name, b"private fixture\n")
        self.source_commit = commit(self.source)
        self.root_patch = patch.object(publication, "ROOT", self.source)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.destination = self.source / "artifacts/generated/publication/snapshot"

    def run_export(self, destination=None, **kwargs):
        with redirect_stdout(io.StringIO()):
            return publication.export(destination or self.destination, **kwargs)

    def public_checkout(self):
        destination = self.source / "publication/public-research"
        destination.mkdir(parents=True)
        git(destination, "init", "--quiet")
        git(destination, "config", "core.autocrlf", "false")
        git(destination, "remote", "add", "origin", "https://example.invalid/original-history.git")
        write(destination, ".gitignore", b"cache/\n")
        write(destination, "README.md", b"historical public work\n")
        write(destination, publication.PROVENANCE, b"{}\n")
        public_commit = commit(destination, "original public author and history")
        return destination, public_commit

    def test_export_is_committed_bytes_with_private_exclusions_and_no_zip(self):
        write(self.source, "cache/local", b"ignored local state")
        result = self.run_export()
        self.assertEqual(result["commit"], self.source_commit)
        self.assertEqual((self.destination / "README.md").read_bytes(), b"committed research\n")
        self.assertEqual((self.destination / "fuzz/fixtures/cases.bin").read_bytes(), b"\0\xff\r\n\x01")
        provenance = json.loads((self.destination / publication.PROVENANCE).read_text("utf-8"))
        self.assertEqual(provenance["local_source_commit"], self.source_commit)
        self.assertEqual(provenance["profile"], "KEM1536-DEV-Q7681-R1")
        self.assertEqual(set(provenance["excluded_paths"]), publication.EXCLUDED)
        for name in publication.EXCLUDED - {publication.PROVENANCE}:
            self.assertFalse((self.destination / name).exists(), name)
        for name, expected in provenance["sha256"].items():
            self.assertEqual(hashlib.sha256((self.destination / name).read_bytes()).hexdigest(), expected)
        self.assertFalse((self.destination / ".git").exists())
        self.assertEqual(list(self.destination.parent.iterdir()), [self.destination])

    def test_source_dirty_or_untracked_requires_a_commit_before_any_write(self):
        for name in ("README.md", "new-research.txt"):
            with self.subTest(path=name):
                write(self.source, name, b"uncommitted new work\n")
                with self.assertRaisesRegex(ValueError, "source worktree must be clean"):
                    self.run_export()
                self.assertFalse(self.destination.exists())
                commit(self.source, "finish fixture change")

    def test_sync_preserves_public_history_author_remote_and_git_database(self):
        destination, previous = self.public_checkout()
        git_before = {name: (destination / ".git" / name).read_bytes()
                      for name in ("HEAD", "config")}
        author_before = git(destination, "show", "-s", "--format=%an <%ae>", previous)
        write(destination, "cache/keep", b"ignored public cache")
        result = self.run_export(destination, sync=True)
        self.assertTrue(result["sync"])
        self.assertEqual(git(destination, "rev-parse", "HEAD").decode("ascii").strip(), previous)
        self.assertEqual(git(destination, "show", "-s", "--format=%an <%ae>", previous), author_before)
        for name, content in git_before.items():
            self.assertEqual((destination / ".git" / name).read_bytes(), content)
        self.assertEqual((destination / "README.md").read_bytes(), b"committed research\n")
        self.assertEqual((destination / "cache/keep").read_bytes(), b"ignored public cache")
        provenance = json.loads((destination / publication.PROVENANCE).read_text("utf-8"))
        self.assertEqual(provenance["previous_public_commit"], previous)
        self.assertEqual(provenance["local_source_commit"], self.source_commit)
        self.assertTrue(git(destination, "status", "--porcelain"))

    def test_sync_refuses_dirty_staged_and_untracked_public_work(self):
        for state in ("modified", "staged", "untracked"):
            with self.subTest(state=state):
                destination, previous = self.public_checkout()
                name = "notes.txt" if state == "untracked" else "README.md"
                write(destination, name, b"local public work\n")
                if state == "staged":
                    git(destination, "add", "README.md")
                with self.assertRaisesRegex(ValueError, "public worktree must be clean"):
                    self.run_export(destination, sync=True)
                self.assertEqual((destination / name).read_bytes(), b"local public work\n")
                self.assertEqual(git(destination, "rev-parse", "HEAD").decode("ascii").strip(), previous)
                # Each subcase gets a separate owned public clone name.
                destination.rename(destination.with_name("finished-" + state))

    def test_sync_refuses_stale_tracked_files_without_deleting_them(self):
        destination, _ = self.public_checkout()
        write(destination, "obsolete.txt", b"review before removal")
        previous = commit(destination)
        with self.assertRaisesRegex(ValueError, "stale tracked.*obsolete.txt"):
            self.run_export(destination, sync=True)
        self.assertEqual((destination / "obsolete.txt").read_bytes(), b"review before removal")
        self.assertEqual((destination / "README.md").read_bytes(), b"historical public work\n")
        self.assertEqual(git(destination, "rev-parse", "HEAD").decode("ascii").strip(), previous)

    def test_sync_refuses_ignored_files_that_would_be_overwritten(self):
        destination, _ = self.public_checkout()
        write(destination, ".gitignore", b"cache/\nfuzz/\n")
        commit(destination)
        write(destination, "fuzz/fixtures/cases.bin", b"untracked ignored private data")
        with self.assertRaisesRegex(ValueError, "ignored/untracked public file"):
            self.run_export(destination, sync=True)
        self.assertEqual((destination / "fuzz/fixtures/cases.bin").read_bytes(), b"untracked ignored private data")

    def test_sync_refuses_hard_link_before_any_write(self):
        destination, _ = self.public_checkout()
        sentinel = self.fixture / "outside-file.txt"
        os.link(destination / "README.md", sentinel)
        with self.assertRaisesRegex(ValueError, "hard links"):
            self.run_export(destination, sync=True)
        self.assertEqual(sentinel.read_bytes(), b"historical public work\n")

    def test_source_git_symlink_is_refused_without_needing_os_symlink_privileges(self):
        # The index can encode a link even on Windows without Developer Mode.
        oid = git(self.source, "hash-object", "-w", "--stdin", content=b"README.md").decode("ascii").strip()
        write(self.source, "link.txt", b"README.md")
        git(self.source, "update-index", "--add", "--cacheinfo", f"120000,{oid},link.txt")
        git(self.source, "-c", "user.name=Publication test", "-c", "user.email=publication@example.invalid",
            "-c", "commit.gpgsign=false", "commit", "-m", "tracked link fixture")
        # Windows core.symlinks=false leaves the link target as a regular file;
        # on Unix a mocked clean gate lets the committed mode be tested directly.
        head = git(self.source, "rev-parse", "HEAD").decode("ascii").strip()
        with patch.object(publication, "clean_head", return_value=head):
            with self.assertRaisesRegex(ValueError, "Git links"):
                self.run_export()
        self.assertFalse(self.destination.exists())

    def test_destination_ownership_and_existing_snapshot_are_enforced(self):
        invalid = [self.fixture / "outside", self.source / "publication",
                   self.source / "publication/child/nested", self.source,
                   self.source / "publication/child/../other"]
        for destination in invalid:
            with self.subTest(path=destination), self.assertRaises(ValueError):
                self.run_export(destination, sync=True)
        with self.assertRaises(ValueError):
            self.run_export(self.source / "publication/new")
        self.run_export()
        with self.assertRaises(FileExistsError):
            self.run_export()

    def test_path_validation_refuses_traversal_git_aliases_and_windows_devices(self):
        invalid = ("../escape", "/absolute", "a/../b", "a//b", "a\\b", "C:/escape",
                   ".git/config", "A/.GIT/config", "git~1/config", "A./file", "NUL.txt")
        for name in invalid:
            with self.subTest(name=name), self.assertRaises(ValueError):
                publication.safe_name(name)
        self.assertEqual(publication.safe_name("research/safe-name.py"), ["research", "safe-name.py"])


if __name__ == "__main__":
    unittest.main()
