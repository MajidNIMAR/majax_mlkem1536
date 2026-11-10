"""Release assurance checks: tampering, path safety and real build graph scope."""

import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from verify_m04_distribution import (cargo_lock, check_files, compiled_inventory,
                                     deterministic_tar, digest, native_dependencies, safe_path,
                                     verify_source_archive, compare_compiled_inputs)


class DistributionTests(unittest.TestCase):
    def test_binary_reuse_rejects_any_compilation_input_change(self):
        names = ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml", ".cargo/config.toml",
                 "crates/kem1536/Cargo.toml", "crates/kem1536/src/engine_poly.rs",
                 "crates/kem1536/src/nested/extra.rs", "crates/kem1536/build.rs",
                 "profiles/kem1536-p0.toml", "vectors/nist-acvp/data.json",
                 "references/manifest.json", "fuzz/fixtures/cases.bin"]
        reference = {name: "a" * 64 for name in names}
        reference.update({"crates/kem1536/tests/delivery_contract.rs": "b" * 64,
                          "docs/report.md": "c" * 64, "research/check.py": "d" * 64})
        current = dict(reference)
        for name in ("crates/kem1536/tests/delivery_contract.rs", "docs/report.md", "research/check.py"):
            current[name] = "e" * 64
        self.assertEqual(set(compare_compiled_inputs(reference, current)), set(names))
        for name in names:
            changed = dict(current, **{name: "f" * 64})
            with self.assertRaises(ValueError, msg=name):
                compare_compiled_inputs(reference, changed)
        added = dict(current, **{"crates/kem1536/src/new_module.rs": "a" * 64})
        with self.assertRaises(ValueError):
            compare_compiled_inputs(reference, added)
        removed = dict(current)
        del removed["profiles/kem1536-p0.toml"]
        with self.assertRaises(ValueError):
            compare_compiled_inputs(reference, removed)

    def test_archive_bytes_are_stable_across_paths_and_host_mtimes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("a", "longer-path-b"):
                folder = root / name
                (folder / "bin").mkdir(parents=True)
                (folder / "bin/kem1536").write_bytes(b"synthetic-executable")
                (folder / "NOTICE").write_text("original project notice\n", encoding="utf-8")
                deterministic_tar(folder, root / f"{name}.tar.gz", 1700000000)
            self.assertEqual(digest(root / "a.tar.gz"), digest(root / "longer-path-b.tar.gz"))
            with tarfile.open(root / "a.tar.gz") as archive:
                self.assertEqual(archive.getmember("bin/kem1536").mode, 0o755)
                self.assertEqual(archive.getmember("NOTICE").uid, 0)
            verify_source_archive(root / "a.tar.gz", {"bin/kem1536": digest(root / "a/bin/kem1536"),
                                                       "NOTICE": digest(root / "a/NOTICE")})
            with self.assertRaises(ValueError):
                verify_source_archive(root / "a.tar.gz", {"AGENTS.md": "0" * 64})

    def test_manifest_rejects_mutation_and_extra_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "input.rs"
            target.write_bytes(b"version one")
            manifest = {"input.rs": digest(target)}
            check_files(root, manifest)
            target.write_bytes(b"version two")
            with self.assertRaises(ValueError):
                check_files(root, manifest)
            target.write_bytes(b"version one")
            (root / "unexpected").write_bytes(b"extra")
            with self.assertRaises(ValueError):
                check_files(root, manifest)
            for name in ("../outside", "/absolute", "safe/../../outside"):
                with self.assertRaises(ValueError):
                    safe_path(root, name)

    def test_inventory_separates_proc_macros_and_rejects_research_feature(self):
        packages = [dict(id=name, name=name, version="0.1.0", source=None, license="MIT",
                         targets=[dict(kind=["proc-macro" if name == "derive" else "lib"])])
                    for name in ("kem1536-cli", "kem1536", "derive", "parse")]
        nodes = [dict(id="kem1536-cli", deps=[dict(pkg="kem1536", dep_kinds=[dict(kind=None)])]),
                 dict(id="kem1536", deps=[dict(pkg="derive", dep_kinds=[dict(kind=None)])]),
                 dict(id="derive", deps=[dict(pkg="parse", dep_kinds=[dict(kind=None)])]),
                 dict(id="parse", deps=[])]
        metadata = dict(packages=packages, resolve=dict(nodes=nodes))
        lock = dict(package=[dict(name=p["name"], version=p["version"]) for p in packages])
        messages = "\n".join(json.dumps(dict(reason="compiler-artifact", package_id=p["id"], features=[])) for p in packages)
        inventory = compiled_inventory(metadata, messages, lock)
        categories = {p["name"]: p["category"] for p in inventory}
        self.assertEqual(categories["kem1536"], "normal_dependency_graph")
        self.assertEqual(categories["derive"], "compile_time_only")
        self.assertEqual(categories["parse"], "compile_time_only")
        bad = messages + "\n" + json.dumps(dict(reason="compiler-artifact", package_id="kem1536", features=["research-vectors"]))
        with self.assertRaises(ValueError):
            compiled_inventory(metadata, bad, lock)

    def test_lock_checksums_and_native_prerequisites_are_not_guessed(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "Cargo.lock"
            path.write_text('version = 4\n[[package]]\nname = "a"\nversion = "1.2.3"\nsource = "registry+https://example.invalid"\nchecksum = "abc123"\n', encoding="utf-8")
            self.assertEqual(cargo_lock(path)["package"][0]["checksum"], "abc123")
            path.write_text('[[package]]\nname = "a"\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                cargo_lock(path)
        windows = native_dependencies("DLL Name: KERNEL32.dll\nDLL Name: bcryptprimitives.dll", "windows")
        self.assertEqual(windows["libraries"], ["bcryptprimitives.dll", "KERNEL32.dll"])
        linux = native_dependencies("(NEEDED) Shared library: [libc.so.6]\nGLIBC_2.7 GLIBC_2.35 GLIBC_2.17", "linux")
        self.assertEqual(linux["highest_glibc_version"], "2.35")
        with self.assertRaises(ValueError):
            native_dependencies("empty output", "linux")


if __name__ == "__main__":
    unittest.main()
