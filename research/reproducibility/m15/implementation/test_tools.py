"""Focused negative tests for packaging tools (separate from 21 science tests).

Run after setup using the command in README.md. Fixtures stay in the ignored
local tool cache; no research receipt or original scientific input is edited.
"""

import hashlib
import json
import os
from pathlib import Path
import py_compile
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

_base = Path(__file__).resolve().parent
_prefix = _base.parents[3] / ".tools/m15-proof" / (".pycache-" + os.urandom(16).hex())
if os.path.lexists(_prefix):
    raise RuntimeError("fresh bytecode prefix unexpectedly exists")
sys.pycache_prefix = str(_prefix)
sys.path.insert(0, str(_base))

import package_support as p
import setup_windows as setup
import verify as driver


class ToolsTests(unittest.TestCase):
    def setUp(self):
        owner = p.safe_path(".tools/m15-proof/support-fixtures")
        owner.mkdir(parents=True, exist_ok=True)
        self.root = Path(tempfile.mkdtemp(prefix="case-", dir=owner))
        p.require(self.root.resolve().is_relative_to(owner.resolve()), "fixture outside owner")

    def wheel(self):
        members = {"z3/__init__.py": b"# synthetic solver fixture\n",
                   "z3/lib/libz3.dll": b"not an executable: extraction fixture only\n"}
        cache = self.root / ".tools/m15-proof/fixture.whl"
        cache.parent.mkdir(parents=True)
        with zipfile.ZipFile(cache, "w") as archive:
            for name, raw in members.items():
                archive.writestr(name, raw)
        lock = {"version": "4.15.4.0", "cache_relative": ".tools/m15-proof/fixture.whl",
                "target": ".tools/m15-proof/site-packages", "wheel_bytes": cache.stat().st_size,
                "wheel_sha256": p.sha(cache), "expected_members_sha256":
                {name: hashlib.sha256(raw).hexdigest() for name, raw in members.items()}}
        return lock, cache, self.root / lock["target"]

    def payload(self):
        base = self.root / "research/reproducibility/m15/implementation"
        base.mkdir(parents=True)
        (base / "input.txt").write_bytes(b"scientific fixture\n")
        inputs = {}
        for name in ("crates/kem1536/src/dev_kem.rs", "crates/kem1536/src/engine_poly.rs"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"source fixture\n")
            inputs[name] = {"bytes": path.stat().st_size, "sha256": p.sha(path)}
        manifest = {"schema": p.MANIFEST_SCHEMA,
                    "files": {"input.txt": {"bytes": (base / "input.txt").stat().st_size,
                                             "sha256": p.sha(base / "input.txt")}},
                    "repository_inputs": inputs, "scope": {"arithmetic_obligations": 31,
                    "ntt_linear_coefficients": 131072, "component_tests": 21, "C01_closed": False}}
        (base / "MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
        return base

    def check_fixture(self, base):
        with patch.object(p, "BASE", base), patch.object(p, "ROOT", self.root), patch.object(p, "load_lock", return_value={}):
            return p.check_package()

    def test_relative_paths_reject_aliases_and_traversal(self):
        for name in ("../x", "/x", "a/../x", "a//x", "./x", "a\\x", "C:/x", "NUL.txt", "a. /x"):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                p.safe_path(name, self.root)

    def test_duplicate_json_key_is_refused(self):
        path = self.root / "duplicate.json"
        path.write_text('{"key":1,"key":2}')
        with self.assertRaises(RuntimeError):
            p.read_json(path)

    def test_reparse_point_is_refused(self):
        real_lstat = Path.lstat
        node = self.root / "junction"
        node.mkdir()
        class Reparse:
            st_mode = 0o040777
            st_file_attributes = 0x400
        def lstat(path, *args, **kwargs):
            return Reparse() if path == node else real_lstat(path, *args, **kwargs)
        with patch.object(Path, "lstat", lstat), self.assertRaises(RuntimeError):
            p.safe_path("junction/child", self.root)

    def test_manifest_valid_fixture(self):
        self.assertEqual(self.check_fixture(self.payload())["scope"]["component_tests"], 21)

    def test_modified_payload_is_refused(self):
        base = self.payload()
        (base / "input.txt").write_bytes(b"changed fixture\n")
        with self.assertRaises(RuntimeError):
            self.check_fixture(base)

    def test_extra_module_is_refused(self):
        base = self.payload()
        (base / "z3.py").write_bytes(b"# unexpected module\n")
        with self.assertRaises(RuntimeError):
            self.check_fixture(base)

    def test_modified_repository_input_is_refused(self):
        base = self.payload()
        (self.root / "crates/kem1536/src/dev_kem.rs").write_bytes(b"different source\n")
        with self.assertRaises(RuntimeError):
            self.check_fixture(base)

    def test_cached_wheel_corruption_is_refused(self):
        lock, cache, target = self.wheel()
        cache.write_bytes(cache.read_bytes() + b"corrupt")
        with self.assertRaises(RuntimeError):
            setup._validate_wheel(lock, cache)
        self.assertFalse(target.exists())

    def test_extraction_and_installed_member_verification(self):
        lock, cache, target = self.wheel()
        with patch.object(p, "ROOT", self.root):
            expected = setup._validate_wheel(lock, cache)
            setup._extract(lock, target, cache, expected)
            result = setup.verify_installed(lock)
        self.assertEqual(result["validated_package_files"], 2)
        self.assertFalse(result["solver_imported"])

    def test_installed_extra_module_is_refused(self):
        lock, cache, target = self.wheel()
        with patch.object(p, "ROOT", self.root):
            setup._extract(lock, target, cache, setup._validate_wheel(lock, cache))
            (target / "z3/extra.py").write_bytes(b"# unexpected module\n")
            with self.assertRaises(RuntimeError):
                setup.verify_installed(lock)

    def test_installed_corruption_is_refused(self):
        lock, cache, target = self.wheel()
        with patch.object(p, "ROOT", self.root):
            setup._extract(lock, target, cache, setup._validate_wheel(lock, cache))
            (target / "z3/lib/libz3.dll").write_bytes(b"changed")
            with self.assertRaises(RuntimeError):
                setup.verify_installed(lock)

    def test_existing_unknown_target_is_not_overwritten(self):
        lock, cache, target = self.wheel()
        target.mkdir()
        sentinel = target / "sentinel.txt"
        sentinel.write_bytes(b"preserve this")
        with patch.object(p, "ROOT", self.root), self.assertRaises(RuntimeError):
            setup._extract(lock, target, cache, setup._validate_wheel(lock, cache))
        self.assertEqual(sentinel.read_bytes(), b"preserve this")

    def test_offline_setup_never_downloads(self):
        lock = {"cache_relative": ".tools/m15-proof/missing.whl", "target": ".tools/m15-proof/site-packages"}
        with patch.object(p, "ROOT", self.root), patch.object(p, "check_platform"), \
             patch.object(p, "check_package"), patch.object(p, "load_lock", return_value=lock), \
             patch.object(setup, "_download", side_effect=AssertionError("network forbidden")):
            with self.assertRaisesRegex(RuntimeError, "offline"):
                setup.ensure_setup(allow_download=False)

    def test_zero_unknown_or_extra_results_are_refused(self):
        expected = {"status": "PASS", "tests": 21}
        for raw in ('{"status":"PASS","tests":0}', '{"status":"UNKNOWN","tests":21}',
                    '{"status":"PASS","tests":21}\n{}'):
            with self.subTest(raw=raw), self.assertRaises(RuntimeError):
                driver.validate_json_result("fixture", raw, expected)

    def test_child_failure_keeps_logs_and_fails(self):
        script = self.root / "verify_toolchain.py"
        script.write_text("raise SystemExit(7)\n")
        output = self.root / "logs"
        output.mkdir()
        with patch.object(p, "BASE", self.root), self.assertRaises(RuntimeError):
            driver.run_component("failed", script.name, [], {}, output)
        self.assertTrue((output / "failed.stderr.txt").is_file())

    def test_child_ignores_ambient_pythonpath_and_old_bytecode(self):
        module = self.root / "helper.py"
        # Timestamp and size deliberately match to make the stale pyc valid
        # for a normal import. A fresh pycache_prefix must select source bytes.
        module.write_text('value="OLD"\n')
        stamp = module.stat().st_mtime
        with patch.object(sys, "pycache_prefix", None):
            py_compile.compile(str(module), doraise=True)
        module.write_text('value="NEW"\n')
        os.utime(module, (stamp, stamp))
        poisoned = self.root / "ambient"
        poisoned.mkdir()
        (poisoned / "ambient_marker.py").write_text("raise RuntimeError('ambient import')\n")
        script = self.root / "verify_toolchain.py"
        script.write_text("import helper,importlib.util,json,sys\n"
                          "print(json.dumps({'value':helper.value,'ambient':importlib.util.find_spec('ambient_marker') is not None,"
                          "'isolated':bool(sys.flags.isolated),'no_site':bool(sys.flags.no_site)}))\n")
        output = self.root / "logs"
        output.mkdir()
        expected = {"value": "NEW", "ambient": False, "isolated": True, "no_site": True}
        with patch.object(p, "BASE", self.root), patch.dict(os.environ, {"PYTHONPATH": str(poisoned)}):
            result = driver.run_component("isolation", script.name, [], expected, output)
        self.assertEqual(result["result"], expected)

    def test_invalid_platform_is_refused(self):
        with patch.object(sys, "platform", "linux"), self.assertRaises(RuntimeError):
            p.check_platform()

    def test_check_only_does_not_import_or_check_solver(self):
        # check-only still invokes real package integrity in normal use; here
        # the package check is bounded to a small fixture to inspect control flow.
        manifest = {"files": {"fixture": {}}, "repository_inputs": {}}
        (self.root / "MANIFEST.json").write_bytes(b"{}")
        with patch.object(p, "BASE", self.root), patch.object(p, "check_package", return_value=manifest), \
             patch.object(setup, "verify_installed", side_effect=AssertionError("solver touched")), \
             patch.object(p, "check_platform", side_effect=AssertionError("platform touched")):
            result = driver.verify(check_only=True)
        self.assertEqual(result["status"], "PASS_INTEGRITY_ONLY")
        self.assertFalse(result["solver_imported"])
        self.assertFalse(result["mathematical_checks_executed"])


if __name__ == "__main__":
    driver.require_isolation()
    unittest.main(verbosity=2)
