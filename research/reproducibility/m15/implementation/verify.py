"""Offline integrity checking or bounded M15 Windows scientific replay.

Use: python -I -S -B research/reproducibility/m15/implementation/verify.py
Use --check-only to check bytes without importing Z3 or executing the proofs.
"""

from __future__ import annotations

import os
import sys

# -B alone still reads existing .pyc. Redirect reads before any local import.
_directory = os.path.dirname(os.path.abspath(__file__))
_repo = os.path.abspath(os.path.join(_directory, "../../../.."))
_cache_prefix = os.path.join(_repo, ".tools", "m15-proof", ".pycache-" + os.urandom(16).hex())
if os.path.lexists(_cache_prefix):
    raise RuntimeError("fresh bytecode prefix unexpectedly exists")
sys.pycache_prefix = _cache_prefix
sys.path.insert(0, _directory)

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import uuid

import package_support as p


def require_isolation() -> None:
    p.require(sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode,
              "invoke with python -I -S -B")


def validate_json_result(label: str, stdout: str, expected: dict) -> dict:
    lines = [line for line in stdout.splitlines() if line.strip()]
    p.require(len(lines) == 1, f"{label}: expected one JSON result")
    value = json.loads(lines[0])
    p.require(isinstance(value, dict) and value == expected,
              f"{label}: result or verification population differs")
    return value


def solver_bootstrap() -> str:
    """Pin both the Python import and native DLL before any scientific import."""
    target = p.safe_path(p.load_lock()["target"])
    native = target / "z3/lib/libz3.dll"
    return (
        "import builtins,ctypes,os\n"
        "from ctypes import wintypes\n"
        "from pathlib import Path\n"
        f"target=Path({str(target)!r})\n"
        f"native=Path({str(native)!r})\n"
        "for key in ('Z3_LIBRARY_PATH','PYTHONPATH'):\n    os.environ.pop(key,None)\n"
        "builtins.Z3_LIB_DIRS=[str(native.parent)]\n"
        "sys.path.insert(0,str(target))\n"
        "original_cdll=ctypes.CDLL\n"
        "mapped_libraries=[]\n"
        "module_filename=ctypes.WinDLL('kernel32',use_last_error=True).GetModuleFileNameW\n"
        "module_filename.argtypes=[wintypes.HMODULE,wintypes.LPWSTR,wintypes.DWORD]\n"
        "module_filename.restype=wintypes.DWORD\n"
        "def pinned_cdll(name,*args,**kwargs):\n"
        "    if Path(name).resolve()!=native.resolve():\n"
        "        raise RuntimeError('non-pinned native solver origin refused')\n"
        "    library=original_cdll(str(native),*args,**kwargs)\n"
        "    buffer=ctypes.create_unicode_buffer(32768)\n"
        "    length=module_filename(library._handle,buffer,len(buffer))\n"
        "    if not 0<length<len(buffer) or Path(buffer.value).resolve()!=native.resolve():\n"
        "        raise RuntimeError('mapped native solver origin differs')\n"
        "    mapped_libraries.append(buffer.value)\n"
        "    return library\n"
        "ctypes.CDLL=pinned_cdll\n"
        "try:\n"
        "    pinned_cdll(str(native))\n"
        "    import z3\n"
        "    import z3.z3core as core\n"
        "finally:\n    ctypes.CDLL=original_cdll\n"
        "assert Path(z3.__file__).resolve()==(target/'z3/__init__.py').resolve()\n"
        "assert Path(core.__file__).resolve()==(target/'z3/z3core.py').resolve()\n"
        "assert len(mapped_libraries)>=2\n"
        "assert all(Path(name).resolve()==native.resolve() for name in mapped_libraries)\n"
    )


def child_code(script: str, arguments: list[str], *, component_tests: bool = False) -> str:
    if component_tests:
        action = (
            "import json,unittest;"
            f"suite=unittest.defaultTestLoader.discover({str(p.BASE)!r},pattern='test_source_model.py');"
            "result=unittest.TextTestRunner(verbosity=2).run(suite);"
            "ok=result.wasSuccessful() and result.testsRun==21 and not result.skipped;"
            "print(json.dumps({'status':'PASS' if ok else 'FAIL','tests':result.testsRun,"
            "'skipped':len(result.skipped),'errors':len(result.errors),'failures':len(result.failures)}));"
            "raise SystemExit(0 if ok else 1)"
        )
    else:
        action = (f"sys.argv={[str(p.BASE / script), *arguments]!r};"
                  f"runpy.run_path({str(p.BASE / script)!r},run_name='__main__')")
    preload = "" if script == "verify_toolchain.py" else solver_bootstrap()
    return ("import runpy,sys\n"
            f"sys.path.insert(0,{str(p.BASE)!r})\n"
            "assert 'z3' not in sys.modules\n" + preload + action)


def run_component(label: str, script: str, arguments: list[str], expected: dict,
                  output: Path, *, component_tests: bool = False) -> dict:
    prefix = p.safe_path(f".tools/m15-proof/.pycache-{uuid.uuid4().hex}")
    p.require(not os.path.lexists(prefix), "child bytecode prefix already exists")
    command = [sys.executable, "-I", "-S", "-B", "-X", f"pycache_prefix={prefix}",
               "-c", child_code(script, arguments, component_tests=component_tests)]
    stdout_path, stderr_path = output / f"{label}.stdout.txt", output / f"{label}.stderr.txt"
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        try:
            completed = subprocess.run(command, cwd=p.ROOT, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, timeout=900, check=False)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError(f"{label}: replay timed out; logs retained") from error
    p.require(completed.returncode == 0, f"{label}: replay failed; logs retained")
    value = validate_json_result(label, stdout_path.read_text(encoding="utf-8"), expected)
    return {"result": value, "isolated_fresh_process": True,
            "old_bytecode_read": False, "stdout_sha256": p.sha(stdout_path),
            "stderr_sha256": p.sha(stderr_path),
            "pinned_solver_origin_checked": script != "verify_toolchain.py"}


def make_output() -> tuple[str, Path]:
    relative = f".tools/m15-proof/replay-receipts/{uuid.uuid4().hex}"
    output = p.safe_path(relative)
    output.mkdir(parents=True, exist_ok=False)
    p.safe_path(relative)
    return relative, output


def write_receipt(output: Path, receipt: dict) -> None:
    path = output / "result.json"
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(receipt, stream, indent=2, sort_keys=True)
        stream.write("\n")


def verify(*, check_only: bool = False) -> dict:
    require_isolation()
    manifest = p.check_package()
    manifest_sha = p.sha(p.BASE / "MANIFEST.json")
    if check_only:
        return {"status": "PASS_INTEGRITY_ONLY", "manifest_sha256": manifest_sha,
                "package_files": len(manifest["files"]), "repository_inputs": 2,
                "network_used": False, "solver_imported": False,
                "mathematical_checks_executed": False, "C01_closed": False}

    p.check_platform()
    # Imported only after all its source bytes have been checked above.
    import setup_windows
    lock = p.load_lock()
    tool = setup_windows.verify_installed(lock)
    relative, output = make_output()
    receipt = {"schema": "m15-local-bounded-replay-v1", "status": "RUNNING",
               "created_utc": datetime.now(timezone.utc).isoformat(),
               "python_version": sys.version.split()[0], "platform": "Windows x86-64",
               "manifest_sha256": manifest_sha, "repository_inputs": manifest["repository_inputs"],
               "solver": tool, "components": {}, "network_used": False,
               "dependency_installation_performed": False, "C01_closed": False,
               "fresh_checkout_validation": False, "hosted_CI_validation": False,
               "scope": manifest["scope"], "receipt": f"{relative}/result.json"}
    try:
        jobs = [
            ("toolchain", "verify_toolchain.py", [], {"status": "PASS", "package_members": 34}, False),
            ("arithmetic", "prove.py", ["verify"],
             {"status": "PASS_SCOPED", "obligations": 31, "C01_closed": False}, False),
            ("ntt", "ntt_certificate.py", ["verify"],
             {"status": "PASS_SCOPED", "checked_linear_coefficients": 131072}, False),
            ("components", "test_source_model.py", [],
             {"status": "PASS", "tests": 21, "skipped": 0, "errors": 0, "failures": 0}, True),
        ]
        for label, script, arguments, expected, tests in jobs:
            print(f"Checking {label}...", file=sys.stderr, flush=True)
            receipt["components"][label] = run_component(label, script, arguments, expected,
                                                          output, component_tests=tests)
        p.require(p.check_package() == manifest and p.sha(p.BASE / "MANIFEST.json") == manifest_sha,
                  "payload or repository inputs changed during replay")
        p.require(setup_windows.verify_installed(lock) == tool, "solver changed during replay")
        receipt.update(status="PASS_SCOPED", inputs_unchanged=True,
                       mathematical_checks_executed=True)
    except Exception as error:
        receipt.update(status="FAIL", error=str(error), mathematical_checks_executed=True)
        write_receipt(output, receipt)
        raise RuntimeError(f"bounded replay failed; see {relative}/result.json") from error
    write_receipt(output, receipt)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-only", action="store_true",
                        help="Offline input integrity only; no mathematical replay and no Z3 import.")
    arguments = parser.parse_args()
    try:
        result = verify(check_only=arguments.check_only)
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print(f"M15 verification failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
