"""Post-capture M09 validation adapter; never changes the captured controller.

Pins the live controls to their compiled-source capture, copies the historical
inputs actually read, and retains before/after receipts even when a child fails.
It coordinates new validate/timing runs only; it grants no historical credit.
"""
import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
INPUTS = (
    "results/engine/r1-001/sources/research/kem_r1_reference.py",
    "results/engine/r1-001/vectors.jsonl.gz",
    "results/engine/r1-001/provenance.json",
    "results/engine/r1-rejections-001/rejections.jsonl.gz",
    "results/engine/r1-rejections-001/provenance.json",
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def utc():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024*1024), b""):
            value.update(block)
    return value.hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write_new(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def inventory(folder):
    return {p.relative_to(folder).as_posix(): sha(p) for p in sorted(folder.rglob("*")) if p.is_file()}


def names_in_capture(controller):
    tree = ast.parse(Path(controller).read_text(encoding="utf-8-sig"))
    values = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
              and any(isinstance(name, ast.Name) and name.id == "CONTROLS" for name in node.targets)]
    require(len(values) == 1 and isinstance(values[0], (tuple, list)), "captured CONTROLS tuple missing")
    names = list(values[0])
    require(len(names) == len(set(names)) and all(isinstance(name, str) and Path(name).name == name
            and name.endswith(".py") for name in names), "unsafe/duplicate control name")
    require("run_m09_qualification.py" in names, "controller must bind itself")
    return names


def bind_controls(root, out):
    source = read(out / "source.json")
    require(inventory(out / "source") == source["source_sha256"], "captured source inventory differs")
    names = names_in_capture(out / "source/research/run_m09_qualification.py")
    records = {}
    for name in names:
        relative = "research/"+name
        observed = sha(root / relative)
        expected = source["source_sha256"][relative]
        require(observed == expected, "live control differs from captured control: "+name)
        records[relative] = observed
    # Include every statically imported local helper, including function-local
    # imports. No arbitrary source is imported to discover this closure.
    for relative in records:
        tree = ast.parse((root / relative).read_text(encoding="utf-8-sig"))
        modules = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                modules.append(node.module.split(".")[0])
            elif isinstance(node, ast.Import):
                modules.extend(alias.name.split(".")[0] for alias in node.names)
        for module in modules:
            local = root / "research" / (module+".py")
            if local.is_file():
                require("research/"+local.name in records, "uncaptured local helper: "+local.name)
    return dict(source_manifest_sha256=sha(out / "source.json"), controls_sha256=records)


def historical_inputs(root):
    hashes = {name: sha(root / name) for name in INPUTS}
    first = read(root / "results/engine/r1-001/provenance.json")
    rejection = read(root / "results/engine/r1-rejections-001/provenance.json")
    oracle = INPUTS[0]
    require(first["input_sha256"][oracle] == hashes[oracle], "M01 oracle provenance differs")
    require(first["output_sha256"]["vectors.jsonl.gz"] == hashes[INPUTS[1]], "M01 vector provenance differs")
    require(rejection["input_sha256"][oracle] == hashes[oracle], "rejection oracle provenance differs")
    require(rejection["input_sha256"][INPUTS[2]] == hashes[INPUTS[2]], "M01 provenance linkage differs")
    require(rejection["output_sha256"]["rejections.jsonl.gz"] == hashes[INPUTS[3]], "rejection vector provenance differs")
    return hashes


def copy_inputs(root, out):
    hashes = historical_inputs(root)
    destination = out / "validation-inputs"
    if destination.exists():
        require(inventory(destination) == hashes, "existing copied inputs differ")
    else:
        destination.mkdir()
        for name in INPUTS:
            target = destination / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / name, target)
        require(inventory(destination) == hashes, "copied input bytes differ")
    return hashes


def runtime():
    import numpy as np
    require(np.__version__ == "2.3.5", "pinned NumPy 2.3.5 required")
    native = __import__("numpy._core._multiarray_umath", fromlist=["__file__"])
    files = [Path(sys.executable), Path(np.__file__), Path(native.__file__)]
    return dict(python=sys.version, executable=sys.executable, numpy_version=np.__version__,
                platform=platform.platform(), machine=platform.machine(),
                selected_runtime_file_sha256={str(path): sha(path) for path in files},
                full_python_native_dependency_closure_claimed=False)


def check_validation_outputs(out):
    summary = read(out / "validation.json")
    require(summary["source_manifest_sha256"] == sha(out / "source.json"), "validation/source mismatch")
    counts = {}
    for host in ("windows", "linux"):
        folder = out / "validation" / host
        smoke = read(folder / "consumer-smoke.stdout")
        exhaustive = read(folder / "consumer-exhaustive.stdout")
        require(smoke["schema"] == 1 and smoke["profile"] == "KEM1536-DEV-Q7681-R1"
                and smoke["fresh_imported_key_round_trips"] == smoke["fresh_rejections"] == 1
                and smoke["repeat_rejection_equal"] is True and smoke["secrets_printed"] is False,
                "consumer smoke counters/scope differ")
        cases = smoke["cases"]
        require(len(cases) == 13 and len({row["operation"] for row in cases}) == 13
                and all(row["status"] == row["expected"] for row in cases), "consumer cases differ")
        require(exhaustive["schema"] == 1 and exhaustive["profile"] == "KEM1536-DEV-Q7681-R1"
                and exhaustive["single_coefficient_value_alignment_cases"] == 65536
                and exhaustive["boundary_position_cases"] == 23040 and exhaustive["total_cases"] == 88576
                and exhaustive["all_expected_statuses_and_accepted_encodings_match"] is True
                and exhaustive["complete_vector_space_exhausted"] is False
                and exhaustive["formal_program_verification"] is False
                and exhaustive["secrets_printed"] is False, "consumer exhaustive counters/scope differ")
        formats = read(folder / "formats.stdout")
        require(formats["inputs"] == 20000 and formats["panics_observed"] == 0
                and [formats[name] for name in ("public_key_imports", "private_key_imports", "ciphertext_imports")]
                == [6667, 6667, 6666]
                and formats["wrong_lengths_rejected"]+formats["exact_length_inputs"] == 20000
                and 0 <= formats["accepted_imports"] <= formats["exact_length_inputs"], "format counters differ")
        counts[host] = dict(consumer_cases=13, exhaustive_probes=88576, formats=20000)
    return counts


def execute(out, action, cpu=10, root=ROOT):
    require(action in ("validate", "timing"), "only validation/timing allowed")
    require(type(cpu) is int and cpu >= 0, "nonnegative CPU index required")
    out, root = Path(out).resolve(), Path(root).resolve()
    require(out.parent == root / "artifacts/generated", "direct generated qualification output required")
    receipts = out / "qualification-adapter" / (action+"-001")
    receipts.mkdir(parents=True, exist_ok=False)
    command = [sys.executable, "-B", str(root / "research/run_m09_qualification.py"), action,
               "--output", str(out), "--cpu", str(cpu)]
    write_new(receipts / "request.json", dict(action=action, requested_utc=utc(), command=command,
              purpose="new M09 acquisition, no captured control or historical evidence rewritten"))
    before, child_exit, error = None, None, None
    try:
        require(not (out / action.replace("validate", "validation")).exists(), "phase output already exists")
        if action == "validate":
            require(not (out / "validation.json").exists(), "validation result already exists")
        controls = bind_controls(root, out)
        inputs = copy_inputs(root, out)
        adapter = Path(__file__).resolve()
        shutil.copyfile(adapter, receipts / "adapter.py")
        before = dict(started_utc=utc(), binding=controls, historical_input_sha256=inputs,
                      adapter_sha256=sha(adapter), runtime=runtime())
        write_new(receipts / "before.json", before)
        with (receipts / "stdout.log").open("xb") as stdout, (receipts / "stderr.log").open("xb") as stderr:
            process = subprocess.run(command, cwd=root, stdout=stdout, stderr=stderr)
        child_exit = process.returncode
        require(child_exit == 0, "qualification child exited "+str(child_exit))
        if action == "validate":
            write_new(receipts / "finite-postchecks.json", check_validation_outputs(out))
        else:
            reports = {host: read(out / "timing" / host / "analysis.json") for host in ("windows", "linux")}
            require(all(row["observations"] == 16000 for row in reports.values()), "timing counts differ")
            write_new(receipts / "timing-postchecks.json", dict(
                reports=reports, requires_investigation=any(row["threshold_crossings"] for row in reports.values()),
                constant_time_proved=False))
    except BaseException as caught:
        error = dict(type=type(caught).__name__, message=str(caught))
    after_error, after = None, None
    try:
        after = dict(binding=bind_controls(root, out), historical_input_sha256=historical_inputs(root),
                     copied_input_sha256=inventory(out / "validation-inputs"), adapter_sha256=sha(Path(__file__)),
                     runtime=runtime() if before is not None else None)
        if before is not None:
            require(after["binding"] == before["binding"], "live controls/source changed during phase")
            require(after["historical_input_sha256"] == before["historical_input_sha256"]
                    == after["copied_input_sha256"], "historical or copied inputs changed during phase")
            require(after["adapter_sha256"] == before["adapter_sha256"], "adapter changed during phase")
            require(after["runtime"] == before["runtime"], "selected runtime files changed during phase")
    except BaseException as caught:
        after_error = dict(type=type(caught).__name__, message=str(caught))
    result = dict(finished_utc=utc(), child_exit_code=child_exit, exit_code_known=child_exit is not None,
                  status="PASS" if error is None and after_error is None else "FAIL",
                  error=error, postflight_error=after_error, after=after,
                  output_sha256=inventory(out / ("validation" if action == "validate" else "timing")),
                  fresh_fuzzing_credit_seconds=0, historical_campaign_credit=0)
    write_new(receipts / "after.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("validate", "timing"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cpu", type=int, default=10)
    args = parser.parse_args()
    result = execute(args.output, args.action, args.cpu)
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["status"] == "PASS" else 1)


if __name__ == "__main__":
    main()
