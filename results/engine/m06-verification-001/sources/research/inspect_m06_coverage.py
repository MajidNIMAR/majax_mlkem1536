"""Preserve the actual LLVM union's function counts, including zero counts."""

import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from inspect_m03_binary import ROOT, linux_path, tool


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    out = ROOT / "artifacts/generated/m06-fuzz-001"
    receipt = json.loads((out / "union-coverage-receipt.json").read_text())
    if not receipt["source_union_validated"]:
        raise ValueError("validated LLVM union required")
    command = list(receipt["export_command"])
    command.remove("-summary-only")
    raw = tool(command[0], *command[1:])
    data = json.loads(raw)
    functions = [row for item in data["data"] for row in item["functions"]
                 if any("/crates/kem1536/src/" in name for name in row["filenames"])]
    names = [row["name"] for row in functions]
    # Demangling is presentation only; the complete original LLVM JSON remains.
    demangled = tool("c++filt", "-s", "rust", *names).decode().splitlines()
    if len(names) != len(demangled):
        raise ValueError("demangled function inventory differs")
    rows = [dict(name=name, LLVM_name=row["name"], count=row["count"], filenames=row["filenames"])
            for name, row in zip(demangled, functions, strict=True)]
    with (out / "union-coverage-full.json.gz").open("xb") as stream:
        with gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=0) as compressed:
            compressed.write(raw)
    shutil.copyfile(Path(__file__), out / "coverage-functions-controller.py")
    result = dict(command=command, full_LLVM_json_sha256=hashlib.sha256(raw).hexdigest(),
                  controller_sha256=sha(Path(__file__)),
                  profile_sha256=sha(out / "union-coverage.profdata"), functions=rows,
                  zero_count_functions=[row for row in rows if row["count"] == 0],
                  branch_or_constant_time_proof=False)
    with (out / "union-functions.json").open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(result["zero_count_functions"], indent=2))


if __name__ == "__main__":
    main()
