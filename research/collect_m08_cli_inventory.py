"""Collect/replay M08 CLI machine inventories, distinct from import review.

This preserves full raw disassembly and physical symbol addresses. It does
not prove PKE erasure, constant time, or complete indirect-call closure.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

from inspect_m03_binary import inventory, parse_disassembly, resolve_elf_relocations
from run_m08 import ROOT, PROFILE, checked_source, read, require, save, sha


def address_index(text):
    labels = [{"address": "0x"+m.group(1), "name": m.group(2)}
              for m in re.finditer(r"^([0-9a-f]+) <(.+)>:\s*$", text, re.MULTILINE)]
    require(labels, "empty physical function index")
    names = {}
    for row in labels:
        names[row["name"]] = names.get(row["name"], 0) + 1
    return {"labels": labels, "physical_address_count": len({int(r["address"], 16) for r in labels}),
            "duplicate_demangled_names": {n:c for n,c in names.items() if c > 1},
            "all_secret_owners_erased_proved": False, "constant_time_proved": False}


def files(folder):
    return {p.relative_to(folder).as_posix(): sha(p) for p in sorted(folder.rglob("*")) if p.is_file()}


def member(root, name):
    require(type(name) is str and "\\" not in name and not Path(name).is_absolute()
            and all(p not in {"", ".", ".."} and ":" not in p for p in name.split("/")), "unsafe inventory member")
    path = (root / name).resolve()
    require(path.is_relative_to(root.resolve()), "inventory member escaped root")
    return path


def collect(run, out):
    require(out.parent.resolve() == (ROOT / "artifacts/generated").resolve() and not out.exists(), "new generated inventory required")
    marker = run / "MEMORY_AND_LATENCY_ACCEPTED.json"
    accepted = read(marker)
    require(accepted["accepted"] is True and accepted["profile"] == PROFILE
            and accepted["candidate_source_manifest_sha256"] == sha(run / "candidate-source.json"), "accepted measured source required")
    checked_source(run, "candidate")
    out.mkdir();(out / "inputs").mkdir();(out / "audit").mkdir()
    for source, name in ((marker, "memory-accepted.json"), (run / "candidate-source.json", "candidate-source.json")):
        shutil.copyfile(source, out / "inputs" / name)
    collection = {"schema": "m08-cli-inventory-collection-v1", "profile": PROFILE,
        "source_manifest_sha256": sha(run / "candidate-source.json"), "memory_acceptance_sha256": sha(marker),
        "build_receipt_sha256": {}, "binaries": {},
        "scope": "Raw CLI disassembly/name-keyed legacy inventory plus physical address index; no PKE erasure or CT proof and no import-consumer review transferred."}
    for host in ("windows", "linux"):
        build_path = run / "candidate" / host / "build.json"
        build = read(build_path)
        require(build["source_manifest_sha256"] == collection["source_manifest_sha256"], "CLI build source differs")
        collection["build_receipt_sha256"][host] = sha(build_path)
        shutil.copyfile(build_path, out / "inputs" / (host + "-build.json"))
        for kind in ("research", "delivered"):
            key = host + "-" + kind
            entry = build["binaries"][kind]
            executable = member(run, entry["path"])
            require(sha(executable) == entry["sha256"] and "release: 1.91.1" in entry["rustc"], "original CLI/compiler differs")
            collection["binaries"][key] = entry
            audit = out / "audit" / key
            command = [sys.executable, "-B", str(ROOT / "research/inspect_m03_binary.py"), "--binary", str(executable), "--output", str(audit)]
            with (out / (key + ".log")).open("xb") as stream:
                subprocess.run(command, cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, check=True)
            with gzip.open(audit / "disassembly.txt.gz", "rt", encoding="utf-8") as stream:
                save(audit / "address-index.json", address_index(stream.read()))
            require(sha(executable) == entry["sha256"], "CLI changed during collection")
    save(out / "collection.json", collection)
    (out / "tools").mkdir()
    for name in ("collect_m08_cli_inventory.py", "inspect_m03_binary.py"):
        shutil.copyfile(ROOT / "research" / name, out / "tools" / name)
    save(out / "provenance.json", {"schema": "m08-cli-inventory-receipt-v1", "files_sha256": files(out),
         "new_disassembly_collected": True, "complete_erasure_or_CT_proved": False})
    return verify(out)


def verify(out):
    provenance = read(out / "provenance.json")
    require(provenance["schema"] == "m08-cli-inventory-receipt-v1", "unknown CLI inventory schema")
    actual = files(out);actual.pop("provenance.json")
    require(actual == provenance["files_sha256"], "CLI inventory members changed")
    collection = read(out / "collection.json")
    require(collection["schema"] == "m08-cli-inventory-collection-v1" and collection["profile"] == PROFILE
            and collection["source_manifest_sha256"] == sha(out / "inputs/candidate-source.json")
            and collection["memory_acceptance_sha256"] == sha(out / "inputs/memory-accepted.json"), "CLI collection chain differs")
    marker = read(out / "inputs/memory-accepted.json")
    require(marker["accepted"] is True and marker["profile"] == PROFILE
            and marker["candidate_source_manifest_sha256"] == collection["source_manifest_sha256"], "CLI acceptance binding differs")
    require(set(collection["binaries"]) == {h+"-"+k for h in ("windows","linux") for k in ("research","delivered")}, "four CLI images required")
    for key, entry in collection["binaries"].items():
        host, kind = key.split("-")
        build_path = out / "inputs" / (host + "-build.json")
        build = read(build_path)
        require(sha(build_path) == collection["build_receipt_sha256"][host]
                and build["source_manifest_sha256"] == collection["source_manifest_sha256"]
                and build["binaries"][kind] == entry, "CLI build receipt changed")
        audit = out / "audit" / key
        with gzip.open(audit / "binary.gz", "rb") as stream:
            require(hashlib.sha256(stream.read()).hexdigest() == entry["sha256"], "CLI image changed")
        with gzip.open(audit / "disassembly.txt.gz", "rt", encoding="utf-8") as stream:
            listing = stream.read()
        require(address_index(listing) == read(audit / "address-index.json"), "physical CLI index differs")
        functions = parse_disassembly(listing)
        if host == "linux":
            resolve_elf_relocations(functions, (audit / "relocations.txt").read_text(encoding="utf-8"))
        report = inventory(functions)
        saved = read(audit / "summary.json")
        require(all(saved[k] == v for k,v in report.items()) and saved["binary_sha256"] == entry["sha256"], "CLI machine inventory differs")
    return {"CLI_inventories_replayed": 4, "new_objdump_run": False, "PKE_erasure_proved": False,
            "import_review_is_separate": True, "constant_time_proved": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("collect", "verify"))
    parser.add_argument("--run", type=Path, default=ROOT / "artifacts/generated/m08-001")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/generated/m08-cli-inventory-001")
    args=parser.parse_args()
    print(json.dumps(collect(args.run.resolve(),args.output.resolve()) if args.action=="collect" else verify(args.output.resolve()),indent=2))


if __name__ == "__main__":
    main()
