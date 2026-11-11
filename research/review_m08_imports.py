"""Collect and replay bounded M08 default-feature import machine inventories.

No automatic taint, constant-time or complete erasure proof is claimed. The
complete listings and explicit stack-addressing instructions support a separate
human provenance review of the emitted import paths, including error returns.
"""
import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil

from inspect_m03_binary import linux_path, tool
from review_m07_binary import address_bodies

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "KEM1536-DEV-Q7681-R1"
LABELS = ("baseline", "candidate")
HOSTS = ("windows", "linux")
BASELINE_CORE = "3b7594bf96b6dcf3a52001582f8ab832da774ed059db66999e0e5091c8c8d48b"
FOCUS_SOURCE = ("crates/kem1536/src/dev_kem.rs", "crates/kem1536/src/engine_poly.rs",
                "crates/kem1536/src/secret_box.rs", "research/m08-import-consumer/Cargo.toml",
                "research/m08-import-consumer/Cargo.lock", "research/m08-import-consumer/src/main.rs")
STACK = re.compile(r"(?:-?0x[0-9a-f]+|-?\d+)?\(%r(?:sp|bp)(?:,[^)]*)?\)")
INSTRUCTION = re.compile(r"^\s*([0-9a-f]+):\s+([a-z][a-z0-9_.]*)\s*(.*)$")


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def save(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def member(root, name):
    require(type(name) is str and name and "\\" not in name
            and all(part not in ("", ".", "..") and ":" not in part for part in name.split("/")),
            "unsafe review member")
    path = root.joinpath(*name.split("/"))
    require(path.resolve().is_relative_to(root.resolve()), "review member escapes root")
    return path


def check_consumer_command(entry, host):
    command = entry["command"]
    require(type(command) is list and command and all(type(argument) is str for argument in command),
            "consumer command must preserve argv")
    require(not any(argument in ("--features", "--all-features") or argument.startswith("--features=")
                    for argument in command), "review consumer requested a feature override")
    require(any("research/m08-import-consumer/Cargo.toml" in argument.replace("\\", "/") for argument in command),
            "separate default-feature consumer manifest absent from build command")
    expected_host = "x86_64-pc-windows-gnu" if host == "windows" else "x86_64-unknown-linux-gnu"
    require("release: 1.91.1" in entry["rustc"] and "host: " + expected_host in entry["rustc"]
            and entry["emit_stack_metadata"] is False, "unexpected consumer compiler/instrumentation")


def operands(text):
    """Split AT&T operands without splitting indexed address components."""
    depth, start, result = 0, 0, []
    for index, character in enumerate(text):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            require(depth >= 0, "unbalanced operand parentheses")
        elif character == "," and depth == 0:
            result.append(text[start:index].strip())
            start = index + 1
    require(depth == 0, "unbalanced operand parentheses")
    result.append(text[start:].strip())
    return result


def instructions(body):
    result = []
    for line in body.splitlines():
        match = INSTRUCTION.match(line)
        if match:
            address, opcode, arguments = match.groups()
            result.append({"address": address, "opcode": opcode, "operands": arguments})
    return result


def relocations(headers):
    result = {}
    for line in headers.splitlines():
        fields = line.split()
        if (len(fields) >= 4 and re.fullmatch(r"[0-9a-f]+", fields[0])
                and fields[2] == "R_X86_64_RELATIVE" and re.fullmatch(r"[0-9a-f]+", fields[3])):
            result[int(fields[0], 16)] = int(fields[3], 16)
    return result


def function_inventory(text, relocation_text):
    functions = address_bodies(text)
    require(functions, "complete disassembly has no functions")
    by_address = {int(row["address"], 16): identifier for identifier, row in functions.items()}
    require(len(by_address) == len(functions), "function addresses are not unique")
    rela = relocations(relocation_text)
    parsed = {}
    for identifier, function in functions.items():
        rows = instructions(function["body"])
        calls, indirect, stack = [], [], []
        for row in rows:
            opcode, arguments = row["opcode"], row["operands"]
            if opcode.startswith("call") or opcode in ("jmp", "jmpq"):
                direct = re.match(r"([0-9a-f]+)\s+<", arguments)
                target, source = None, None
                if direct:
                    target, source = by_address.get(int(direct.group(1), 16)), "direct machine address"
                elif arguments.startswith("*"):
                    slot = re.search(r"#\s+([0-9a-f]+)", arguments)
                    if slot:
                        target = by_address.get(rela.get(int(slot.group(1), 16)))
                    if target:
                        source = "ELF relative relocation"
                    else:
                        indirect.append(row)
                if target and target != identifier:
                    calls.append({**row, "target": target, "resolution": source})
            parts = operands(arguments) if arguments else []
            addresses = [(index, part) for index, part in enumerate(parts) if STACK.search(part)]
            if addresses:
                # This is syntactic evidence, not automatic secret taint. RBP
                # need not be a frame pointer, and LEA does not read the bytes.
                stack.append({**row, "stack_operands": [part for _, part in addresses],
                              "destination_is_stack_syntax": bool(parts and STACK.search(parts[-1])),
                              "address_calculation_only": opcode.startswith("lea")})
        parsed[identifier] = {"name": function["name"], "address": function["address"],
            "body_sha256": hashlib.sha256(function["body"].encode()).hexdigest(),
            "instructions": len(rows), "calls": calls, "unresolved_indirect_transfers": indirect,
            "conditional_branches": [row for row in rows if row["opcode"].startswith("j")
                                     and row["opcode"] not in ("jmp", "jmpq")],
            "divisions": [row for row in rows if re.fullmatch(r"i?div[bwlq]?", row["opcode"])],
            "explicit_stack_addressing": stack}
    wrappers = {kind: [identifier for identifier, row in parsed.items()
                       if "m08_import_consumer::import_" + kind + "_probe" in row["name"]]
                for kind in ("public", "private")}
    require(all(len(value) == 1 for value in wrappers.values()), "one retained wrapper per public/private import required")
    pending = [identifier for value in wrappers.values() for identifier in value]
    reachable = set(pending)
    while pending:
        for call in parsed[pending.pop()]["calls"]:
            if call["target"] not in reachable:
                reachable.add(call["target"])
                pending.append(call["target"])
    validation = sorted(identifier for identifier, row in parsed.items() if any(name in row["name"] for name in
        ("validate_vector_encoding", "decode_polynomial_into", "unpack_coefficient", "from_bytes", "Polynomial::fill_with")))
    names = Counter(row["name"] for row in parsed.values())
    return {"schema": "m08-import-physical-inventory-v1", "physical_functions": len(parsed),
        "duplicate_demangled_names": dict(sorted((name, count) for name, count in names.items() if count > 1)),
        "retained_import_wrappers": wrappers, "reachable_by_resolved_direct_closure": sorted(reachable),
        "validation_related_functions": validation, "functions": parsed,
        "unresolved_indirect_target_set_complete": False, "system_library_bodies_included": False,
        "constant_time_proved": False, "all_spills_or_copies_erased_proved": False,
        "scope": "Complete physical function inventory; direct and ELF-relative-relocation closure from retained default-feature import wrappers. Explicit RSP/RBP operands are syntax, not taint or a complete stack/register trace."}


def verify_contents(output):
    collection = read(output / "collection.json")
    require(collection["schema"] == "m08-import-review-collection-v1" and collection["profile"] == PROFILE,
            "wrong review collection schema/profile")
    require(sha(output / "inputs/memory-accepted.json") == collection["memory_acceptance_sha256"], "memory gate changed")
    marker = read(output / "inputs/memory-accepted.json")
    require(marker["profile"] == PROFILE and marker["accepted"] is True
            and marker["candidate_source_manifest_sha256"] == collection["source_manifest_sha256"]["candidate"],
            "unaccepted candidate source")
    for label in LABELS:
        manifest_path = output / "inputs" / (label + "-source.json")
        require(sha(manifest_path) == collection["source_manifest_sha256"][label], "review source manifest changed")
        manifest = read(manifest_path)
        require(manifest["profile"] == PROFILE, "focused source profile differs")
        for name in FOCUS_SOURCE:
            require(sha(member(output / "source" / label, name)) == manifest["source_sha256"][name],
                    "focused source changed: " + name)
        for host in HOSTS:
            key = label + "-" + host
            build_path = output / "inputs" / (key + "-build.json")
            require(sha(build_path) == collection["build_receipt_sha256"][key], "review build receipt changed")
            build = read(build_path)
            entry = build["binaries"]["consumer"]
            require(build["profile"] == PROFILE and build["source_manifest_sha256"] == collection["source_manifest_sha256"][label]
                    and entry == collection["binaries"][key] and "release: 1.91.1" in entry["rustc"],
                    "consumer build/source/compiler binding differs")
            check_consumer_command(entry, host)
            audit = output / "audit" / key
            headers = (audit / "headers.txt").read_text(encoding="utf-8")
            require(("file format pei-x86-64" if host == "windows" else "file format elf64-x86-64") in headers,
                    "reviewed machine format differs")
            with gzip.open(audit / "binary.gz", "rb") as stream:
                require(hashlib.sha256(stream.read()).hexdigest() == entry["sha256"], "reviewed binary differs")
            with gzip.open(audit / "disassembly.txt.gz", "rt", encoding="utf-8") as stream:
                computed = function_inventory(stream.read(), (audit / "relocations.txt").read_text(encoding="utf-8"))
            require(read(audit / "inventory.json") == computed, "physical function inventory does not replay")
    baseline = read(output / "inputs/baseline-source.json")["source_sha256"]
    candidate = read(output / "inputs/candidate-source.json")["source_sha256"]
    require(baseline[FOCUS_SOURCE[0]] == BASELINE_CORE, "baseline is not the measured M07 core")
    require(all(baseline[name] == candidate[name] for name in FOCUS_SOURCE[1:]), "non-target arithmetic/storage/consumer changed")
    return {"consumer_images_verified": 4, "physical_inventories_recomputed": 4,
            "new_objdump_run": False, "manual_dataflow_review_is_separate": True,
            "constant_time_proved": False, "all_copies_erased_proved": False}


def check_witnesses(output):
    data, collection = read(output / "witnesses.json"), read(output / "collection.json")
    require(data["schema"] == "m08-import-witnesses-v1" and set(data["images"]) == set(collection["binaries"])
            and data["constant_time_proved"] is False and data["all_copies_erased_proved"] is False,
            "manual witness scope or image panel differs")
    count = 0
    for key, image in data["images"].items():
        require(image["binary_sha256"] == collection["binaries"][key]["sha256"]
                and image["witnesses"] and type(image["bounded_conclusion"]) is str and image["bounded_conclusion"],
                "manual image provenance or conclusion absent")
        with gzip.open(output / "audit" / key / "disassembly.txt.gz", "rt", encoding="utf-8") as stream:
            functions = address_bodies(stream.read())
        seen = set()
        for witness in image["witnesses"]:
            identity = (witness["function"], witness["address"], witness["opcode"], witness["operands"])
            require(identity not in seen and witness["function"] in functions and type(witness["purpose"]) is str
                    and witness["purpose"], "missing or duplicate manual instruction witness")
            seen.add(identity)
            expected = {key: witness[key] for key in ("address", "opcode", "operands")}
            require(expected in instructions(functions[witness["function"]]["body"]), "manual instruction witness no longer matches listing")
            count += 1
    return count


def collect(run, output):
    run, output = run.resolve(), output.resolve()
    require(run.is_relative_to(ROOT / "artifacts/generated"), "collection inputs must remain in the project generated workspace")
    marker_path = run / "MEMORY_AND_LATENCY_ACCEPTED.json"
    require(marker_path.is_file(), "wait for the memory/latency acceptance gate before objdump")
    marker = read(marker_path)
    require(marker["profile"] == PROFILE and marker["accepted"] is True, "candidate gate is not accepted")
    require(output.is_relative_to(ROOT / "artifacts/generated") and not output.exists(), "new generated review directory required")
    manifests = {label: read(run / (label + "-source.json")) for label in LABELS}
    require(all(manifest["profile"] == PROFILE for manifest in manifests.values()), "comparison source profiles differ")
    require(marker["candidate_source_manifest_sha256"] == sha(run / "candidate-source.json"), "gate/source manifest differs")
    for label in LABELS:
        for name, checksum in manifests[label]["source_sha256"].items():
            require(sha(member(run / (label + "-source"), name)) == checksum, "compilation source changed: " + name)
    require(manifests["baseline"]["source_sha256"][FOCUS_SOURCE[0]] == BASELINE_CORE, "baseline core differs from M07")
    require(all(manifests["baseline"]["source_sha256"][name] == manifests["candidate"]["source_sha256"][name]
                for name in FOCUS_SOURCE[1:]), "consumer/arithmetic/storage differs between compared versions")
    builds = {(label, host): read(run / label / host / "build.json") for label in LABELS for host in HOSTS}
    for (label, host), build in builds.items():
        entry = build["binaries"]["consumer"]
        check_consumer_command(entry, host)
        require(build["profile"] == PROFILE and build["source_manifest_sha256"] == sha(run / (label + "-source.json"))
                and sha(member(run, entry["path"])) == entry["sha256"] and "release: 1.91.1" in entry["rustc"],
                "unbound original consumer image")
    output.mkdir()
    (output / "inputs").mkdir()
    shutil.copyfile(marker_path, output / "inputs/memory-accepted.json")
    collection = {"schema": "m08-import-review-collection-v1", "profile": PROFILE,
                  "memory_acceptance_sha256": sha(marker_path), "source_manifest_sha256": {},
                  "build_receipt_sha256": {}, "binaries": {},
                  "full_compilation_inputs_rechecked_at_collection": True,
                  "disassembly_is_observation_not_CT_or_erasure_proof": True}
    for label in LABELS:
        path = run / (label + "-source.json")
        collection["source_manifest_sha256"][label] = sha(path)
        shutil.copyfile(path, output / "inputs" / (label + "-source.json"))
        for name in FOCUS_SOURCE:
            destination = member(output / "source" / label, name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(member(run / (label + "-source"), name), destination)
        for host in HOSTS:
            key, build = label + "-" + host, builds[label, host]
            source_receipt = run / label / host / "build.json"
            collection["build_receipt_sha256"][key] = sha(source_receipt)
            collection["binaries"][key] = entry = build["binaries"]["consumer"]
            shutil.copyfile(source_receipt, output / "inputs" / (key + "-build.json"))
            audit = output / "audit" / key
            audit.mkdir(parents=True)
            executable = member(run, entry["path"])
            listing = tool("objdump", "-d", "-C", "--no-show-raw-insn", linux_path(executable))
            headers = tool("objdump", "-x", linux_path(executable))
            relocation_text = tool("readelf", "-rW", linux_path(executable)) if host == "linux" else b""
            (audit / "headers.txt").write_bytes(headers)
            (audit / "relocations.txt").write_bytes(relocation_text)
            (audit / "objdump-version.txt").write_bytes(tool("objdump", "--version"))
            for name, data in (("binary.gz", executable.read_bytes()), ("disassembly.txt.gz", listing)):
                with (audit / name).open("xb") as stream, gzip.GzipFile(fileobj=stream, mode="wb", filename="", mtime=0) as compressed:
                    compressed.write(data)
            save(audit / "inventory.json", function_inventory(listing.decode(), relocation_text.decode()))
            require(sha(executable) == entry["sha256"], "original changed during disassembly")
    save(output / "collection.json", collection)
    return verify_contents(output)


def seal(output):
    output = output.resolve()
    require(output.is_relative_to(ROOT / "artifacts/generated"), "seal only the owned generated review")
    require(not (output / "provenance.json").exists(), "never replace a sealed import review")
    verify_contents(output)
    observations = (output / "OBSERVATIONS.md").read_text(encoding="utf-8")
    collection = read(output / "collection.json")
    require("M08" in observations and all(row["sha256"] in observations for row in collection["binaries"].values()),
            "human observations must identify all four exact reviewed consumers")
    require((output / "witnesses.json").is_file(), "addressed manual dataflow witnesses required before sealing")
    check_witnesses(output)
    (output / "tools").mkdir()
    for name in ("review_m08_imports.py", "test_review_m08_imports.py", "inspect_m03_binary.py", "review_m07_binary.py", "review_m06_binary.py"):
        shutil.copyfile(ROOT / "research" / name, output / "tools" / name)
    files = {path.relative_to(output).as_posix(): sha(path) for path in sorted(output.rglob("*")) if path.is_file()}
    save(output / "provenance.json", {"schema": "m08-import-review-receipt-v1", "files_sha256": files,
         "manual_provenance_review_and_machine_inventory_distinct": True, "global_erasure_or_CT_proved": False})
    return verify(output)


def verify(output):
    output = output.resolve()
    receipt = read(output / "provenance.json")
    require(receipt["schema"] == "m08-import-review-receipt-v1", "unknown import review schema")
    actual = {p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file() and p != output / "provenance.json"}
    require(actual == set(receipt["files_sha256"]), "import review member inventory differs")
    for name, checksum in receipt["files_sha256"].items():
        require(sha(member(output, name)) == checksum, "import review member changed: " + name)
    return {"frozen_members_verified": len(actual), "addressed_manual_instruction_witnesses": check_witnesses(output), **verify_contents(output)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("collect", "seal", "verify"))
    parser.add_argument("--run", type=Path, default=ROOT / "artifacts/generated/m08-001")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/generated/m08-import-review-001")
    args = parser.parse_args()
    result = collect(args.run, args.output) if args.action == "collect" else (seal(args.output) if args.action == "seal" else verify(args.output))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
