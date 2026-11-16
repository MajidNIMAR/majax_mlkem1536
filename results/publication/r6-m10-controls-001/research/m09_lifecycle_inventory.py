"""Collect/replay physical-address inventories for two new M09 PC images.

This is a machine-code inventory, not a secret-taint, erasure or constant-time
proof.  verify is data-only: it never invokes a compiler, binary or objdump.
"""

import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    "Cargo.toml", "Cargo.lock", "crates/kem1536/Cargo.toml",
    "crates/kem1536/src/dev_kem.rs", "crates/kem1536/src/engine_poly.rs",
    "crates/kem1536/src/secret_box.rs",
)
LABEL = re.compile(r"^([0-9a-f]+) <(.+)>:$", re.MULTILINE)
INSTRUCTION = re.compile(r"^\s*([0-9a-f]+):\s+([a-z][a-z0-9_.]*)\s*(.*)$")
STACK = re.compile(r"(?:-?0x[0-9a-f]+|-?\d+)?\(%r(?:sp|bp)(?:,[^)]*)?\)")
FOCUS = ("kem1536::dev_kem::", "kem1536::engine_poly::", "kem1536::secret_box::",
         "_ZN7kem15367dev_kem", "_ZN7kem153611engine_poly", "_ZN7kem153610secret_box")


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    return digest(Path(path).read_bytes())


def save(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def member(folder, name):
    require(type(name) is str and name and "\\" not in name
            and all(part not in ("", ".", "..") and ":" not in part
                    for part in name.split("/")), "unsafe inventory member")
    path = folder.joinpath(*name.split("/"))
    require(path.resolve().is_relative_to(folder.resolve()), "escaped member")
    return path


def gzip_write(path, data):
    with path.open("xb") as stream:
        with gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0) as zipped:
            zipped.write(data)


def parse(text):
    """Keep every physical function, even when demangled names coincide."""
    labels = list(LABEL.finditer(text))
    require(labels, "empty physical index")
    functions = []
    seen = set()
    for index, label in enumerate(labels):
        address, name = label.groups()
        require(address not in seen, "ambiguous physical address")
        seen.add(address)
        body = text[label.end():labels[index + 1].start()
                    if index + 1 < len(labels) else len(text)]
        code = []
        for line in body.splitlines():
            match = INSTRUCTION.match(line)
            if match:
                site, opcode, operands = match.groups()
                code.append({"address": site, "opcode": opcode, "operands": operands})
        functions.append({"address": address, "name": name, "instructions": code})
    return functions


def summarize(text, relocations=""):
    functions = parse(text)
    by_address = {int(row["address"], 16): row for row in functions}
    addresses = set(by_address)
    instruction_owner = {int(instruction["address"], 16): address
                         for address, row in by_address.items()
                         for instruction in row["instructions"]}
    # Resolve only explicit ELF RELATIVE relocation addends to retained functions.
    # Other indirect targets stay visibly unresolved; no completeness is assumed.
    slots = {}
    for line in relocations.splitlines():
        fields = line.split()
        if (len(fields) >= 4 and re.fullmatch(r"[0-9a-f]+", fields[0])
                and fields[2] == "R_X86_64_RELATIVE"
                and re.fullmatch(r"[0-9a-f]+", fields[3])):
            target = int(fields[3], 16)
            if target in addresses:
                slots[int(fields[0], 16)] = target
    roots = {address for address, row in by_address.items()
             if any(tag in row["name"] for tag in FOCUS)}
    require(roots, "no retained engine symbols: scope cannot be attributed")
    edges, transfers, unresolved = {}, [], []
    for address, row in by_address.items():
        edges[address] = set()
        for instruction in row["instructions"]:
            opcode, operands = instruction["opcode"], instruction["operands"]
            if opcode not in ("call", "callq", "jmp", "jmpq"):
                continue
            direct = re.match(r"(?:0x)?([0-9a-f]+)\s+<", operands)
            target, kind = None, "unresolved"
            if direct:
                target = int(direct.group(1), 16)
                kind = "direct"
            elif operands.startswith("*"):
                slot = re.search(r"#\s+(?:0x)?([0-9a-f]+)", operands)
                if slot and int(slot.group(1), 16) in slots:
                    target = slots[int(slot.group(1), 16)]
                    kind = "ELF-relative-slot"
            entry = {"function": row["address"], **instruction,
                     "resolution": kind,
                     "target_address": format(target, "x") if target is not None else None}
            transfers.append(entry)
            physical_target = target if target in addresses else instruction_owner.get(target)
            if physical_target is not None:
                edges[address].add(physical_target)
            else:
                unresolved.append(entry)
    reachable, pending = set(roots), list(roots)
    while pending:
        for target in edges[pending.pop()]:
            if target not in reachable:
                reachable.add(target)
                pending.append(target)
    divisions, branches, stack, wipes = [], [], [], []
    for address in sorted(reachable):
        row = by_address[address]
        for instruction in row["instructions"]:
            entry = {"function": row["address"], "name": row["name"], **instruction}
            opcode, operands = instruction["opcode"], instruction["operands"]
            if re.fullmatch(r"i?div[bwlq]?", opcode):
                divisions.append(entry)
            if ((opcode.startswith("j") and opcode not in ("jmp", "jmpq"))
                    or opcode.startswith("loop")):
                branches.append(entry)
            if STACK.search(operands):
                stack.append(entry)
            # Literal immediate-zero stores are witnesses only: they are NOT
            # classified as secret owners, complete loops or all wipe methods.
            if opcode.startswith("mov") and operands.startswith("$0x0,") and "(" in operands:
                wipes.append(entry)
    counts = Counter(row["name"] for row in functions)
    return {
        "schema": "m09-physical-lifecycle-inventory-v1",
        "physical_functions": [{"address": row["address"], "name": row["name"],
                                "instruction_count": len(row["instructions"])}
                               for row in functions],
        "duplicate_demangled_names": {name: count for name, count in sorted(counts.items()) if count > 1},
        "engine_roots": [format(address, "x") for address in sorted(roots)],
        "direct_or_relative_slot_reachable": [format(address, "x") for address in sorted(reachable)],
        "transfers_in_scope": [row for row in transfers if int(row["function"], 16) in reachable],
        "unresolved_or_external_in_scope": [row for row in unresolved if int(row["function"], 16) in reachable],
        "division_sites_in_scope": divisions,
        "conditional_branch_sites_in_scope": branches,
        "stack_addressing_sites_in_scope": stack,
        "literal_zero_store_witnesses_in_scope": wipes,
        "all_PKE_paths_proved_erased": False,
        "secret_registers_or_ABI_proved_erased": False,
        "constant_time_proved": False,
        "scope": "Physical-address x86-64 listing; retained engine roots and explicit direct/ELF-relative-slot closure. No taint or indirect completeness proof.",
    }


def tracked_files(folder):
    return {path.relative_to(folder).as_posix(): sha(path)
            for path in sorted(folder.rglob("*")) if path.is_file()}


def wsl_path(path):
    path = path.resolve()
    return "/mnt/" + path.drive[0].lower() + str(path)[2:].replace("\\", "/")


def invoke(argv, log):
    process = subprocess.run(argv, cwd=ROOT, capture_output=True, check=False)
    log.append({"argv": argv, "exit_code": process.returncode,
                "stdout_sha256": digest(process.stdout), "stderr_sha256": digest(process.stderr)})
    require(process.returncode == 0, "machine inventory tool failed")
    return process.stdout


def check_build_scope(receipt, host, binary_kind, source_manifest_sha256):
    require(receipt["profile"] == "KEM1536-DEV-Q7681-R1" and receipt["host"] == host
            and receipt["source_manifest_sha256"] == source_manifest_sha256,
            "image profile/host/source manifest differs")
    entry = receipt["binaries"][binary_kind]
    command = entry["command"]
    require(type(command) is list and command and all(type(item) is str for item in command)
            and "--release" in command and "--locked" in command and "--offline" in command,
            "recorded locked release build required")
    require(not any(item in ("--features", "--all-features") or item.startswith("--features=")
                    for item in command), "default-feature image required")
    target = "x86_64-pc-windows-gnu" if host == "windows" else "x86_64-unknown-linux-gnu"
    require("release: 1.91.1" in entry["rustc"] and "host: " + target in entry["rustc"]
            and entry["emit_stack_metadata"] is False and entry["exit_code"] == 0,
            "compiler, instrumentation or build status outside qualification")
    return entry


def checked_builds(build_root, binary_kind):
    require(build_root.is_relative_to(ROOT / "artifacts/generated"), "local qualification root required")
    source_path = build_root / "source.json"
    source = read(source_path)["source_sha256"]
    require(set(SOURCES).issubset(source), "core/manifest source inputs absent")
    require(tracked_files(build_root / "source") == source, "qualification source closure changed")
    images, receipts = {}, {}
    for host in ("windows", "linux"):
        receipt_path = build_root / host / "build.json"
        receipt = read(receipt_path)
        entry = check_build_scope(receipt, host, binary_kind, sha(source_path))
        binary = member(build_root, entry["path"])
        require(binary.is_file() and sha(binary) == entry["sha256"], "original build image differs")
        images[host] = binary
        receipts[host] = receipt_path
    return source, images, receipts


def collect(output, build_root, binary_kind):
    require(output.parent == (ROOT / "artifacts/generated").resolve() and not output.exists(),
            "new direct child of artifacts/generated required")
    inputs_before, binaries, receipts = checked_builds(build_root, binary_kind)
    output.mkdir()
    (output / "inputs").mkdir()
    (output / "inputs/source.json").write_bytes((build_root / "source.json").read_bytes())
    for host, path in receipts.items():
        (output / "inputs" / (host + "-build.json")).write_bytes(path.read_bytes())
    sources = output / "sources"
    sources.mkdir()
    for name in inputs_before:
        destination = member(sources, name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(member(build_root / "source", name).read_bytes())
    images = {}
    for host, binary in binaries.items():
        folder = output / host
        folder.mkdir()
        original = binary.read_bytes()
        require(original[:4] == b"\x7fELF" if host == "linux" else original[:2] == b"MZ",
                "unexpected binary format")
        log = []
        prefix = ["wsl.exe", "-d", "Ubuntu-22.04", "--"]
        path = wsl_path(binary)
        listing = invoke(prefix + ["objdump", "-d", "-C", "--no-show-raw-insn", path], log)
        headers = invoke(prefix + ["objdump", "-x", path], log)
        require(b"architecture: i386:x86-64" in headers, "x86-64 parser requires x86-64 image")
        versions = invoke(prefix + ["objdump", "--version"], log)
        relocations = invoke(prefix + ["readelf", "-Wr", path], log) if host == "linux" else b""
        require(binary.read_bytes() == original, "image changed during collection")
        gzip_write(folder / "binary.gz", original)
        gzip_write(folder / "disassembly.txt.gz", listing)
        (folder / "headers.txt").write_bytes(headers)
        (folder / "objdump-version.txt").write_bytes(versions)
        (folder / "relocations.txt").write_bytes(relocations)
        save(folder / "commands.json", log)
        save(folder / "inventory.json", summarize(listing.decode("utf-8"), relocations.decode("utf-8")))
        images[host] = {"original_path": binary.relative_to(ROOT).as_posix(),
                        "sha256": digest(original), "bytes": len(original)}
    require(checked_builds(build_root, binary_kind) == (inputs_before, binaries, receipts),
            "qualification inputs changed during collection")
    (output / "m09_lifecycle_inventory.py").write_bytes(Path(__file__).read_bytes())
    save(output / "collection.json", {"schema": "m09-lifecycle-collection-v1", "profile": "KEM1536-DEV-Q7681-R1",
                                      "source_sha256": inputs_before, "images": images,
                                      "source_manifest_sha256": sha(build_root / "source.json"),
                                      "build_receipt_sha256": {host: sha(path) for host, path in receipts.items()},
                                      "build_root_relative": build_root.relative_to(ROOT).as_posix(),
                                      "binary_kind": binary_kind,
                                      "fresh_machine_collection": True,
                                      "external_review_performed": False})
    save(output / "provenance.json", {"schema": "m09-lifecycle-receipt-v1",
                                      "members_sha256": tracked_files(output)})
    return verify(output)


def verify(output):
    provenance = read(output / "provenance.json")
    require(provenance["schema"] == "m09-lifecycle-receipt-v1", "receipt schema differs")
    actual = tracked_files(output)
    actual.pop("provenance.json")
    require(actual == provenance["members_sha256"], "lifecycle members differ")
    for name, expected in provenance["members_sha256"].items():
        require(sha(member(output, name)) == expected, "member differs")
    collection = read(output / "collection.json")
    require(collection["schema"] == "m09-lifecycle-collection-v1"
            and collection["profile"] == "KEM1536-DEV-Q7681-R1"
            and set(collection["images"]) == {"windows", "linux"}
            and collection["external_review_performed"] is False, "collection schema/scope differs")
    require(set(SOURCES).issubset(collection["source_sha256"]), "core source closure differs")
    source_path = output / "inputs/source.json"
    require(sha(source_path) == collection["source_manifest_sha256"]
            and read(source_path)["source_sha256"] == collection["source_sha256"]
            and tracked_files(output / "sources") == collection["source_sha256"], "source manifest differs")
    for name, expected in collection["source_sha256"].items():
        require(sha(member(output / "sources", name)) == expected, "captured source differs")
    counts = {}
    for host, image in collection["images"].items():
        folder = output / host
        build_path = output / "inputs" / (host + "-build.json")
        build = read(build_path)
        require(sha(build_path) == collection["build_receipt_sha256"][host]
                and build["source_manifest_sha256"] == collection["source_manifest_sha256"],
                "build/source link differs")
        entry = check_build_scope(build, host, collection["binary_kind"], collection["source_manifest_sha256"])
        require(entry["sha256"] == image["sha256"]
                and collection["build_root_relative"] + "/" + entry["path"] == image["original_path"],
                "build/image link differs")
        with gzip.open(folder / "binary.gz", "rb") as stream:
            binary = stream.read()
        require(digest(binary) == image["sha256"] and len(binary) == image["bytes"], "image differs")
        require("architecture: i386:x86-64" in (folder / "headers.txt").read_text(encoding="utf-8"),
                "x86-64 headers required")
        with gzip.open(folder / "disassembly.txt.gz", "rt", encoding="utf-8") as stream:
            listing = stream.read()
        inventory = summarize(listing, (folder / "relocations.txt").read_text(encoding="utf-8"))
        require(inventory == read(folder / "inventory.json"), "physical inventory differs")
        counts[host] = {"physical_functions": len(inventory["physical_functions"]),
                        "engine_roots": len(inventory["engine_roots"]),
                        "reachable_functions": len(inventory["direct_or_relative_slot_reachable"]),
                        "division_sites": len(inventory["division_sites_in_scope"]),
                        "literal_zero_store_witnesses": len(inventory["literal_zero_store_witnesses_in_scope"])}
    return {"images": counts, "new_objdump_on_verify": False, "external_review": False,
            "complete_erasure_proved": False, "constant_time_proved": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("collect", "verify"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build-root", type=Path)
    parser.add_argument("--binary-kind", choices=("delivered", "consumer"), default="delivered")
    args = parser.parse_args()
    if args.action == "collect":
        require(args.build_root is not None, "qualification build root required")
        result = collect(args.output.resolve(), args.build_root.resolve(), args.binary_kind)
    else:
        require(args.build_root is None, "verify uses archived images only")
        result = verify(args.output.resolve())
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
