"""Collect/replay the exact PC images for the M10 secret-lifecycle review.

The physical parser is reused unchanged from M09. New M10 receipts bind all
captured sources, default-image build receipts and image hashes. Replay reads
saved data only; it runs no compiler, image or objdump. Inventories are not
secret-taint, constant-time or whole-program erasure proofs.
"""
import argparse
import gzip
import json
from pathlib import Path

import m09_lifecycle_inventory as physical
from verify_r1_certificate_bridge import verify_static_contract


ROOT = physical.ROOT
CONTROLS = ("m10_secret_inventory.py", "m09_lifecycle_inventory.py",
            "verify_r1_certificate_bridge.py", "m09_source_contract.py", "m10_source_contract.py")
REALIZATIONS = {"baseline": {("M09-typed-noise-destination-message-1", 62)},
                "candidate": {("M10-destination-derived-conditional-assignment-1", 75),
                              ("M10-borrowed-XOF-destination-assignment-2", 77),
                              ("M10-borrowed-XOF-copied-output-3", 78)}}
BASELINE_MANIFEST = "fea4458893be1e7f84e42d58da22c3740363a015103917fb0828603f902925ce"


def check_commands(commands, host, original_path, listing, headers, versions, relocations):
    """Bind saved command receipts to the exact saved stdout, without execution."""
    physical.require(type(commands) is list and len(commands) == (4 if host == "linux" else 3),
                     "machine command panel differs")
    first = commands[0]["argv"]
    physical.require(type(first) is list and len(first) == 9 and type(first[-1]) is str
                     and first[-1].startswith("/mnt/") and first[-1].endswith("/" + original_path),
                     "command/image path differs")
    path = first[-1]
    prefix = ["wsl.exe", "-d", "Ubuntu-22.04", "--"]
    expected = [
        (prefix + ["objdump", "-d", "-C", "--no-show-raw-insn", path], listing),
        (prefix + ["objdump", "-x", path], headers),
        (prefix + ["objdump", "--version"], versions),
    ]
    if host == "linux":
        expected.append((prefix + ["readelf", "-Wr", path], relocations))
    else:
        physical.require(relocations == b"", "unexpected Windows ELF relocations")
    for command, (argv, stdout) in zip(commands, expected):
        physical.require(set(command) == {"argv", "exit_code", "stdout_sha256", "stderr_sha256"}
                         and command["argv"] == argv and type(command["exit_code"]) is int
                         and command["exit_code"] == 0
                         and command["stdout_sha256"] == physical.digest(stdout)
                         and command["stderr_sha256"] == physical.digest(b""),
                         "command/status/saved stdout link differs")


def source_contract(source, label):
    physical.require(label in REALIZATIONS, "unknown M10 image role")
    contract = verify_static_contract(source)
    physical.require((contract["realization"], contract["reviewed_source_anchors"]) in REALIZATIONS[label],
                     "source realization differs from declared role")
    physical.require(contract["formal_program_verification"] is False, "incorrect source-proof claim")
    return contract


def collect(output, build_root, binary_kind, label):
    physical.require(output.parent == (ROOT / "artifacts/generated").resolve()
                     and output.name.startswith("m10-") and not output.exists(),
                     "new direct M10 generated child required")
    physical.require(binary_kind in ("delivered", "consumer"), "default CLI/consumer required")
    before, binaries, receipts = physical.checked_builds(build_root, binary_kind)
    manifest_sha = physical.sha(build_root / "source.json")
    if label == "baseline":
        physical.require(manifest_sha == BASELINE_MANIFEST, "M10 prepatch baseline differs")
    contract = source_contract((build_root / "source/crates/kem1536/src/dev_kem.rs").read_text("utf-8-sig"), label)
    output.mkdir()
    for name in before:
        destination = physical.member(output / "sources", name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(physical.member(build_root / "source", name).read_bytes())
    (output / "inputs").mkdir()
    (output / "inputs/source.json").write_bytes((build_root / "source.json").read_bytes())
    for host, path in receipts.items():
        (output / "inputs" / (host + "-build.json")).write_bytes(path.read_bytes())
    (output / "controls").mkdir()
    for name in CONTROLS:
        (output / "controls" / name).write_bytes(Path(__file__).with_name(name).read_bytes())
    images = {}
    for host, binary in binaries.items():
        folder = output / host
        folder.mkdir()
        original = binary.read_bytes()
        physical.require(original[:4] == b"\x7fELF" if host == "linux" else original[:2] == b"MZ",
                         "unexpected image format")
        prefix, path, commands = ["wsl.exe", "-d", "Ubuntu-22.04", "--"], physical.wsl_path(binary), []
        listing = physical.invoke(prefix + ["objdump", "-d", "-C", "--no-show-raw-insn", path], commands)
        headers = physical.invoke(prefix + ["objdump", "-x", path], commands)
        versions = physical.invoke(prefix + ["objdump", "--version"], commands)
        relocations = physical.invoke(prefix + ["readelf", "-Wr", path], commands) if host == "linux" else b""
        physical.require(b"architecture: i386:x86-64" in headers, "x86-64 image required")
        physical.require(binary.read_bytes() == original, "image changed during collection")
        physical.gzip_write(folder / "binary.gz", original)
        physical.gzip_write(folder / "disassembly.txt.gz", listing)
        (folder / "headers.txt").write_bytes(headers)
        (folder / "relocations.txt").write_bytes(relocations)
        (folder / "objdump-version.txt").write_bytes(versions)
        physical.save(folder / "commands.json", commands)
        physical.save(folder / "inventory.json", physical.summarize(listing.decode("utf-8"), relocations.decode("utf-8")))
        images[host] = {"original_path": binary.relative_to(ROOT).as_posix(),
                        "sha256": physical.digest(original), "bytes": len(original)}
    physical.require(physical.checked_builds(build_root, binary_kind) == (before, binaries, receipts),
                     "source/build/image inputs changed during collection")
    physical.save(output / "collection.json", {
        "schema": "m10-secret-inventory-v1", "profile": "KEM1536-DEV-Q7681-R1", "role": label,
        "binary_kind": binary_kind, "source_contract": contract, "source_sha256": before,
        "source_manifest_sha256": manifest_sha, "images": images,
        "build_root_relative": build_root.relative_to(ROOT).as_posix(),
        "build_receipt_sha256": {host: physical.sha(path) for host, path in receipts.items()},
        "control_sha256": {name: physical.sha(output / "controls" / name) for name in CONTROLS},
        "fresh_machine_collection": True, "external_review_performed": False,
    })
    physical.save(output / "provenance.json", {"schema": "m10-secret-inventory-receipt-v1",
                                              "members_sha256": physical.tracked_files(output)})
    return verify(output)


def verify(output):
    receipt = physical.read(output / "provenance.json")
    physical.require(receipt["schema"] == "m10-secret-inventory-receipt-v1", "receipt schema differs")
    files = physical.tracked_files(output)
    files.pop("provenance.json")
    physical.require(files == receipt["members_sha256"], "secret inventory members differ")
    for name, expected in receipt["members_sha256"].items():
        physical.require(physical.sha(physical.member(output, name)) == expected, "unsafe/changed member")
    collection = physical.read(output / "collection.json")
    physical.require(collection["schema"] == "m10-secret-inventory-v1"
                     and collection["profile"] == "KEM1536-DEV-Q7681-R1"
                     and collection["binary_kind"] in ("delivered", "consumer")
                     and set(collection["images"]) == {"windows", "linux"}
                     and collection["fresh_machine_collection"] is True
                     and collection["external_review_performed"] is False, "collection scope differs")
    physical.require(set(physical.SOURCES).issubset(collection["source_sha256"]), "core source inputs absent")
    physical.require(set(collection["control_sha256"]) == set(CONTROLS)
                     and physical.tracked_files(output / "controls") == collection["control_sha256"],
                     "reader closure differs")
    manifest_sha = physical.sha(output / "inputs/source.json")
    physical.require(manifest_sha == collection["source_manifest_sha256"]
                     and physical.read(output / "inputs/source.json")["source_sha256"] == collection["source_sha256"]
                     and physical.tracked_files(output / "sources") == collection["source_sha256"],
                     "complete captured source manifest differs")
    if collection["role"] == "baseline":
        physical.require(manifest_sha == BASELINE_MANIFEST, "M10 prepatch baseline differs")
    contract = source_contract((output / "sources/crates/kem1536/src/dev_kem.rs").read_text("utf-8-sig"),
                               collection["role"])
    physical.require(contract == collection["source_contract"], "source/realization link differs")
    counts = {}
    for host, image in collection["images"].items():
        folder = output / host
        build_path = output / "inputs" / (host + "-build.json")
        physical.require(physical.sha(build_path) == collection["build_receipt_sha256"][host], "build receipt differs")
        entry = physical.check_build_scope(physical.read(build_path), host, collection["binary_kind"], manifest_sha)
        physical.require(entry["sha256"] == image["sha256"]
                         and collection["build_root_relative"] + "/" + entry["path"] == image["original_path"],
                         "build/image/source link differs")
        with gzip.open(folder / "binary.gz", "rb") as stream:
            binary = stream.read()
        physical.require(physical.digest(binary) == image["sha256"] and len(binary) == image["bytes"], "image differs")
        physical.require(binary[:4] == b"\x7fELF" if host == "linux" else binary[:2] == b"MZ", "image format differs")
        headers = (folder / "headers.txt").read_bytes()
        versions = (folder / "objdump-version.txt").read_bytes()
        relocations = (folder / "relocations.txt").read_bytes()
        physical.require(b"architecture: i386:x86-64" in headers, "architecture differs")
        with gzip.open(folder / "disassembly.txt.gz", "rb") as stream:
            listing = stream.read()
        check_commands(physical.read(folder / "commands.json"), host, image["original_path"],
                       listing, headers, versions, relocations)
        inventory = physical.summarize(listing.decode("utf-8"), relocations.decode("utf-8"))
        physical.require(inventory == physical.read(folder / "inventory.json"), "physical-address inventory differs")
        counts[host] = {"physical_functions": len(inventory["physical_functions"]),
                        "engine_roots": len(inventory["engine_roots"]),
                        "reachable_functions": len(inventory["direct_or_relative_slot_reachable"]),
                        "unresolved_transfers": len(inventory["unresolved_or_external_in_scope"]),
                        "division_sites": len(inventory["division_sites_in_scope"])}
    return {"role": collection["role"], "binary_kind": collection["binary_kind"], "images": counts,
            "source_contract": contract, "new_objdump_on_verify": False, "external_review": False,
            "complete_erasure_proved": False, "constant_time_proved": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("collect", "verify"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--build-root", type=Path)
    parser.add_argument("--binary-kind", choices=("delivered", "consumer"), default="delivered")
    parser.add_argument("--label", choices=tuple(REALIZATIONS))
    args = parser.parse_args()
    if args.action == "collect":
        physical.require(args.build_root is not None and args.label is not None, "build root and role required")
        result = collect(args.output.resolve(), args.build_root.resolve(), args.binary_kind, args.label)
    else:
        physical.require(args.build_root is None and args.label is None, "replay uses captured inputs only")
        result = verify(args.output.resolve())
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
