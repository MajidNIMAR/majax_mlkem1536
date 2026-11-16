"""Collect and replay a bounded review of the original M07 candidate binaries.

Collection is prohibited until the recorded memory/latency acceptance marker.
This does not prove constant time, complete indirect-call closure, every copy's
provenance, or erasure of all registers, paths and secret owners.
"""

import argparse
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

from inspect_m03_binary import inventory, parse_disassembly, resolve_elf_relocations
from review_m06_binary import instructions, inverse_copy_contract, zero_store_loops

ROOT = Path(__file__).resolve().parents[1]
CORE = {
    "crates/kem1536/src/dev_kem.rs": "3b7594bf96b6dcf3a52001582f8ab832da774ed059db66999e0e5091c8c8d48b",
    "crates/kem1536/src/engine_poly.rs": "ffe7b50dfebfe8d9998296672bd1973a8376a02cb06f2338418e27f23a392ac2",
    "crates/kem1536/src/secret_box.rs": "08d6ba7accadb46dc66b780a396dc418950641b29a91d365e12537001c40d28e",
}
BINARIES = {
    ("windows", "research"): "66ad042a53ad4fd55b251b6fd091550efc70e0c7a5df861d3824235907b83156",
    ("windows", "delivered"): "c707186a5da83d5a5ed4523d713bdb204c95412818d8d18ba0a9ba9029105f33",
    ("linux", "research"): "af546cdf1469959e6ff078f8e9fbc72efe717e5f28db10441fddda8d223b62f0",
    ("linux", "delivered"): "da097bdcd1340e6766791abdc1eb416e5fba4c1ebf8d2a775359a49a7e205014",
}
REFERENCE_BINARIES = {
    "windows": "2f68e65fd193c0e5b272771ec74fe71fd9d23169c41ae990f875f159e724552a",
    "linux": "d83068e57ddc7e0da0145cd903976ed360a4d1afd163eec25b8086748f537115",
}
NTT = "kem1536::engine_poly::"
HELPERS = ("Polynomial::forward_into", "NttPolynomial::multiply_add_assign",
           "NttPolynomial::inverse_into", "transform")
OWNER_LAYOUTS = {
    # coefficient, transformed array, product, matrix_entry, sum; then
    # secret, value, v, left, right, sum. Labels were traced from call arguments.
    ("windows", "research"): ((0x80, 0x480, 0x280, 0x1080, 0x1280),
                              (0x50, 0xa50, 0x250, 0x850, 0x650),
                              (0x70, 0x870, 0x270, 0x470, 0xa70, 0x670)),
    ("windows", "delivered"): ((0xcc0, 0xc0, 0xec0, 0x10c0, 0x12c0),
                               (0x50, 0xa50, 0x250, 0x850, 0x650),
                               (0x770, 0x970, 0x370, 0x570, 0x170, 0xb70)),
    ("linux", "research"): ((0x58, 0x658, 0x458, 0x1258, 0x258),
                            (0x38, 0xa38, 0x238, 0x838, 0x438),
                            (0x48, 0xa48, 0x248, 0x448, 0x648, 0x848)),
    ("linux", "delivered"): ((0xa0, 0x2a0, 0x10a8, 0x12a8, 0xea8),
                             (0x38, 0xa38, 0x238, 0x838, 0x438),
                             (0x748, 0x948, 0x148, 0x548, 0x348, 0xb48)),
}
DECODERS = {("windows", "research"): 0x14005b4e0, ("windows", "delivered"): 0x140056cd0,
            ("linux", "research"): 0x2a8770, ("linux", "delivered"): 0x2bacb0}


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    return digest(Path(path).read_bytes())


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def save(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def focus(name):
    """Include the retained Rust/LLVM names, not only demangled core names."""
    return (("kem1536::dev_kem::" in name and any(part in name for part in
             ("from_bytes", "validate_vector_encoding", "decode_polynomial_into", "keygen",
              "pke_encrypt", "pke_decrypt", "decapsulate", "pack_into", "unpack_coefficient")))
            or "kem1536::engine_poly::" in name
            or "kem1536::secret_box::" in name
            or name.startswith("_ZN7kem15367dev_kem"))


def address_bodies(text):
    """Do not collapse distinct monomorphisations with the same demangled name."""
    labels = list(re.finditer(r"^([0-9a-f]+) <(.+)>:$", text, re.M))
    result = {}
    for index, label in enumerate(labels):
        address, name = label.groups()
        identifier = address + ":" + name
        require(identifier not in result, "duplicate function label at the same address")
        result[identifier] = dict(name=name, address=address,
            body=text[label.start():labels[index + 1].start() if index + 1 < len(labels) else len(text)].rstrip())
    return result


def zero_store_loops_m07(body):
    """Apply the unchanged M06 loop grammar to the observed public counters.

    Renaming affects only recognition; the retained listing is never rewritten.
    A loop is accepted only when its original seed uses the selected register.
    """
    seeds = {address: (op, args) for address, op, args in instructions(body)}
    result = []
    for short, wide in (("%eax", "%rax"), ("%ecx", "%rcx"), ("%edx", "%rdx"),
                        ("%esi", "%rsi"), ("%edi", "%rdi"), ("%r8d", "%r8"),
                        ("%r9d", "%r9"), ("%r10d", "%r10"), ("%r11d", "%r11")):
        # Reviewed KG prefixes reload/address different saved registers. These
        # mov/lea instructions change neither flags, rsp nor the wipe storage.
        kept, active_seed, skipped = [], None, {}
        for line in body.splitlines():
            parsed = instructions(line)
            if parsed:
                address, opcode, args = parsed[0]
                if opcode == "mov" and re.fullmatch(r"\$0x[0-9a-f]+," + re.escape(short), args):
                    active_seed = address
                elif active_seed and (opcode, args) in {
                        ("mov", "0x10(%rsp),%r13"), ("mov", "0x8(%rsp),%r14"),
                        ("mov", "0x30(%rsp),%rdi"), ("mov", "0xb0(%rsp),%r13"),
                        ("lea", "0x48(%rsp),%rdi")} and args.rsplit(",", 1)[-1] != wide:
                    skipped.setdefault(active_seed, []).append(dict(address=address, opcode=opcode, operands=args))
                    continue
                elif not (opcode in ("data16", "cs", "nop", "nopw", "nopl")
                          or (opcode == "xchg" and args == "%ax,%ax")):
                    active_seed = None
            kept.append(line)
        renamed = "\n".join(kept)
        if wide != "%rax":
            # Protect an unrelated original rax, so mixed-counter stores can
            # never become apparently identical through textual renaming.
            renamed = re.sub(r"%eax\b", "%m07_original_eax", renamed)
            renamed = re.sub(r"%rax\b", "%m07_original_rax", renamed)
        renamed = re.sub(re.escape(short) + r"\b", "%eax", renamed)
        renamed = re.sub(re.escape(wide) + r"\b", "%rax", renamed)
        for loop in zero_store_loops(renamed):
            opcode, args = seeds[loop["seed_address"]]
            if opcode == "mov" and args.endswith("," + short):
                result.append(dict(**loop, counter_register=wide,
                                   reviewed_independent_prefix_instructions=skipped.get(loop["seed_address"], [])))
    return sorted(result, key=lambda loop: int(loop["entry"], 16))


def analyze(audit, host, kind):
    audit = Path(audit)
    binary = gzip.decompress((audit / "binary.gz").read_bytes())
    require(digest(binary) == BINARIES[host, kind], "unreviewed M07 binary")
    text = gzip.decompress((audit / "disassembly.txt.gz").read_bytes()).decode()
    label_counts = Counter(re.findall(r"^[0-9a-f]+ <(.+)>:$", text, re.M))
    raw = address_bodies(text)
    funcs = parse_disassembly(text)
    addressed = {identifier: parse_disassembly(row["body"])[row["name"]]
                 for identifier, row in raw.items()}
    if host == "linux":
        resolve_elf_relocations(funcs, (audit / "relocations.txt").read_text())
        resolve_elf_relocations(addressed, (audit / "relocations.txt").read_text())
    calculated = inventory(funcs)
    retained = read(audit / "summary.json")
    require(retained["binary_sha256"] == digest(binary), "audit binary hash differs")
    for name in ("all_code", "R1_core", "directly_reachable", "core_functions", "reachable_functions"):
        require(retained[name] == calculated[name], "full binary inventory does not replay: " + name)
    require(not any("Polynomial::multiply_into" in name for name in funcs), "test-only product retained")
    rows = {}
    for identifier, item in addressed.items():
        name, body = raw[identifier]["name"], raw[identifier]["body"]
        if not focus(name):
            continue
        require(not item["divisions"], "division in examined crypto function: " + name)
        ins = instructions(body)
        calls = []
        for index, (address, op, args) in enumerate(ins):
            if op in ("call", "callq") and any(part in args for part in ("memcpy", "memmove")):
                calls.append(dict(address=address, instruction=op + " " + args,
                                  preceding_instructions=[dict(address=a, opcode=o, operands=v)
                                      for a, o, v in ins[max(0, index - 6):index]]))
        try:
            wipes = dict(recognised=zero_store_loops_m07(body), unmodelled_shape=None)
        except ValueError as error:
            wipes = dict(recognised=[], unmodelled_shape=str(error))
        rows[identifier] = dict(name=name, body_sha256=digest(body.encode()), address=item["address"],
                          divisions=item["divisions"], conditional_branches=item["conditional_branches"],
                          calls=item["calls"], indirect_transfers=item["indirect_transfers"],
                          copy_calls=calls, literal_zero_store_loops_before_first_ret=wipes,
                          owner_provenance_and_all_paths_proved=False)
    for suffix in HELPERS:
        require(sum(row["name"] == NTT + suffix for row in rows.values()) == 1,
                "required NTT helper absent or ambiguous: " + suffix)
    inverse, = [identifier for identifier, row in rows.items()
                if row["name"] == NTT + "NttPolynomial::inverse_into"]
    copy = inverse_copy_contract(raw[inverse]["body"], host)
    import_names = {kind: [identifier for identifier, row in rows.items()
                          if row["name"].endswith(kind + "::from_bytes")]
                    for kind in ("EncapsulationKey", "DecapsulationKey")}
    # Whole-program optimisation may integrate an import into its callers.
    # Absence is recorded; those exact callers need the separate human review.
    require(all(len(names) <= 1 for names in import_names.values()), "import API symbols ambiguous")
    keygen_layout, encryption_layout, decryption_layout = OWNER_LAYOUTS[host, kind]
    owner_functions = {}
    for operation, offsets, labels in (
            ("keygen", keygen_layout, ("coefficient", "transformed_s", "product", "matrix_entry", "sum")),
            ("encrypt", encryption_layout, ("coefficient", "transformed_r", "product", "matrix_entry", "sum")),
            ("decrypt", decryption_layout, ("secret_then_inverse", "value", "v", "left", "right", "sum"))):
        if operation == "keygen":
            selected = [identifier for identifier, row in rows.items()
                        if row["name"] == "kem1536::dev_kem::" + ("keygen_internal" if kind == "research" else "keygen")]
        elif operation == "encrypt":
            selected = [identifier for identifier, row in rows.items() if "pke_encrypt_into" in row["name"]]
        else:
            selected = [identifier for identifier, row in rows.items()
                        if row["name"] == "kem1536::dev_kem::" + ("pke_decrypt" if kind == "research" else "decapsulate")]
        require(len(selected) == 1, "owner function absent or ambiguous")
        identifier, = selected
        loops = rows[identifier]["literal_zero_store_loops_before_first_ret"]["recognised"]
        covered = {byte for loop in loops for byte in range(loop["stack_interval_inclusive"][0],
                                                           loop["stack_interval_inclusive"][1] + 1)}
        targets = []
        for label, start in zip(labels, offsets):
            size = 3072 if label.startswith("transformed_") else 512
            require(set(range(start, start + size)) <= covered, "targeted owner wipe is incomplete: " + identifier + "/" + label)
            targets.append(dict(label=label, bytes=size, stack_interval_inclusive=[start, start + size - 1]))
        owner_functions[operation] = dict(function=identifier, targets=targets,
            identity_basis="manual trace of original call arguments, never inference from initialization order",
            literal_coverage_passed=True, all_path_execution_proved=False)
    validators = [identifier for identifier, row in rows.items() if "validate_vector_encoding" in row["name"]]
    scan = dict(named_validator_retained=bool(validators), imports_absent_are_not_assumed_integrated=True)
    if validators:
        require(len(validators) == 1, "validator absent or ambiguous")
        identifier, = validators
        normal = instructions(raw[identifier]["body"], normal_prefix=True)
        decoder = DECODERS[host, kind]
        positions = [index for index, (_, op, args) in enumerate(normal) if op in ("call", "callq")
                     and re.match(r"[0-9a-f]+", args) and int(args.split()[0], 16) == decoder]
        require(len(positions) == 6, "validator no longer has its six unrolled decode calls")
        require(not any(op.startswith("j") or op.startswith("loop") for _, op, _ in normal[:positions[-1] + 1]),
                "control transfer appeared before all six decode calls")
        checked = 0x40 if host == "windows" else 0x28
        loops = rows[identifier]["literal_zero_store_loops_before_first_ret"]["recognised"]
        require(any(loop["stack_interval_inclusive"] == [checked, checked + 511] for loop in loops),
                "validation checked owner wipe absent")
        scan.update(function=identifier, decoder_address=hex(decoder),
                    unrolled_decode_calls=[normal[index][0] for index in positions],
                    branch_before_six_decode_calls=False, checked_owner_interval_inclusive=[checked, checked + 511])
    return dict(schema="m07-bounded-binary-review-v1", host=host, kind=kind,
                binary_sha256=digest(binary), functions=rows, inverse_copy_contract=copy,
                named_validation_symbols={part: [identifier for identifier, row in rows.items()
                                                 if part in row["name"]]
                                          for part in ("validate_vector_encoding", "decode_polynomial_into")},
                distinct_function_labels=len(raw), focused_symbols_reviewed_by_address=True,
                duplicated_focused_demangled_names={name: count for name, count in label_counts.items()
                                                   if count > 1 and focus(name)},
                address_distinct_totals=dict(functions=len(addressed),
                    instructions=sum(row["instructions"] for row in addressed.values()),
                    conditional_branches=sum(len(row["conditional_branches"]) for row in addressed.values()),
                    divisions=sum(len(row["divisions"]) for row in addressed.values())),
                full_inventory_recomputed=True, test_only_old_product_absent=True,
                division_in_examined_crypto_functions=False, import_api_symbols=import_names,
                targeted_owner_functions=owner_functions, validation_scan_contract=scan,
                constant_time_proved=False, complete_indirect_target_set_proved=False,
                all_copies_erased_proved=False, all_secret_owners_erased_proved=False,
                limits="literal loop and ABI copy recognition plus separate human source/call-site review; no full CFG/dataflow, registers, spills, abnormal-return or system-library erasure proof")


def collect(run, output, resume=False):
    run, output = Path(run).resolve(), Path(output).resolve()
    marker = run / "MEMORY_AND_LATENCY_ACCEPTED.json"
    # This check precedes all subprocesses and disassembly.
    require(marker.is_file(), "wait for MEMORY_AND_LATENCY_ACCEPTED.json before any objdump")
    require(output.is_relative_to(ROOT / "artifacts/generated") and
            (not output.exists() or (resume and not (output / "collection.json").exists()
                                     and not (output / "provenance.json").exists())),
            "new output or explicitly resumed incomplete M07 collection required")
    source_manifest = read(run / "candidate-source.json")
    for name, expected in source_manifest["source_sha256"].items():
        require(sha(run / "candidate-source" / name) == expected, "frozen candidate source changed: " + name)
    require({name: source_manifest["source_sha256"][name] for name in CORE} == CORE,
            "M07 core differs from the source under review")
    before = {}
    for host, kind in BINARIES:
        build = read(run / "candidate" / host / "build.json")
        entry = build["binaries"][kind]
        require(build["source_manifest_sha256"] == sha(run / "candidate-source.json"), "build source receipt differs")
        require(entry["sha256"] == BINARIES[host, kind] == sha(run / entry["path"]), "original candidate executable changed")
        require("release: 1.91.1" in entry["rustc"], "unexpected compiler")
        before[host + "-" + kind] = entry
    output.mkdir(parents=True, exist_ok=resume)
    (output / "inputs").mkdir(exist_ok=resume)
    def copy_input(source, destination):
        if destination.exists():
            require(resume and sha(source) == sha(destination), "incomplete collection input differs")
        else:
            shutil.copyfile(source, destination)
    copy_input(marker, output / "inputs/MEMORY_AND_LATENCY_ACCEPTED.json")
    copy_input(run / "candidate-source.json", output / "inputs/candidate-source.json")
    for host in ("windows", "linux"):
        copy_input(run / "candidate" / host / "build.json", output / "inputs" / (host + "-build.json"))
    for name in CORE:
        destination = output / "source" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        copy_input(run / "candidate-source" / name, destination)
    for host, kind in BINARIES:
        entry = before[host + "-" + kind]
        audit = output / "audit" / (host + "-" + kind)
        command = [sys.executable, "-B", str(ROOT / "research/inspect_m03_binary.py"),
                   "--binary", str(run / entry["path"]), "--output", str(audit)]
        if audit.exists():
            require(resume and (audit / "summary.json").is_file()
                    and read(audit / "summary.json")["binary_sha256"] == entry["sha256"],
                    "incomplete audit cannot be resumed or differs")
        else:
            with (output / (host + "-" + kind + "-inspection.log")).open("xb") as log:
                subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
        result = analyze(audit, host, kind)
        if (audit / "review.json").exists():
            require(resume and read(audit / "review.json") == result, "existing incomplete review differs")
        else:
            save(audit / "review.json", result)
        require(sha(run / entry["path"]) == entry["sha256"], "binary changed during collection")
    save(output / "collection.json", dict(original_run=str(run), core_sha256=CORE,
         marker_sha256=sha(marker), source_manifest_sha256=sha(run / "candidate-source.json"),
         binaries=before, manual_observations_required=True))
    return dict(collected_original_executables=4, output=str(output), human_review_still_required=True)


def verify_contents(output):
    output = Path(output).resolve()
    collection = read(output / "collection.json")
    require(collection["core_sha256"] == CORE, "reviewed core differs")
    require(sha(output / "inputs/MEMORY_AND_LATENCY_ACCEPTED.json") == collection["marker_sha256"], "acceptance marker differs")
    require(sha(output / "inputs/candidate-source.json") == collection["source_manifest_sha256"], "source manifest differs")
    source_manifest = read(output / "inputs/candidate-source.json")
    for name, checksum in CORE.items():
        require(sha(output / "source" / name) == source_manifest["source_sha256"][name] == checksum,
                "review source differs")
    for host, kind in BINARIES:
        build = read(output / "inputs" / (host + "-build.json"))
        entry = build["binaries"][kind]
        require(build["host"] == host and build["profile"] == "KEM1536-DEV-Q7681-R1"
                and build["source_manifest_sha256"] == collection["source_manifest_sha256"],
                "build source/host association differs")
        require(entry == collection["binaries"][host + "-" + kind]
                and entry["sha256"] == BINARIES[host, kind] and "release: 1.91.1" in entry["rustc"],
                "build executable association differs")
        audit = output / "audit" / (host + "-" + kind)
        require(read(audit / "review.json") == analyze(audit, host, kind), "bounded binary review does not replay")
    references = read(output / "reference-inputs.json")
    reference_manifest = read(output / "inputs-reference/baseline-source.json")
    require(sha(output / "inputs-reference/baseline-source.json") == references["source_manifest_sha256"],
            "reference source manifest differs")
    for name, checksum in references["core_sha256"].items():
        require(sha(output / "source-reference" / name) == reference_manifest["source_sha256"][name] == checksum,
                "reference core differs")
    require(references["core_sha256"]["crates/kem1536/src/dev_kem.rs"] ==
            "eb7635eedc73c3db93d7baa81a86817157969a82890f797acfb3694a767e0262", "not the M06 source")
    for host, checksum in REFERENCE_BINARIES.items():
        record = references["references"][host]
        build_path = output / "inputs-reference" / (host + "-build.json")
        build = read(build_path)
        require(sha(build_path) == record["build_sha256"]
                and build["host"] == host and build["source_manifest_sha256"] == references["source_manifest_sha256"]
                and build["binaries"]["research"] == record["binary"]
                and record["binary"]["sha256"] == checksum, "reference build binding differs")
        audit = (output / record["audit"]).resolve()
        require(audit.is_relative_to(output), "reference audit escapes receipt")
        require(digest(gzip.decompress((audit / "binary.gz").read_bytes())) == checksum,
                "reference executable differs")
        text = gzip.decompress((audit / "disassembly.txt.gz").read_bytes()).decode()
        funcs = parse_disassembly(text)
        if host == "linux":
            resolve_elf_relocations(funcs, (audit / "relocations.txt").read_text())
        computed, retained = inventory(funcs), read(audit / "summary.json")
        require(retained["binary_sha256"] == checksum, "reference summary differs")
        for field in ("all_code", "R1_core", "directly_reachable", "core_functions", "reachable_functions"):
            require(computed[field] == retained[field], "reference inventory does not replay: " + field)
    witnesses = read(output / "spill-witnesses.json")
    for witness in witnesses["witnesses"]:
        audit = (output / witness["audit"]).resolve()
        require(audit.is_relative_to(output), "spill witness audit escapes receipt")
        text = gzip.decompress((audit / "disassembly.txt.gz").read_bytes()).decode()
        selected = [row for row in address_bodies(text).values()
                    if int(row["address"], 16) == int(witness["function_address"], 16)]
        require(len(selected) == 1 and digest(selected[0]["body"].encode()) == witness["body_sha256"],
                "spill witness function differs")
        ins = {address: [opcode, operands] for address, opcode, operands in instructions(selected[0]["body"])}
        for anchor in witness["instruction_anchors"]:
            require(ins[anchor["address"]] == [anchor["opcode"], anchor["operands"]], "spill witness instruction differs")
    return dict(full_inventories_and_bounded_reviews_replayed=4,
                reference_inventories_replayed=2, spill_instruction_witnesses_verified=len(witnesses["witnesses"]),
                new_objdump_run=False, all_copies_erased_proved=False, constant_time_proved=False)


def verify(output):
    output = Path(output).resolve()
    manifest = read(output / "provenance.json")
    require(manifest["schema"] == "m07-binary-review-receipt-v1", "unknown review receipt schema")
    expected = manifest["files_sha256"]
    actual = {p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()
              and p != output / "provenance.json"}
    require(actual == set(expected), "review receipt member inventory differs")
    for name, checksum in expected.items():
        member = (output / name).resolve()
        require(member.is_relative_to(output) and sha(member) == checksum, "review receipt checksum differs: " + name)
    return dict(frozen_members_verified=len(expected), **verify_contents(output))


def refresh(output):
    output = Path(output).resolve()
    require((output / "collection.json").is_file() and not (output / "provenance.json").exists(),
            "only an unsealed current collection may be refreshed")
    results = {(host, kind): analyze(output / "audit" / (host + "-" + kind), host, kind)
               for host, kind in BINARIES}
    for (host, kind), result in results.items():
        path = output / "audit" / (host + "-" + kind) / "review.json"
        path.write_text(json.dumps(result, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    return dict(unsealed_reviews_refreshed=4, disassembly_or_binaries_modified=False)


def seal(output):
    output = Path(output).resolve()
    observations = (output / "OBSERVATIONS.md").read_text(encoding="utf-8")
    require("M07" in observations and all(checksum in observations for checksum in BINARIES.values()),
            "human observations must identify all four exact binaries")
    # A failure must not create an immutable-looking provenance receipt.
    verify_contents(output)
    (output / "tools").mkdir()
    for name in ("review_m07_binary.py", "review_m06_binary.py", "inspect_m03_binary.py",
                 "test_review_m07_binary.py", "test_review_m06_binary.py"):
        shutil.copyfile(ROOT / "research" / name, output / "tools" / name)
    files = {p.relative_to(output).as_posix(): sha(p) for p in sorted(output.rglob("*")) if p.is_file()}
    require("provenance.json" not in files, "never replace a sealed review receipt")
    save(output / "provenance.json", dict(schema="m07-binary-review-receipt-v1", files_sha256=files,
         binaries_rebuilt_by_this_review=False, collection_and_manual_observations_distinct=True,
         complete_CT_or_erasure_proof=False))
    return verify(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("collect", "refresh", "seal", "verify"))
    parser.add_argument("--run", type=Path, default=ROOT / "artifacts/generated/m07-001")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/generated/m07-binary-001")
    parser.add_argument("--resume-collection", action="store_true", help="reuse only an incomplete unsealed audit")
    args = parser.parse_args()
    result = collect(args.run, args.output, args.resume_collection) if args.action == "collect" else (
        seal(args.output) if args.action == "seal" else (
            refresh(args.output) if args.action == "refresh" else verify(args.output)))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
