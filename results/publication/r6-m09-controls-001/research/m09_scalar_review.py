"""Collect/replay the bounded scalar M09 transform and message-owner review.

All replay inputs are saved listings and receipts. No compiler, binary or
objdump executes here. This is not a whole-program CT or erasure proof.
"""

import argparse
import gzip
import json
from pathlib import Path
import re

from m09_lifecycle_inventory import ROOT, parse, read, require, save, sha, tracked_files, verify as inventory_verify


REJECTED_PROVENANCE = "443641a7bf45422c1fb7b6f93ce5a99b549003a61dd2a7cf9f95d796a4722645"
TRANSFORM = "kem1536::engine_poly::transform"
DECAPSULATE = "kem1536::dev_kem::decapsulate"


def body(functions, name):
    rows = [row for row in functions if row["name"] == name]
    require(len(rows) == 1, "reviewed function absent or ambiguous: " + name)
    return rows[0]


def literal(function, opcode, operands):
    rows = [row for row in function["instructions"]
            if row["opcode"] == opcode and row["operands"].split(" #", 1)[0].rstrip() == operands]
    require(len(rows) == 1, "literal witness absent or ambiguous: " + operands)
    return {"function": function["name"], **rows[0]}


def split_operands(text):
    depth, start, result = 0, 0, []
    for index, character in enumerate(text):
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif character == "," and depth == 0:
            result.append(text[start:index].strip())
            start = index + 1
    result.append(text[start:].strip())
    return result


def scalar_fact(function, host):
    require(not any(re.search(r"%[xyz]mm", row["operands"])
                    for row in function["instructions"]), "SIMD register use returned to transform")
    require(not any(re.fullmatch(r"i?div[bwlq]?", row["opcode"])
                    for row in function["instructions"]), "division in transform")
    if host == "windows":
        frame = "$0x58,%rsp"
        expected_pushes = {"%r15", "%r14", "%r13", "%r12", "%rsi", "%rdi", "%rbp", "%rbx"}
        allowed_stores = {"%rdx,0x38(%rsp)", "%rcx,0x30(%rsp)", "%rcx,0x40(%rsp)",
                          "%rcx,0x50(%rsp)", "%rax,0x48(%rsp)", "%dx,0x2e(%rsp)"}
        public_chain = [("mov", "%rdx,0x38(%rsp)"), ("mov", "0x38(%rsp),%rax"),
                        ("lea", "(%rax,%r11,2),%r11"), ("movzwl", "(%r11,%r10,2),%edx"),
                        ("mov", "%dx,0x2e(%rsp)"), ("movzwl", "0x2e(%rsp),%edx")]
        owner_stores = [("mov", "%r14w,0x0(%r13,%r10,2)"), ("mov", "%r9w,(%r15,%r10,2)")]
    else:
        frame = "$0x38,%rsp"
        expected_pushes = {"%rbp", "%r15", "%r14", "%r13", "%r12", "%rbx"}
        allowed_stores = {"%rsi,0x18(%rsp)", "%rdi,0x10(%rsp)", "%rcx,0x20(%rsp)",
                          "%rsi,0x30(%rsp)", "%rax,0x28(%rsp)", "%di,0xe(%rsp)"}
        public_chain = [("mov", "%rsi,0x18(%rsp)"), ("mov", "0x18(%rsp),%rcx"),
                        ("lea", "(%rcx,%rax,2),%rbx"), ("movzwl", "(%rbx,%rax,2),%edi"),
                        ("mov", "%di,0xe(%rsp)"), ("movzwl", "0xe(%rsp),%edi")]
        owner_stores = [("mov", "%r14w,0x0(%r13,%rax,2)"), ("mov", "%r8w,(%r15,%rax,2)")]
    writes = []
    for row in function["instructions"]:
        arguments = split_operands(row["operands"].split(" #", 1)[0])
        if len(arguments) > 1 and re.search(r"\(%rsp(?:,[^)]*)?\)$", arguments[-1]):
            require(row["opcode"] in ("mov", "movw", "movq"), "unreviewed stack writer")
            writes.append(row)
    require(len(writes) == 6 and {row["operands"] for row in writes} == allowed_stores,
            "transform frame stores differ from reviewed public values")
    pushes = [row for row in function["instructions"] if row["opcode"] in ("push", "pushq")]
    require(len(pushes) == len(expected_pushes) and {row["operands"] for row in pushes} == expected_pushes,
            "nonvolatile GPR preservation set changed")
    return {"function_address": function["address"], "instruction_count": len(function["instructions"]),
            "frame_reservation": literal(function, "sub", frame),
            "ABI_GPR_pushes": pushes, "frame_writes_reviewed_as_public": writes,
            "public_table_to_stack_twiddle_chain": [literal(function, op, args) for op, args in public_chain],
            "secret_result_stores_into_owner": [literal(function, op, args) for op, args in owner_stores],
            "no_SIMD_in_this_function": True, "no_division_in_this_function": True,
            "prior_XMM8_save_mechanism_present": False,
            "interpretation": "Owner and table pointers, stage/stride counters, and one public twiddle are the six explicit frame stores. Secret butterfly values remain in GPRs and write back to the owner in this reviewed function. Incoming GPR saves remain an ABI obligation."}


def message_fact(function, host):
    offset = 0x40 if host == "windows" else 0x20
    destination = "%r10b,0x40(%rsp,%r8,1)" if host == "windows" else "%r8b,0x20(%rsp,%rsi,1)"
    write = literal(function, "or", destination)
    ret_index = next(index for index, row in enumerate(function["instructions"]) if row["opcode"] == "ret")
    normal = {row["address"] for row in function["instructions"][:ret_index]}
    wipes = [literal(function, "movb", "$0x0," + hex(offset + byte) + "(%rsp)") for byte in range(32)]
    require(all(row["address"] in normal and int(row["address"], 16) > int(write["address"], 16) for row in wipes),
            "message-owner normal-return wipes differ")
    return {"function_address": function["address"], "message_owner_offset": hex(offset),
            "recover_into_owner_instruction": write,
            "normal_return_32_literal_byte_wipes": wipes,
            "scope": "Recovered message is assembled into this Decaps owner and its 32 bytes have literal zero stores before the observed normal return. Other temporaries/registers/caller copies and all exception paths are not thereby proved erased."}


def facts(cli, consumer, expected_source, rejected_report, rejected_provenance):
    require(re.fullmatch(r"[0-9a-f]{64}", expected_source), "source-manifest SHA-256 required")
    require(sha(rejected_provenance) == REJECTED_PROVENANCE, "rejected review receipt differs")
    negative_receipt, negative = read(rejected_provenance), read(rejected_report)
    require(sha(rejected_report) == negative_receipt["members_sha256"]["review.json"]
            and negative["candidate_rejected"] is True, "rejected report differs")
    result = {"schema": "m09-scalar-targeted-review-v1", "source_manifest_sha256": expected_source,
              "rejected_review_provenance_sha256": REJECTED_PROVENANCE,
              "rejected_Windows_copy_bytes_per_image": 16, "images": {},
              "scope_limits": {"all_registers_or_ABI_copies_erased": False, "complete_PKE_erasure_proved": False,
                               "constant_time_proved": False, "external_review": False,
                               "new_binary_or_objdump_on_verify": False}}
    for kind, folder in (("cli", cli), ("consumer", consumer)):
        inventory_verify(folder)
        collection = read(folder / "collection.json")
        require(collection["source_manifest_sha256"] == expected_source, "reviewed scalar source differs")
        for host in ("windows", "linux"):
            with gzip.open(folder / host / "disassembly.txt.gz", "rt", encoding="utf-8") as stream:
                functions = parse(stream.read())
            result["images"][kind + "-" + host] = {
                "binary_sha256": collection["images"][host]["sha256"],
                "collection_provenance_sha256": sha(folder / "provenance.json"),
                "listing_sha256": sha(folder / host / "disassembly.txt.gz"),
                "transform": scalar_fact(body(functions, TRANSFORM), host),
                "message_owner": message_fact(body(functions, DECAPSULATE), host)}
    return result


def collect(output, cli, consumer, expected_source, rejected):
    require(output.parent == (ROOT / "artifacts/generated").resolve() and not output.exists(), "new generated review required")
    report = facts(cli, consumer, expected_source, rejected / "review.json", rejected / "provenance.json")
    output.mkdir()
    (output / "inputs").mkdir()
    for name in ("review.json", "provenance.json"):
        (output / "inputs" / ("rejected-" + name)).write_bytes((rejected / name).read_bytes())
    save(output / "review.json", report)
    for name in ("m09_scalar_review.py", "m09_lifecycle_inventory.py"):
        (output / name).write_bytes((ROOT / "research" / name).read_bytes())
    (output / "README.md").write_text(
        "# M09 scalar transform: targeted correction review\n\n"
        "The previous table-vectorized variant is rejected. Four new images retain a scalar "
        "transform without SIMD saves; the six explicit frame stores are traced to public "
        "pointers/counters/twiddle. This removes the specific XMM8-save mechanism. The "
        "message owner has 32 literal normal-return byte wipes in each image.\n\n"
        "This bounded internal review does not prove whole-program constant time, complete "
        "PKE erasure or erasure of all ABI/register/caller copies. Supply the two retained "
        "CLI/consumer collections to the copied reader's verify action. No compiler, binary "
        "or machine tool executes during verify.\n", encoding="utf-8", newline="\n")
    save(output / "provenance.json", {"schema": "m09-scalar-review-receipt-v1", "members_sha256": tracked_files(output)})
    return verify(output, cli, consumer)


def verify(output, cli, consumer):
    provenance = read(output / "provenance.json")
    actual = tracked_files(output)
    actual.pop("provenance.json")
    require(provenance["schema"] == "m09-scalar-review-receipt-v1"
            and actual == provenance["members_sha256"], "scalar review members changed")
    saved = read(output / "review.json")
    report = facts(cli, consumer, saved["source_manifest_sha256"], output / "inputs/rejected-review.json",
                   output / "inputs/rejected-provenance.json")
    require(report == saved, "scalar review literal/source/image binding differs")
    return {"scalar_image_reviews_replayed": 4, "prior_XMM8_save_mechanism_removed_in_reviewed_functions": True,
            "message_owner_normal_return_byte_wipes": 128, "new_objdump_on_verify": False,
            "global_erasure_or_CT_proved": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("collect", "verify"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--consumer", type=Path, required=True)
    parser.add_argument("--source-manifest-sha256")
    parser.add_argument("--rejected-review", type=Path)
    args = parser.parse_args()
    if args.action == "collect":
        require(args.source_manifest_sha256 is not None and args.rejected_review is not None,
                "explicit reviewed source SHA and rejected review required")
        result = collect(args.output.resolve(), args.cli.resolve(), args.consumer.resolve(),
                         args.source_manifest_sha256, args.rejected_review.resolve())
    else:
        require(args.source_manifest_sha256 is None and args.rejected_review is None, "verify uses retained inputs")
        result = verify(args.output.resolve(), args.cli.resolve(), args.consumer.resolve())
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
