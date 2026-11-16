"""Replay literal witnesses for the rejected first M09 ABI-copy variant.

Source-to-data interpretation is an explicitly bounded internal review.  The
reader verifies preserved instructions and provenance, not a formal taint proof.
"""

import argparse
import gzip
import json
from pathlib import Path
import re

from m09_lifecycle_inventory import ROOT, parse, read, require, save, sha, tracked_files, verify as inventory_verify


SOURCE_MANIFEST = "89cec589ed2d8b8533cc263c1a22a7933f0f024263edef41c58acbb4dac67d1f"
FUNCTIONS = ("kem1536::dev_kem::pke_encrypt_into", "kem1536::dev_kem::decapsulate",
             "kem1536::engine_poly::Polynomial::forward_into", "kem1536::engine_poly::transform")


def body(functions, name):
    rows = [row for row in functions if row["name"] == name]
    require(len(rows) == 1, "expected reviewed function is absent or ambiguous")
    return rows[0]


def site(function, offset, opcode, operands):
    address = format(int(function["address"], 16) + offset, "x")
    rows = [row for row in function["instructions"] if row["address"] == address]
    require(len(rows) == 1 and rows[0]["opcode"] == opcode
            and rows[0]["operands"].split(" #", 1)[0].rstrip() == operands,
            "reviewed literal instruction differs at " + address)
    return {"function": function["name"], **rows[0]}


def facts(cli, consumer):
    result = {"schema": "m09-first-variant-lifecycle-review-v1", "candidate_rejected": True,
              "source_manifest_sha256": SOURCE_MANIFEST, "images": {},
              "reviewed_interpretation": "Last eight e2+Encode(m) coefficients retained in XMM8 cross the Windows ABI-preserving calls and are saved by table-vectorized transform outside their owner.",
              "ABI_reference": "https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-170#x64-register-usage",
              "ABI_assumption": "The imported memset and normal Rust calls conform to the Windows x64 nonvolatile XMM6..XMM15 convention. Runtime DLL internals were not inspected.",
              "scope_limits": {"protocol_leak_demonstrated": False, "all_144_saved_bytes_proved_secret": False,
                               "complete_taint_proof": False, "complete_erasure_proved": False,
                               "constant_time_proved": False, "external_review": False}}
    for kind, folder in (("cli", cli), ("consumer", consumer)):
        inventory_verify(folder)
        collection = read(folder / "collection.json")
        require(collection["source_manifest_sha256"] == SOURCE_MANIFEST, "different variant source")
        for host in ("windows", "linux"):
            with gzip.open(folder / host / "disassembly.txt.gz", "rt", encoding="utf-8") as stream:
                functions = parse(stream.read())
            selected = [body(functions, name) for name in FUNCTIONS]
            encryption, decapsulation, forward, transform = selected
            xmm_saves = [row for row in transform["instructions"]
                         if re.fullmatch(r"%xmm(?:[6-9]|1[0-4]),0x[0-9a-f]+\(%rsp\)", row["operands"])]
            frame = [row for row in transform["instructions"]
                     if row["opcode"] == "sub" and row["operands"].endswith(",%rsp")][0]
            entry = {"binary_sha256": collection["images"][host]["sha256"],
                     "collection_provenance_sha256": sha(folder / "provenance.json"),
                     "listing_sha256": sha(folder / host / "disassembly.txt.gz"),
                     "transform_frame_subtraction": frame,
                     "transform_XMM6_to_XMM14_save_instructions": xmm_saves,
                     "function_addresses": {row["name"]: row["address"] for row in selected}}
            if host == "windows":
                require(len(xmm_saves) == 9, "first variant's nine XMM save slots changed")
                forward_addr = format(int(forward["address"], 16), "x")
                transform_addr = format(int(transform["address"], 16), "x")
                pack = site(encryption, 0x6b2, "packssdw", "%xmm5,%xmm8")
                store = site(encryption, 0x6b7, "movdqu", "%xmm8,0x50(%rsp,%rax,2)")
                call = site(encryption, 0x74d, "call", forward_addr + " <" + forward["name"] + ">")
                tail = site(forward, 0x13a, "jmp", transform_addr + " <" + transform["name"] + ">")
                spill = site(transform, 0x4f, "movdqa", "%xmm8,0xd0(%rsp)")
                restore = site(transform, 0x672, "movaps", "0xd0(%rsp),%xmm8")
                require(not any(re.search(r",%xmm8$", row["operands"])
                                for row in forward["instructions"]), "forward overwrites XMM8")
                # The exact whole function is preserved by the listing hash.
                # These additional literals bound the owner loads and loop exit.
                entry["e2_message_XMM8_chain"] = [
                    site(encryption, 0x630, "movdqu", "0x50(%rsp,%rax,2),%xmm1"),
                    site(encryption, 0x642, "movdqu", "0x250(%rsp,%rax,2),%xmm3"),
                    pack, store, call, tail, spill, restore]
                entry["recovered_message_destination"] = site(decapsulation, 0x410, "or", "%r10b,0x40(%rsp,%r8,1)")
                entry["confirmed_additional_owner_external_copy_bytes"] = 16
                entry["all_saved_slots_erased"] = False
            else:
                require(len(xmm_saves) == 0, "unexpected Linux XMM save in first variant")
                entry["recovered_message_destination"] = site(decapsulation, 0x3ed, "or", "%r8b,0x20(%rsp,%rsi,1)")
                entry["same_Windows_copy_mechanism_observed"] = False
            result["images"][kind + "-" + host] = entry
    return result


def create(output, cli, consumer):
    require(output.parent == (ROOT / "artifacts/generated").resolve() and not output.exists(), "new generated review required")
    report = facts(cli, consumer)
    output.mkdir()
    save(output / "review.json", report)
    for name in ("m09_lifecycle_review.py", "m09_lifecycle_inventory.py"):
        (output / name).write_bytes((ROOT / "research" / name).read_bytes())
    (output / "source-review.md").write_bytes((ROOT / "docs/REVUE_CYCLE_SECRET_M09.md").read_bytes())
    (output / "README.md").write_text(
        "# First M09 variant: rejected ABI-copy finding\n\n"
        "The four collections are immutable raw evidence. The Windows XMM8 chain identifies "
        "a new 16-byte owner-external copy of e2+Encode(m) coefficients. The other ABI slots "
        "are not all proven secret. No protocol leak, global erasure or CT proof is claimed.\n\n"
        "Replay the retained literals and full collection provenance with the copied reader, "
        "passing --cli and --consumer to the two original collection directories. No binary "
        "or machine tool executes during verify. The semantic interpretation is a bounded "
        "internal review with the stated ABI assumption.\n", encoding="utf-8", newline="\n")
    save(output / "provenance.json", {"schema": "m09-lifecycle-review-receipt-v1",
                                      "members_sha256": tracked_files(output)})
    return verify(output, cli, consumer)


def verify(output, cli, consumer):
    provenance = read(output / "provenance.json")
    actual = tracked_files(output)
    actual.pop("provenance.json")
    require(provenance["schema"] == "m09-lifecycle-review-receipt-v1"
            and actual == provenance["members_sha256"], "review evidence changed")
    result = facts(cli, consumer)
    require(result == read(output / "review.json"), "reviewed literals or binding changed")
    return {"literal_image_reviews_replayed": len(result["images"]),
            "candidate_rejected": True, "Windows_confirmed_copy_bytes_per_image": 16,
            "all_144_bytes_classified_secret": False, "new_objdump_on_verify": False,
            "global_erasure_or_CT_proved": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("create", "verify"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--consumer", type=Path, required=True)
    args = parser.parse_args()
    action = create if args.action == "create" else verify
    print(json.dumps(action(args.output.resolve(), args.cli.resolve(), args.consumer.resolve()), indent=2))


if __name__ == "__main__":
    main()
