"""Data-only, bounded instruction witnesses for the M10 lifecycle review.

Input inventories retain the images and full listings. This smaller recueil
binds their provenance hashes and replays the explicitly reviewed fragments.
No compiler, objdump or KEM image runs here. Whole-program taint, compiled
constant time and register/ABI erasure remain outside these checks.
"""
import argparse
import gzip
import json
from pathlib import Path
import re

import m09_lifecycle_inventory as physical
import m10_secret_inventory as inventory
from m09_scalar_review import split_operands


CONTROLS = (*inventory.CONTROLS, "m09_scalar_review.py", "m10_secret_review.py")
NOISE = "kem1536::dev_kem::noise_into"
DECAP = "kem1536::dev_kem::decapsulate"
ASSIGN = "kem1536::dev_kem::assign_shared_secret_into"


def body(functions, name):
    rows = [f for f in functions if f["name"] == name]
    physical.require(len(rows) == 1, "physical function missing/ambiguous: " + name)
    return rows[0]


def literal(function, opcode, operands):
    rows = [r for r in function["instructions"] if r["opcode"] == opcode
            and r["operands"].split(" #", 1)[0].rstrip() == operands]
    physical.require(len(rows) == 1, "literal instruction missing/ambiguous: " + operands)
    return rows[0]


def normal(function):
    instructions = function["instructions"]
    end = next(i for i, row in enumerate(instructions) if row["opcode"] in ("ret", "retq"))
    return instructions[:end + 1]


def check_collection_scope(collection, kind, role):
    physical.require(kind in ("cli", "consumer") and role in ("baseline", "candidate"), "unknown review slot")
    expected_kind = "delivered" if kind == "cli" else "consumer"
    physical.require(collection["binary_kind"] == expected_kind and collection["role"] == role,
                     "collection does not fill its declared CLI/consumer and baseline/candidate slot")


def load(folder, kind, role):
    result = inventory.verify(folder)
    collection = physical.read(folder / "collection.json")
    check_collection_scope(collection, kind, role)
    listings = {}
    for host in ("windows", "linux"):
        with gzip.open(folder / host / "disassembly.txt.gz", "rt", encoding="utf-8") as stream:
            listings[host] = physical.parse(stream.read())
    identity = {"collection_provenance_sha256": physical.sha(folder / "provenance.json"),
                "source_manifest_sha256": collection["source_manifest_sha256"],
                "source_contract": result["source_contract"], "images": collection["images"]}
    return identity, listings


def stack_writers(rows):
    result = []
    for row in rows:
        args = split_operands(row["operands"].split(" #", 1)[0])
        if len(args) < 2 or "%rsp" not in args[-1]:
            continue
        if row["opcode"].startswith(("mov", "xor", "or", "and", "add", "sub")):
            result.append(row)
    return result


def direct_overlap_writers(rows, start, length):
    result = []
    for row in stack_writers(rows):
        destination = split_operands(row["operands"].split(" #", 1)[0])[-1]
        match = re.fullmatch(r"(?:(0x[0-9a-f]+|[0-9]+))?\(%rsp\)", destination)
        if match:
            address = int(match[1], 0) if match[1] else 0
            width = {"movb": 1, "movw": 2, "movl": 4, "movq": 8,
                     "movups": 16, "movaps": 16}.get(row["opcode"])
            suffix = re.fullmatch(r"(?:mov|xor|or|and|add|sub)([bwlq])", row["opcode"])
            if width is None and suffix:
                width = {"b": 1, "w": 2, "l": 4, "q": 8}[suffix[1]]
            if width is None:
                source = split_operands(row["operands"].split(" #", 1)[0])[0]
                if re.fullmatch(r"%[abcd]l|%[abcd]h|%[sd]il|%[bs]pl|%r[0-9]+b", source):
                    width = 1
                elif re.fullmatch(r"%[abcd]x|%[sd]i|%[bs]p|%r[0-9]+w", source):
                    width = 2
                elif re.fullmatch(r"%e[a-z]+|%r[0-9]+d", source):
                    width = 4
                elif re.fullmatch(r"%r[a-z0-9]+", source):
                    width = 8
            physical.require(width is not None, "unreviewed direct frame store width: " + str(row))
            if address < start + length and address + width > start:
                result.append(row)
    return result


def rejected_noise_fact(functions, host, role):
    f = body(functions, NOISE)
    original, consumed, reader, noise = {
        ("baseline", "windows"): (0x100, 0x1d0, 0x30, 0x1d0),
        ("baseline", "linux"): (0xe0, 0x1b0, 0x10, 0x1b0),
        ("candidate", "windows"): (0x1c0, 0x298, 0x30, 0x100),
        ("candidate", "linux"): (0x1a0, 0x270, 0x10, 0xe0),
    }[role, host]
    rows = normal(f)
    source_register, size_register = ("%rdx", "%r8d") if host == "windows" else ("%rsi", "%edx")
    sizes = [i for i, r in enumerate(rows) if r["opcode"] == "mov"
             and r["operands"] == "$0xd0," + size_register]
    physical.require(len(sizes) == 1, "consuming state copy size changed")
    size_at = sizes[0]
    source = [r for r in rows[max(0, size_at - 3):size_at]
              if r["opcode"] == "lea" and r["operands"] == hex(original) + "(%rsp)," + source_register]
    physical.require(len(source) == 1, "consuming copy source is not the absorbed original state")
    call_at = next(i for i in range(size_at, size_at + 4) if rows[i]["opcode"].startswith("call"))
    absorb = [r for r in rows[:call_at] if r["opcode"].startswith("call")
              and "absorb_u64_le" in r["operands"]]
    physical.require(len(absorb) == 4, "N framing no longer has the four reviewed absorb calls")
    physical.require(literal(f, "mov", "$0x20," + ("%r9d" if host == "windows" else "%ecx")) in rows,
                     "seed32 absorption absent")
    post = rows[call_at + 1:]
    physical.require(not direct_overlap_writers(post, original, 201),
                     "the original state now has a direct frame writer; negative witness must be reviewed")
    permutations = [i for i, r in enumerate(post) if r["opcode"].startswith("call")
                    and "keccak_p" in r["operands"]]
    physical.require(len(permutations) == 2, "two noise squeezes changed")
    wipe_suffix = {"instructions": post[permutations[-1] + 1:]}
    zero_reader = [literal(wipe_suffix, "movq", "$0x0," + hex(reader + i) + "(%rsp)")
                   for i in range(0, 200, 8)]
    physical.require(all(r in post for r in zero_reader), "reader state wipes no longer match")
    physical.require(literal(wipe_suffix, "movb", "$0x0," + hex(reader + 200) + "(%rsp)") in post,
                     "reader cursor wipe absent")
    return {"function": f, "normal_return": rows[-1], "framing_lengths": [21, 2, 32, 1],
            "SHAKE256_rate_bytes": 136, "original_state_frame_offset": original,
            "consumed_state_frame_offset": consumed, "reader_frame_offset": reader,
            "noise_owner_frame_offset": noise,
            "literal_seed32_frame_range_inclusive": [original + 23, original + 54],
            "four_absorb_calls": absorb, "consuming_copy": rows[max(0, size_at - 3):call_at + 1],
            "reader_state_zero_stores": zero_reader,
            "normal_postcopy_explicit_stack_writers": stack_writers(post),
            "original_not_covered_by_reviewed_normal_wipes": True,
            "claim": "Observed local pre-padding state persists through this normal return; N has 56 input bytes and its 32 seed bytes occur literally at state+23..+54. Indexed writes and callees are retained, not abstracted into a universal taint proof."}


def assignment_fact(functions, host):
    f, decap = body(functions, ASSIGN), body(functions, DECAP)
    rows = normal(f)
    physical.require(sum(r["opcode"] == "cmovne" for r in rows) == 4, "four-word selection changed")
    physical.require(not any(r["opcode"].startswith(("j", "call", "div", "idiv")) for r in rows),
                     "selection control/call/division needs review")
    physical.require(not any(re.search(r"%[xyz]mm", r["operands"]) for r in rows), "SIMD in selection helper")
    frame_writes = stack_writers(rows)
    expected_flag = "%r8b,0x7(%rsp)" if host == "windows" else "%dl,-0x1(%rsp)"
    physical.require(len(frame_writes) == 1 and frame_writes[0]["opcode"] == "mov"
                     and frame_writes[0]["operands"] == expected_flag, "selection frame writes exceed reviewed mask")
    destination = "%rcx" if host == "windows" else "%rdi"
    out_stores = [r for r in rows if r["opcode"] == "mov" and
                  split_operands(r["operands"])[-1] in
                  ("(" + destination + ")", "0x8(" + destination + ")",
                   "0x10(" + destination + ")", "0x18(" + destination + ")")]
    physical.require(len(out_stores) == 4, "selection destination writes changed")
    calls = [i for i, r in enumerate(decap["instructions"]) if r["opcode"].startswith("call") and ASSIGN in r["operands"]]
    physical.require(len(calls) == 1, "selection caller missing/ambiguous")
    at = calls[0]
    return {"function": f, "four_direct_destination_stores": out_stores,
            "caller_mask_and_owner_setup": decap["instructions"][at - 15:at + 1],
            "no_key_word_stack_store_in_this_helper": True,
            "mask_stack_storage_not_claimed_erased": frame_writes,
            "incoming_pushes": [r for r in rows if r["opcode"].startswith("push")],
            "constant_time_proved": False, "register_erasure_proved": False}


def result_move_fact(functions, host):
    f = body(functions, DECAP)
    rows = normal(f)
    key = 0x280 if host == "windows" else 0x260
    call = next(i for i, r in enumerate(rows) if r["opcode"].startswith("call") and ASSIGN in r["operands"])
    load = literal(f, "movaps", hex(key) + "(%rsp),%xmm0")
    physical.require(rows[call + 1] == load, "return-owner copy sequence changed")
    post = rows[call + 6:]
    physical.require(not direct_overlap_writers(post, key, 32), "output owner is now explicitly overwritten")
    physical.require(not any(r["opcode"].startswith("call") for r in post), "normal suffix now calls another function")
    return {"function_address": f["address"], "key_owner_frame_offset": key,
            "return_copy": rows[call + 1:call + 6], "normal_return": rows[-1],
            "normal_postcopy_explicit_stack_writers": stack_writers(post),
            "local_output_source_not_covered_by_reviewed_wipes": True,
            "claim": "The selected output is copied to the API return place, leaving this local source outside the reviewed normal wipe ranges; API output and global ABI erasure are separate obligations."}


def wipe_range(rows, start, length):
    """Literal immediate-zero stores and the bytes they cover, on given rows."""
    covered, stores = set(), []
    widths = {"movb": 1, "movw": 2, "movl": 4, "movq": 8}
    for row in rows:
        match = re.fullmatch(r"\$0x0,(?:(0x[0-9a-f]+))?\(%rsp\)", row["operands"])
        if match and row["opcode"] in widths:
            offset = int(match[1], 16) if match[1] else 0
            touched = set(range(offset, offset + widths[row["opcode"]])) & set(range(start, start + length))
            if touched:
                covered.update(touched)
                stores.append(row)
    physical.require(covered == set(range(start, start + length)),
                     "literal normal wipe range incomplete: " + hex(start) + "/" + str(length))
    return {"frame_start": start, "bytes_covered": length, "stores": stores}


def borrowed_xof_fact(functions, host):
    result = {}
    for name, offset, reader in ((NOISE, 0x30 if host == "windows" else 0x10,
                                  0x100 if host == "windows" else 0xe0),
                                 ("kem1536::dev_kem::xof_into", 0x20 if host == "windows" else 0,
                                  0xf0 if host == "windows" else 0xd0)):
        f = body(functions, name)
        rows = normal(f)
        permutations = [i for i, r in enumerate(rows) if r["opcode"].startswith("call")
                        and "keccak_p" in r["operands"]]
        physical.require(len(permutations) == (2 if name == NOISE else 1), "squeeze count changed")
        suffix = rows[permutations[-1] + 1:]
        size_register = "%r8d" if host == "windows" else "%edx"
        physical.require(any(r["opcode"] == "mov" and r["operands"] == "$0xc8," + size_register
                             for r in rows[:permutations[0]]), "borrowed state-to-reader copy size changed")
        physical.require(not any(r["opcode"] == "mov" and r["operands"] == "$0xd0," + size_register
                                 for r in rows[:permutations[0]]), "consumed whole-state copy returned")
        result[name] = {"function": f, "normal_return": rows[-1],
                        "borrowed_absorber_normal_wipe": wipe_range(suffix, offset, 201),
                        "reader_normal_wipe": wipe_range(suffix, reader, 201),
                        "whole_state_208_byte_move_present": False,
                        "claim": "Both explicitly identified SHAKE owners are wiped on this normal suffix; registers and callee ABI copies are not covered."}
    return result


def derive_owner_fact(functions, host):
    f = body(functions, "kem1536::dev_kem::derive_into")
    rows = normal(f)
    calls = [i for i, r in enumerate(rows) if r["opcode"].startswith("call")]
    physical.require(len(calls) == 5, "derive primitive calls changed")
    return {"function": f, "finalize_borrow_setup_and_call": rows[calls[-1] - 2:calls[-1] + 1],
            "state_normal_wipe": wipe_range(rows[calls[-1] + 1:], 0x20 if host == "windows" else 0, 201),
            "output_destination": "borrowed destination saved from the fourth ABI argument; no local digest64 result in this helper",
            "callee_copies_or_registers_proved_erased": False}


def encaps_output_fact(functions, host):
    f = body(functions, "kem1536::dev_kem::encapsulate")
    rows = normal(f)
    material = 0x40 if host == "windows" else 0x20
    load = literal(f, "movaps", hex(material) + "(%rsp),%xmm0")
    at = rows.index(load)
    return {"function_address": f["address"], "material64_frame_offset": material,
            "key_to_tuple_return_copy": rows[at:at + 4],
            "material64_normal_success_wipe": wipe_range(rows[at + 4:], material, 64),
            "additional_local_key32_source_observed": False,
            "claim": "In the default Encaps success path, G32 loads feed the tuple return place, followed by G64 wiping. This is not an assertion about all caller copies."}


def copied_result_fact(functions, host):
    f = body(functions, DECAP)
    rows = normal(f)
    call = next(i for i, r in enumerate(rows) if r["opcode"].startswith("call") and ASSIGN in r["operands"])
    key = 0x280 if host == "windows" else 0x260
    load = literal(f, "movaps", hex(key) + "(%rsp),%xmm0")
    at = rows.index(load)
    physical.require(at == call + 1, "output copy source changed")
    return {"function_address": f["address"], "output_copy": rows[at:at + 5],
            "selection_owner_normal_wipe": wipe_range(rows[at + 5:], key, 32),
            "local_output_source_not_covered_by_reviewed_wipes": False,
            "API_output_and_register_erasure_are_separate": True}


def lifecycle_ledger(functions):
    selected = [f for f in functions if
                (f["name"].startswith("kem1536::dev_kem::") and "serde_core" not in f["name"]
                 and not f["name"].endswith("run_diagnostics"))
                or f["name"].startswith("kem1536::engine_poly::")
                or ("sha3::Sha3_512" in f["name"] and "finalize_into_reset" in f["name"])]
    physical.require(selected, "lifecycle ledger empty")
    divisions = [r for f in selected for r in f["instructions"] if re.fullmatch(r"i?div[bwlq]?", r["opcode"])]
    physical.require(not divisions, "division in retained reviewed engine functions")
    return {"functions": selected, "division_sites_in_these_functions": divisions,
            "inlined_paths": {"PKE_keygen": "keygen", "PKE_decrypt_and_recover": "decapsulate",
                              "PKE_reencrypt": "pke_encrypt_into called from decapsulate"},
            "conditional_control_scope": "Public fixed counts, public formats/lengths and OS entropy/error control are reviewed separately from secret arithmetic; the instruction ledger is not a taint proof.",
            "unresolved_external_calls_proved_complete": False,
            "global_constant_time_or_erasure_proved": False}


def current_report(cli, consumer, accepted):
    inputs, facts = {}, {}
    for kind, folder in (("cli", cli), ("consumer", consumer)):
        identity, functions = load(folder, kind, "candidate")
        physical.require(identity["source_contract"]["reviewed_source_anchors"] == (78 if accepted else 77),
                         "review source realization differs")
        inputs[kind] = identity
        facts[kind] = {}
        for host in ("windows", "linux"):
            row = {"assignment": assignment_fact(functions[host], host),
                   "borrowed_XOF": borrowed_xof_fact(functions[host], host),
                   "derive": derive_owner_fact(functions[host], host),
                   "Encaps_output": encaps_output_fact(functions[host], host),
                   "lifecycle": lifecycle_ledger(functions[host])}
            row["Decaps_output"] = (copied_result_fact if accepted else result_move_fact)(functions[host], host)
            facts[kind][host] = row
    physical.require(inputs["cli"]["source_manifest_sha256"] == inputs["consumer"]["source_manifest_sha256"],
                     "CLI/consumer source captures differ")
    return {"schema": "m10-secret-final-review-v1" if accepted else "m10-secret-intermediate-review-v1",
            "status": "BOUNDED_REVIEW_PASS" if accepted else "REJECTED_FOR_PROMOTION",
            "inputs": inputs, "facts": facts, "new_binary_executions": 0,
            "external_review_performed": False, "whole_program_erasure_proved": False,
            "interpretation": "Targeted owners and their normal-return wipes are traced through the retained KG/PKE/Decaps functions. The validity mask, volatile registers, incoming ABI saves, dependencies and caller copies remain explicit limits; no universal CT or erasure claim."}


def rejected_report(collections):
    expected = {"baseline-cli", "baseline-consumer", "candidate-cli", "candidate-consumer"}
    physical.require(set(collections) == expected, "four prepatch/001 input collections required")
    inputs, facts = {}, {}
    for label in sorted(collections):
        role, kind = label.split("-", 1)
        identity, functions = load(collections[label], kind, role)
        physical.require(identity["source_contract"]["reviewed_source_anchors"] == (62 if role == "baseline" else 75),
                         "negative proof must use the baseline/first-variant sources")
        inputs[label] = identity
        facts[label] = {}
        for host in ("windows", "linux"):
            row = {"noise": rejected_noise_fact(functions[host], host, role)}
            if role == "candidate":
                row["assignment"] = assignment_fact(functions[host], host)
                row["output_move"] = result_move_fact(functions[host], host)
            facts[label][host] = row
    for role in ("baseline", "candidate"):
        physical.require(inputs[role + "-cli"]["source_manifest_sha256"]
                         == inputs[role + "-consumer"]["source_manifest_sha256"],
                         "negative-review CLI/consumer captures differ")
    return {"schema": "m10-secret-rejected-review-v1", "status": "REJECTED_FOR_PROMOTION",
            "inputs": inputs, "facts": facts, "new_binary_executions": 0,
            "external_review_performed": False, "whole_program_erasure_proved": False,
            "interpretation": "The absorbed-state residue predates M10 and persists in 001. CtAssign removes the older byte-scalarized selection boundary, but 001 also leaves the moved API-output source locally. Both observations require another iteration; functional agreement cannot promote 001."}


def seal(output, report):
    physical.require(output.parent == (physical.ROOT / "artifacts/generated").resolve()
                     and output.name.startswith("m10-") and not output.exists(), "new M10 review folder required")
    output.mkdir()
    (output / "controls").mkdir()
    for name in CONTROLS:
        (output / "controls" / name).write_bytes(Path(__file__).with_name(name).read_bytes())
    physical.save(output / "review.json", report)
    physical.save(output / "provenance.json", {"schema": "m10-secret-review-receipt-v1",
                                              "members_sha256": physical.tracked_files(output)})


def verify_envelope(output):
    receipt = physical.read(output / "provenance.json")
    files = physical.tracked_files(output)
    files.pop("provenance.json")
    physical.require(receipt["schema"] == "m10-secret-review-receipt-v1"
                     and files == receipt["members_sha256"], "secret review envelope differs")
    for name, expected in receipt["members_sha256"].items():
        physical.require(physical.sha(physical.member(output, name)) == expected, "unsafe/changed review member")


def collect_rejected(output, collections):
    seal(output, rejected_report(collections))
    return verify_rejected(output, collections)


def verify_rejected(output, collections):
    verify_envelope(output)
    expected = rejected_report(collections)
    physical.require(physical.read(output / "review.json") == expected, "negative instruction review differs")
    return {"status": expected["status"], "images_reviewed": 8,
            "source_state_residue_preexisting": True, "new_binary_executions": 0,
            "whole_program_erasure_proved": False, "constant_time_proved": False}


def collect(output, cli, consumer, accepted=True):
    seal(output, current_report(cli, consumer, accepted))
    return verify(output, cli, consumer, accepted)


def verify(output, cli, consumer, accepted=True):
    verify_envelope(output)
    expected = current_report(cli, consumer, accepted)
    physical.require(physical.read(output / "review.json") == expected, "current instruction review differs")
    return {"status": expected["status"], "images_reviewed": 4, "new_binary_executions": 0,
            "SHAKE_owners_normal_suffix_wiped": True, "local_output_source_wiped": accepted,
            "whole_program_erasure_proved": False, "constant_time_proved": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("collect-rejected", "verify-rejected", "collect-intermediate",
                                          "verify-intermediate", "collect", "verify"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline-cli", type=Path)
    parser.add_argument("--baseline-consumer", type=Path)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--consumer", type=Path, required=True)
    args = parser.parse_args()
    if args.action.endswith("-rejected"):
        physical.require(args.baseline_cli is not None and args.baseline_consumer is not None,
                         "baseline inventories required for preexisting-state witness")
        inputs = {"baseline-cli": args.baseline_cli.resolve(), "baseline-consumer": args.baseline_consumer.resolve(),
                  "candidate-cli": args.cli.resolve(), "candidate-consumer": args.consumer.resolve()}
        action = collect_rejected if args.action == "collect-rejected" else verify_rejected
        result = action(args.output.resolve(), inputs)
    else:
        physical.require(args.baseline_cli is None and args.baseline_consumer is None, "current review uses two inventories")
        action = collect if args.action.startswith("collect") else verify
        result = action(args.output.resolve(), args.cli.resolve(), args.consumer.resolve(),
                        accepted=not args.action.endswith("-intermediate"))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
