"""Replay a narrow review of four frozen M06 x86-64 executables.

This checks helper copies and explicit normal-prefix zero-store loops at
manually identified owner locations. It is not a provenance, all-path erasure,
constant-time or complete indirect-call proof. Unknown binaries fail closed.
"""

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re

from inspect_m03_binary import parse_disassembly, resolve_elf_relocations

PREFIX = "kem1536::engine_poly::"
HELPERS = ("Polynomial::forward_into", "NttPolynomial::multiply_add_assign",
           "NttPolynomial::inverse_into", "transform")
BINARY_LAYOUTS = {
    "f84cb5418bef5bc630d631a209bd98f4f51e1f1496616963468139becda2d027":
        ("windows", "research", 0x1470, 0x270, 0x1a30, 0x230, 0xc30, 0x850, 0x650, 0x250),
    "8afa24959f7ec8e59472938f9569da4f30ef8088d9aa48f4c82baa2e19f11b67":
        ("windows", "delivered", 0x14a0, 0x2a0, 0x1a30, 0x230, 0xc30, 0x970, 0x770, 0x370),
    "e01cdb5c9a067f4a091e6c0ebd323e1b32ca176cc9f6fe74ff2b94bfc414b70a":
        ("linux", "research", 0x1448, 0x248, 0x1a18, 0x218, 0xc18, 0x828, 0x628, 0x228),
    "eef23ebf6c9b96b14d377d585971a4cbc531d0c58e26654a544abac8133b39ff":
        ("linux", "delivered", 0x1498, 0x290, 0x1a18, 0x218, 0xc18, 0x1558, 0x1358, 0x358),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def bodies(text):
    matches = list(re.finditer(r"^([0-9a-f]+) <(.+)>:$", text, re.M))
    return {match.group(2): text[match.start():matches[index + 1].start()
                               if index + 1 < len(matches) else len(text)].rstrip()
            for index, match in enumerate(matches)}


def instructions(body, normal_prefix=False):
    result = []
    for line in body.splitlines():
        match = re.match(r"\s*([0-9a-f]+):\s+([a-z][a-z0-9_.]*)\s*(.*)", line)
        if match:
            result.append(match.groups())
            if normal_prefix and match.group(2) in ("ret", "retq"):
                break
    return result


def padding(op, args):
    return (op == "xchg" and args == "%ax,%ax") or bool(
        re.fullmatch(r"(?:(?:data16|cs) )*nop(?:w|l)?(?: .*)?", op + (" " + args if args else "")))


def zero_store_loops(body):
    """Recognise only the observed rax/rsp, eight-u16-store loop shape.

    Coverage is arithmetic on the literal loop, not a control-flow theorem.
    Inspection ends at the first ret, so unwind bodies are not claimed.
    """
    ins = instructions(body, normal_prefix=True)
    found = []
    for index, (seed_address, opcode, args) in enumerate(ins):
        seed = re.fullmatch(r"\$(0x[0-9a-f]+),%eax", args) if opcode == "mov" else None
        if not seed:
            continue
        cursor = index + 1
        while cursor < len(ins) and padding(*ins[cursor][1:]):
            cursor += 1
        start = cursor
        stores = []
        while cursor < len(ins):
            _, op, operands = ins[cursor]
            store = re.fullmatch(r"\$0x0,(-?0x[0-9a-f]+)?\(%rsp,%rax,1\)", operands)
            if op != "movw" or not store:
                break
            stores.append(int(store.group(1) or "0", 16))
            cursor += 1
        if not stores:
            continue
        require(len(stores) == 8, "candidate wipe must have eight consecutive zero u16 stores")
        require(cursor + 2 < len(ins), "truncated wipe loop")
        require(ins[cursor][1:] == ("add", "$0x10,%rax"), "wipe step changed")
        bound = re.fullmatch(r"\$(0x[0-9a-f]+),%rax", ins[cursor + 1][2])
        require(ins[cursor + 1][1] == "cmp" and bound, "wipe bound changed")
        require(ins[cursor + 2][1] == "jne" and
                ins[cursor + 2][2].split()[0] == ins[start][0], "wipe back-edge changed")
        lo, hi = int(seed.group(1), 16), int(bound.group(1), 16)
        require(hi - lo == 512, "reviewed wipe must span 512 counter bytes")
        coverage = {offset + counter + byte for offset in stores
                    for counter in range(lo, hi, 16) for byte in range(2)}
        require(len(coverage) == 512 and max(coverage) - min(coverage) == 511,
                "incomplete or overlapping wipe stores")
        found.append(dict(seed_address=seed_address, entry=ins[start][0],
                          counter_start=lo, counter_end_exclusive=hi, step=16,
                          store_offsets=stores, bytes_per_loop_execution=512,
                          stack_interval_inclusive=[min(coverage), max(coverage)]))
    return found


def inverse_copy_contract(body, platform):
    """Track only the short reviewed register prefix through memcpy/transform."""
    require(platform in ("windows", "linux"), "unknown ABI")
    if platform == "windows":
        state, arguments = {"%rcx": "source", "%rdx": "destination"}, ("%rcx", "%rdx", "%r8")
        volatile = {"%rax", "%rcx", "%rdx", "%r8", "%r9", "%r10", "%r11"}
    else:
        state, arguments = {"%rdi": "source", "%rsi": "destination"}, ("%rdi", "%rsi", "%rdx")
        volatile = {"%rax", "%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9", "%r10", "%r11"}
    copied = False
    def register(name):
        return {"%edx": "%rdx", "%r8d": "%r8"}.get(name, name)
    for address, op, args in instructions(body):
        if op.startswith("j"):
            raise ValueError("branch before reviewed copy/transform")
        if op in ("call", "callq"):
            if not copied:
                require("memcpy" in args, "first inverse call must be memcpy")
                require([state.get(reg) for reg in arguments] == ["destination", "source", 512],
                        "copy is not source-to-owned-destination with length 512")
                copied = True
                for reg in volatile:
                    state.pop(reg, None)
            else:
                require("<" + PREFIX + "transform>" in args, "second inverse call must be transform")
                require(state.get(arguments[0]) == "destination", "inverse transform changed owner")
                return dict(bytes=512, copy_address=copy_address,
                            inverse_transform_address=address,
                            source="borrowed NttPolynomial", destination="borrowed Polynomial owner",
                            temporary_polynomial_return=False)
            copy_address = address
            continue
        if op == "mov":
            parts = args.split(",")
            require(len(parts) == 2, "unmodelled inverse-prefix mov")
            src, dst = parts
            dst = register(dst)
            if dst.startswith("%"):
                if src.startswith("%"):
                    state[dst] = state.get(register(src))
                elif src.startswith("$0x"):
                    state[dst] = int(src[1:], 16)
                else:
                    state.pop(dst, None)
        elif op == "lea":
            state.pop(args.rsplit(",", 1)[-1], None)
        elif op in ("push", "sub", "movdqa") or padding(op, args):
            # Only these exact unrelated ABI operations occur in this prefix.
            require(op != "sub" or args.endswith(",%rsp"), "unmodelled register subtraction")
            require(op != "movdqa" or args.endswith("(%rsp)"), "unmodelled SIMD prefix load")
        else:
            raise ValueError("unmodelled inverse-prefix instruction")
    raise ValueError("reviewed inverse transform call missing")


def review(audit):
    audit = Path(audit)
    binary = gzip.decompress((audit / "binary.gz").read_bytes())
    checksum = digest(binary)
    require(checksum in BINARY_LAYOUTS, "unknown binary: requires a new human layout review")
    platform, kind, sbase, ssum, rbase, rsum, randomness, left, right, dsum = BINARY_LAYOUTS[checksum]
    summary = json.loads((audit / "summary.json").read_text())
    require(summary["binary_sha256"] == checksum, "binary summary checksum differs")
    text = gzip.decompress((audit / "disassembly.txt.gz").read_bytes()).decode()
    funcs, raw = parse_disassembly(text), bodies(text)
    if platform == "linux":
        resolve_elf_relocations(funcs, (audit / "relocations.txt").read_text())
    require(not any("Polynomial::multiply_into" in name for name in funcs),
            "test-only old product is present")
    helpers = {}
    for suffix in HELPERS:
        name = PREFIX + suffix
        require(name in funcs and name in raw, "required NTT helper missing: " + name)
        f = funcs[name]
        require(not f["divisions"], "division in NTT helper")
        helpers[name] = dict(body_sha256=digest(raw[name].encode()),
                             conditional_branches=f["conditional_branches"], calls=f["calls"],
                             indirect_transfers=f["indirect_transfers"], divisions=0)
        if suffix != "transform":
            require(len(f["conditional_branches"]) == 1 and
                    f["conditional_branches"][0]["opcode"] == "jne",
                    "reviewed helper must have only its fixed traversal back-edge")
    helpers[PREFIX + "NttPolynomial::inverse_into"]["direct_copy_contract"] = inverse_copy_contract(
        raw[PREFIX + "NttPolynomial::inverse_into"], platform)
    kg = "kem1536::dev_kem::" + ("keygen_internal" if kind == "research" else "keygen")
    decryption = "kem1536::dev_kem::" + ("pke_decrypt" if kind == "research" else "decapsulate")
    enc_names = [name for name in raw if name == "kem1536::dev_kem::pke_encrypt_into" or
                 name.startswith("_ZN7kem15367dev_kem16pke_encrypt_into17")]
    require(len(enc_names) == 1, "encrypt_into absent or ambiguous, including LLVM-mangled names")
    enc = enc_names[0]
    targets = {kg: [("transformed_s", sbase, 3072), ("keygen_sum", ssum, 512)],
               enc: [("transformed_r", rbase, 3072), ("encryption_sum", rsum, 512),
                     ("noise_randomness", randomness, 512)],
               decryption: [("decrypt_left", left, 512), ("decrypt_right", right, 512),
                            ("decrypt_sum", dsum, 512)]}
    owners = {}
    for name, locations in targets.items():
        require(name in raw, "owner function missing")
        loops = zero_store_loops(raw[name])
        covered = {byte for loop in loops for byte in range(loop["stack_interval_inclusive"][0],
                                                           loop["stack_interval_inclusive"][1] + 1)}
        owner_rows = []
        for label, start, size in locations:
            require(set(range(start, start + size)) <= covered, "targeted owner wipe incomplete: " + label)
            owner_rows.append(dict(label=label, bytes=size,
                                   manually_reviewed_stack_interval_inclusive=[start, start + size - 1]))
        owners[name] = dict(body_sha256=digest(raw[name].encode()),
                            literal_zero_store_loops_before_first_ret=loops, targeted_owners=owner_rows,
                            owner_identity_basis="manual source/call-argument trace for this exact frozen binary",
                            control_flow_and_all_owner_lifetimes_proved=False)
    return dict(schema="m06-bounded-ntt-review-v1", binary_sha256=checksum, platform=platform, kind=kind,
                helpers=helpers, targeted_owner_storage=owners,
                old_test_product_absent=True, constant_time_proved=False,
                all_secret_owners_erased_proved=False, all_copies_erased_proved=False,
                scope="literal normal-prefix loop coverage at reviewed owner locations and a short inverse ABI copy trace; no all-path dataflow, spill, register, panic or system-library proof")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("audit", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    require(not (args.output and args.verify), "select output or verify")
    result = review(args.audit)
    if args.output:
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
    if args.verify:
        require(json.loads(args.verify.read_text()) == result, "saved NTT review does not replay")
    print(json.dumps(dict(binary_sha256=result["binary_sha256"], platform=result["platform"],
                          kind=result["kind"], helpers=len(result["helpers"]),
                          targeted_owners=sum(len(row["targeted_owners"]) for row in
                                              result["targeted_owner_storage"].values()),
                          all_copies_erased_proved=False)))


if __name__ == "__main__":
    main()
