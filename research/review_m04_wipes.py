"""Check the two normal-return NTT scratch wipe loops in a specific x86-64 binary.

This recognises a narrow reviewed LLVM loop shape. It is not a general
disassembler, data-flow proof, erasure proof or constant-time proof.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re

NAME = "kem1536::engine_poly::Polynomial::multiply_into"


def wipe_coverage(body):
    # Restrict to the reviewed normal-return path, excluding unwind cleanup.
    normal = body.split("\tret", 1)[0]
    instructions = []
    for line in normal.splitlines():
        match = re.match(r"\s*([0-9a-f]+):\s+([a-z][a-z0-9]*)\s*(.*)", line)
        if match:
            instructions.append(match.groups())
    loops = []
    for i, (address, op, operands) in enumerate(instructions):
        if op != "mov" or operands != "$0xe,%eax":
            continue
        stores, loop_start = [], None
        for cursor in range(i + 1, min(i + 20, len(instructions))):
            here, opcode, args = instructions[cursor]
            zero = re.fullmatch(r"\$0x0,(-?0x[0-9a-f]+)?\(%rsp,%rax,1\)", args)
            if opcode == "movw" and zero:
                stores.append(int(zero.group(1), 16) if zero.group(1) else 0)
                loop_start = loop_start or here
                continue
            if opcode == "add" and args == "$0x10,%rax":
                suffix = instructions[cursor + 1:cursor + 3]
                if len(suffix) != 2 or suffix[0][1:] != ("cmp", "$0x20e,%rax"):
                    raise ValueError("wipe loop bound changed")
                if suffix[1][1] != "jne" or suffix[1][2].split()[0] != loop_start:
                    raise ValueError("wipe loop back-edge changed")
                coverage = {offset + counter + byte for counter in range(14, 526, 16)
                            for offset in stores for byte in range(2)}
                if len(stores) != 8 or len(coverage) != 512 or max(coverage) - min(coverage) != 511:
                    raise ValueError("scratch wipe is incomplete")
                loops.append({"entry": loop_start, "normal_path_counter_values": "14,30,...,510",
                              "store_offsets": stores, "bytes": len(coverage),
                              "stack_interval_inclusive": [min(coverage), max(coverage)]})
                break
            # Fail closed on inserted branches, calls, counter writes or any
            # other instruction. Only reviewed no-op padding may intervene.
            if not re.fullmatch(r"(?:(?:data16|cs) )*nop(?:w|l)?(?: .*)?", opcode + (" " + args if args else "")):
                raise ValueError("unmodelled instruction inside scratch wipe loop")
    if len(loops) != 2:
        raise ValueError("two reviewed normal-return scratch wipe loops required")
    a, b = sorted(loops, key=lambda row: row["stack_interval_inclusive"])
    if a["stack_interval_inclusive"][1] + 1 != b["stack_interval_inclusive"][0]:
        raise ValueError("scratch intervals unexpectedly changed")
    return loops


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("audit", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    disassembly = gzip.decompress((args.audit / "disassembly.txt.gz").read_bytes()).decode()
    marker = f"<{NAME}>:"
    start = disassembly.index(marker)
    end = disassembly.index("\n\n", start)
    body = disassembly[start:end]
    summary = json.loads((args.audit / "summary.json").read_text())
    functions = json.loads((args.audit / "core-functions.json").read_text())
    function = functions[NAME]
    if function["divisions"] or "memcpy" in body:
        raise ValueError("division or memcpy appeared in multiply_into")
    result = {"binary_sha256": summary["binary_sha256"], "function": NAME,
              "function_disassembly_sha256": hashlib.sha256(body.encode()).hexdigest(),
              "normal_return_scratch_wipes": wipe_coverage(body),
              "total_normal_return_scratch_bytes": 1024,
              "direct_memcpy_reference_in_function": False,
              "divisions_in_function": 0, "unwind_cleanup_present": "Unwind_Resume" in body,
              "old_return_value_temporary": "removed at source; direct output stores reviewed separately",
              "all_copies_erased_proved": False, "constant_time_proved": False,
              "limits": "normal-return loop coverage only; output provenance, registers, spills, callers and indirect target sets require separate review"}
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
