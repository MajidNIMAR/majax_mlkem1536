"""Independent exhaustive decoder checks, without project arithmetic imports.

Enumerates complete toy codebooks and every symbol of 64 actual-modulus
blocks. Exact Python integers and an absolute circular-distance formula.
"""

from datetime import datetime, timezone
import hashlib
import itertools
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "results/j2/run-010"


def replay():
    toys = json.loads((RUN / "toy-enumeration.json").read_text(encoding="utf-8"))
    classifications = 0
    for toy in toys:
        code = toy["code"]
        q = code["q"]
        words = []
        for labels in itertools.product(range(q), repeat=code["k"]):
            word = tuple(symbol * multiplier % q for symbol, block in zip(labels, code["generators"]) for multiplier in block)
            words.append(word)
        if len(set(words)) != q ** code["k"]:
            raise ValueError("toy codewords not distinct")
        histogram = {}
        for target in itertools.product(range(q), repeat=code["n"]):
            best = min(sum(min(abs(x-y), q-abs(x-y)) ** 2 for x, y in zip(target, word)) for word in words)
            histogram[best] = histogram.get(best, 0) + 1
            classifications += 1
        expected = [{"squared_norm": value, "count": histogram[value]} for value in sorted(histogram)]
        if expected != toy["histogram"] or sum(histogram.values()) != toy["targets"]:
            raise ValueError("independent full-codebook histogram mismatch")
    cases = json.loads((RUN / "oracle-cases.json").read_text(encoding="utf-8"))
    if len(cases) != 64:
        raise ValueError("64 actual-modulus blocks required")
    candidates = 0
    for case in cases:
        q = case["q"]
        best = None
        for symbol in range(q):
            score = 0
            for x, multiplier in zip(case["values"], case["generator"]):
                raw = abs(x - symbol * multiplier % q)
                score += min(raw, q - raw) ** 2
            candidate = score, symbol
            best = candidate if best is None else min(best, candidate)
        if best != (case["squared_norm"], case["label"]):
            raise ValueError("independent actual-modulus oracle mismatch")
        candidates += q
    return dict(method="complete toy codebooks plus full actual-modulus block alphabets",
                project_arithmetic_imported=False, toy_cases=len(toys), classified_targets=classifications,
                actual_modulus_blocks=len(cases), actual_modulus_candidate_symbols=candidates, all_matched=True)


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    result = replay()
    output = RUN / "independent-verification.json"
    if output.exists():
        if json.loads(output.read_text(encoding="utf-8")) != result:
            raise ValueError("independent saved verification mismatch")
    else:
        write(output, result)
        names = ["research/verify_block_decoder_independent.py", "results/j2/run-010/toy-enumeration.json",
                 "results/j2/run-010/oracle-cases.json"]
        write(RUN / "independent-provenance.json", dict(created_utc=datetime.now(timezone.utc).isoformat(),
                                                       input_sha256={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in names},
                                                       output_sha256={output.name: hashlib.sha256(output.read_bytes()).hexdigest()}))
    print(json.dumps(result, indent=2))
