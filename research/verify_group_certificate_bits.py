"""Independent H02 geometry and CBD-bit replay; no project arithmetic imports."""

import argparse
from collections import Counter
from fractions import Fraction
import hashlib
import itertools
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "results/j2/run-006"


def replay():
    saved = json.loads((RUN / "winner-certificate.json").read_text(encoding="utf-8"))
    q, levels = 7681, 4096

    def rounded(numerator, denominator):
        return (2 * numerator + denominator) // (2 * denominator)

    rows = [rounded(q * j, levels) for j in range(levels)]
    columns = [[rounded(q * (2 * i + phase), 2 * levels) for i in range(levels)]
               for phase in (0, 1)]
    if set(columns[0]) | set(columns[1]) != set(range(q)):
        raise ValueError("independent cover union failed")
    for coordinates in (rows, *columns):
        if len(set(coordinates)) != levels or min(coordinates) < 0 or max(coordinates) >= q:
            raise ValueError("independent cover distinctness failed")
        if any(not 1 <= (coordinates[(i + 1) % levels] - coordinates[i]) % q <= 2
               for i in range(levels)):
            raise ValueError("independent cover gap failed")
    if any((j % 2) == (((j + 1) % levels) % 2) for j in range(levels)):
        raise ValueError("independent cover phase wrap failed")
    # These exhaustive 1-D predicates certify all q^2 input pairs: on a row
    # horizontal error <=1, between two rows both at distance one, their
    # alternating column phases contain every possible input x.
    z = Fraction(saved["z"])
    samples = [sum(bits[:3]) - sum(bits[3:])
               for bits in itertools.product((0, 1), repeat=6)]
    conditional = {s: sum((z ** (-s * e) for e in samples), Fraction(0)) / 64
                   for s in set(samples)}
    pairs = [(s, e) for s in samples for e in samples]
    product = sum((count * z ** value for value, count in Counter(s * e for s, e in pairs).items()),
                  Fraction(0)) / 4096
    group = sum((conditional[s1] * conditional[s2] * z ** max(abs(s1), abs(s2))
                 for s1, s2 in pairs), Fraction(0)) / 4096
    final = sum((z ** e for e in samples), Fraction(0)) / 64
    for key, computed in (("product_MGF", product), ("pair_domination_MGF", group), ("e2_MGF", final)):
        encoded = saved["certificate"][key]
        if computed != Fraction(int(encoded["numerator_hex"], 16), int(encoded["denominator_hex"], 16)):
            raise ValueError("independent group MGF mismatch")
    dv = saved["dv"]
    error_max = max(abs((rounded(q * (((x * (1 << dv) + q // 2) // q) % (1 << dv)), 1 << dv)
                         - x + q // 2) % q - q // 2) for x in range(q))
    threshold = q // 4 - error_max
    if threshold != saved["tail_threshold"]:
        raise ValueError("independent safe threshold mismatch")
    for bit in (0, 1):
        mu = rounded(q * bit, 2)
        for error in range(-(threshold - 1) - error_max, threshold + error_max):
            decoded = (((mu + error) % q) * 2 + q // 2) // q % 2
            if decoded != bit:
                raise ValueError("independent decoder region failed")
    count = saved["quantized_pairs"]
    bound = 512 * product ** (3072 - 2 * count) * group ** count * final / z ** threshold
    encoded = saved["certificate"]["uncapped_bound"]
    if bound != Fraction(int(encoded["numerator_hex"], 16), int(encoded["denominator_hex"], 16)):
        raise ValueError("independent final bound mismatch")
    if (bound.numerator ** 5 << 874) > bound.denominator ** 5:
        raise ValueError("independent integer C05 decision failed")
    if (13 * 1536 - 2 * count + 256 * dv + 7) // 8 != saved["ciphertext_bytes"]:
        raise ValueError("independent bit-count mismatch")
    return {"snapshot": "run-006", "project_arithmetic_imported": False,
            "cover_for_all_q_squared_pairs": True, "CBD_bit_strings": 64,
            "pair_outcomes": 4096, "full_fraction_matches": True,
            "c05_exact_comparison": True, "candidate_id": saved["id"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    target, manifest = RUN / "independent-verification.json", RUN / "independent-provenance.json"
    if args.write and (target.exists() or manifest.exists()):
        raise FileExistsError("independent H02 verification already preserved")
    if not args.write:
        provenance = json.loads(manifest.read_text(encoding="utf-8"))
        for group, base in (("input_sha256", ROOT), ("output_sha256", RUN)):
            for name, expected in provenance[group].items():
                path = (base / name).resolve()
                if not path.is_relative_to(base) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                    raise ValueError("independent H02 checksum mismatch")
    result = replay()
    if args.write:
        inputs = ["research/verify_group_certificate_bits.py", "results/j2/run-006/winner-certificate.json"]
        content = (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        provenance = {"purpose": "independent replay before first Git freeze; prior run files unchanged",
                      "input_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in inputs},
                      "output_sha256": {target.name: hashlib.sha256(content).hexdigest()}}
        with target.open("xb") as stream:
            stream.write(content)
        with manifest.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(provenance, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    elif result != json.loads(target.read_text(encoding="utf-8")):
        raise ValueError("independent H02 result changed")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
