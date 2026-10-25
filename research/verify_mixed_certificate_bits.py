"""Independent replay from CBD bit strings; no project arithmetic imports."""

import argparse
from collections import Counter
from fractions import Fraction
import hashlib
import itertools
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "results/j2/run-005"


def replay():
    saved = json.loads((RUN / "winner-certificate.json").read_text(encoding="utf-8"))
    z = Fraction(saved["z"])
    samples = [sum(bits[:3]) - sum(bits[3:])
               for bits in itertools.product((0, 1), repeat=6)]
    pair_outcomes = [(s, e) for s in samples for e in samples]
    q = 7681

    def comp(x, width):
        return ((2 ** width * x + q // 2) // q) % (2 ** width)

    def decomp(x, width):
        return (q * x + 2 ** (width - 1)) // 2 ** width

    radii = {}
    for width in (11, 12, 13):
        radii[width] = max(abs((decomp(comp(x, width), width) - x + q // 2) % q - q // 2)
                           for x in range(q))
        if radii[width] != saved["u_error_radii"][str(width)]:
            raise ValueError("independent rounding range mismatch")
    rv = max(abs((decomp(comp(x, saved["dv"]), saved["dv"]) - x + q // 2) % q - q // 2)
             for x in range(q))
    safe = saved["tail_threshold"] - 1
    for bit in (0, 1):
        for residual in range(-safe - rv, safe + rv + 1):
            if comp((decomp(bit, 1) + residual) % q, 1) != bit:
                raise ValueError("independent safe interval check failed")
    product_histogram = Counter(s * e for s, e in pair_outcomes)
    product = sum((weight * z ** x for x, weight in product_histogram.items()), Fraction(0)) / 4096
    final = sum((z ** x for x in samples), Fraction(0)) / 64
    upper = 512 * product ** 1536 * final / z ** saved["tail_threshold"]
    for width in (11, 12, 13):
        radius = radii[width]
        histogram = Counter(-s * e + radius * abs(s) for s, e in pair_outcomes)
        mgf = sum((weight * z ** x for x, weight in histogram.items()), Fraction(0)) / 4096
        encoded = saved["certificate"]["domination_mgfs"][str(width)]
        if mgf != Fraction(int(encoded["numerator_hex"], 16), int(encoded["denominator_hex"], 16)):
            raise ValueError("independent domination MGF mismatch")
        upper *= mgf ** saved["u_counts"][str(width)]
    original = saved["certificate"]["uncapped_bound"]
    if upper != Fraction(int(original["numerator_hex"], 16), int(original["denominator_hex"], 16)):
        raise ValueError("independent final fraction mismatch")
    if (upper.numerator ** 5 << 874) > upper.denominator ** 5:
        raise ValueError("independent exact C05 decision failed")
    return {"snapshot": "run-005", "method": "independent enumeration of CBD3 bit strings",
            "CBD_bit_strings": 64, "pair_outcomes": 4096,
            "project_arithmetic_imported": False, "full_fraction_matches": True,
            "c05_exact_comparison": True, "candidate_id": saved["id"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    target = RUN / "bits-verification.json"
    manifest = RUN / "bits-provenance.json"
    if args.write and (target.exists() or manifest.exists()):
        raise FileExistsError("independent certificate already preserved")
    if not args.write:
        provenance = json.loads(manifest.read_text(encoding="utf-8"))
        for group, base in (("input_sha256", ROOT), ("output_sha256", RUN)):
            for relative, expected in provenance[group].items():
                path = (base / relative).resolve()
                if not path.is_relative_to(base) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                    raise ValueError("bit-enumeration provenance mismatch")
    result = replay()
    if args.write:
        content = (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        files = ["research/verify_mixed_certificate_bits.py", "results/j2/run-005/winner-certificate.json"]
        provenance = {"purpose": "independent replay added before first Git freeze; original run files unchanged",
                      "input_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                       for name in files},
                      "output_sha256": {target.name: hashlib.sha256(content).hexdigest()}}
        with target.open("xb") as stream:
            stream.write(content)
        with manifest.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(provenance, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
    elif result != json.loads(target.read_text(encoding="utf-8")):
        raise ValueError("independent replay changed")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
