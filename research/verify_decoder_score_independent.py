"""Independent complete toy targets and literal CBD1 bit-string enumeration.

No project arithmetic imports. Reconstructs decoder residuals, joint phases,
coordinate/block product laws, and shared-secret score moments.
"""

from collections import Counter
from datetime import datetime, timezone
import hashlib
import itertools
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "results/j2/run-011"


def circular_product(a, b):
    q = len(a)
    return [sum(a[i] * b[(p-i) % q] for i in range(q)) for p in range(q)]


def secrets(n):
    return Counter(tuple(bits[2*i] - bits[2*i+1] for i in range(n))
                   for bits in itertools.product((0, 1), repeat=2*n))


def phase_law(histogram, q, n):
    result = [0] * q
    for r, count in histogram.items():
        for s, weight in secrets(n).items():
            result[sum(a*b for a,b in zip(r, s)) % q] += count * weight
    return result


def replay():
    toys = json.loads((RUN / "toy-laws.json").read_text(encoding="utf-8"))
    classified, bit_strings = 0, 0
    failures = []
    for case in toys:
        code = case["code"]
        q, n, k = code["q"], code["n"], code["k"]
        words = [(message, tuple(a*g % q for a, block in zip(message, code["generators"]) for g in block))
                 for message in itertools.product(range(q), repeat=k)]
        histogram = Counter()
        for target in itertools.product(range(q), repeat=n):
            _, _, word = min((sum(min(abs(x-y), q-abs(x-y)) ** 2 for x,y in zip(target, word)), message, word)
                             for message, word in words)
            residual = []
            for x, y in zip(target, word):
                value = x-y
                if value > q//2:
                    value -= q
                elif value < -q//2 + 1:
                    value += q
                residual.append(value)
            histogram[tuple(residual)] += 1
            classified += 1
        if [dict(residual=list(r), count=c) for r,c in sorted(histogram.items())] != case["residual_histogram"]:
            raise ValueError("independent residual histogram mismatch")
        phase = phase_law(histogram, q, n)
        if phase != case["phase_weights"] or sum(phase) != case["phase_denominator"]:
            raise ValueError("independent joint phase law mismatch")
        coordinate, block = [1]+[0]*(q-1), [1]+[0]*(q-1)
        coordinate_denominator = 1
        for i in range(n):
            marginal = Counter()
            for r,c in histogram.items():
                marginal[(r[i],)] += c
            coordinate = circular_product(coordinate, phase_law(marginal, q, 1))
            coordinate_denominator *= q**n * 4
        if coordinate != case["coordinate_product_phase_weights"] or coordinate_denominator != case["coordinate_product_denominator"]:
            raise ValueError("independent coordinate-product law mismatch")
        offset, block_denominator = 0, 1
        for generator in code["generators"]:
            marginal = Counter()
            for r,c in histogram.items():
                marginal[r[offset:offset+len(generator)]] += c
            block = circular_product(block, phase_law(marginal, q, len(generator)))
            block_denominator *= q**n * 4**len(generator)
            offset += len(generator)
        if any(a*case["phase_denominator"] != b*block_denominator for a,b in zip(block, phase)):
            raise ValueError("independent block factorization mismatch")
        matches = all(a*case["phase_denominator"] == b*coordinate_denominator for a,b in zip(coordinate, phase))
        if matches != case["coordinate_law_matches_joint"]:
            raise ValueError("coordinate-factorization status mismatch")
        failures.append(not matches)
        cosine = [math.cos(2*math.pi*p/q) for p in range(q)]
        scores = []
        for s, weight in sorted(secrets(n).items()):
            counts = [0]*q
            for r,c in histogram.items():
                counts[sum(a*b for a,b in zip(s,r)) % q] += c
            score = math.fsum(counts[p]*cosine[p] for p in range(q))/q**n
            scores.append(dict(secret=list(s), bit_weight=weight, target_phase_counts=counts, score=score))
        for actual, expected in zip(scores, case["secret_rows"]):
            if any(actual[k] != expected[k] for k in ("secret", "bit_weight", "target_phase_counts")) or abs(actual["score"]-expected["score"]) > 1e-12:
                raise ValueError("independent secret-conditioned score mismatch")
        mean = math.fsum(s["bit_weight"]*s["score"] for s in scores)/4**n
        variance = math.fsum(s["bit_weight"]*(s["score"]-mean)**2 for s in scores)/4**n
        if abs(mean-case["shared_secret_score_mean"]) > 1e-12 or abs(variance-case["shared_secret_score_variance"]) > 1e-12:
            raise ValueError("independent shared-secret moments mismatch")
        bit_strings += 4**n
    return dict(toy_cases=len(toys), complete_targets=classified, literal_secret_bit_strings=bit_strings,
                project_arithmetic_imported=False, joint_phase_laws_matched=True,
                exact_block_factorizations_matched=True, coordinate_factorization_failures=sum(failures),
                shared_secret_moments_matched=True)


def save(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    result = replay()
    output = RUN / "independent-verification.json"
    if output.exists():
        if json.loads(output.read_text(encoding="utf-8")) != result:
            raise ValueError("saved independent score check mismatch")
    else:
        save(output, result)
        names = ["research/verify_decoder_score_independent.py", "results/j2/run-011/toy-laws.json"]
        save(RUN / "independent-provenance.json", dict(created_utc=datetime.now(timezone.utc).isoformat(),
                                                       input_sha256={n: hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in names},
                                                       output_sha256={output.name: hashlib.sha256(output.read_bytes()).hexdigest()}))
    print(json.dumps(result, indent=2))
