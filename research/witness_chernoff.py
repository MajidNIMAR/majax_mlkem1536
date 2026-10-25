"""Independent rational Chernoff certificate for a lossless-u witness.

No polynomial-power recurrence or floating-point decision is used. This
proves an upper bound in the ideal independent CBD sampler model only.
"""

from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "results/j2/run-004"


def mgf_product(eta, z):
    if eta < 1 or z <= 1:
        raise ValueError("positive eta and rational z > 1 required")
    return sum((math.comb(2 * eta, eta + a) * math.comb(2 * eta, eta + b)
                * z ** (a * b)
                for a in range(-eta, eta + 1) for b in range(-eta, eta + 1)),
               Fraction(0)) / (1 << (4 * eta))


def mgf_cbd(eta, z):
    # Each of eta independent bit differences has PGF (z+2+1/z)/4.
    return ((z + 2 + 1 / z) / 4) ** eta


def safe_radius(q, dv):
    if q < 3 or q % 2 != 1 or dv < 1:
        raise ValueError("odd modulus and positive compression width required")

    def compress(x, bits):
        return ((x * (1 << bits) + q // 2) // q) % (1 << bits)

    def decompress(x, bits):
        return (q * x + (1 << (bits - 1))) // (1 << bits)

    errors = [(decompress(compress(x, dv), dv) - x + q // 2) % q - q // 2
              for x in range(q)]
    a, b = min(errors), max(errors)
    one_residues = [x for x in range(q) if compress(x, 1) == 1]
    mu = decompress(1, 1)
    intervals = [(-q // 4 + 1, q // 4), (min(one_residues) - mu, max(one_residues) - mu)]
    # In Python -q//4 is floor(-q/4), hence +1 equals -(q//4) for odd q.
    lower = max(low - a for low, _ in intervals)
    upper = min(high - b for _, high in intervals)
    radius = min(-lower, upper)
    if radius < 0:
        raise ValueError("no nonnegative common safe radius")
    return radius, (a, b)


def rational_hex(value):
    return {"numerator_hex": format(value.numerator, "x"),
            "denominator_hex": format(value.denominator, "x")}


def certificate():
    q, n, k, eta, dv = 7681, 256, 6, 3, 5
    z = Fraction(13, 10)  # Explicit rational choice, no numerical optimizer.
    radius, errors = safe_radius(q, dv)
    threshold = radius + 1
    product, final = mgf_product(eta, z), mgf_cbd(eta, z)
    # If |B| <= radius, both message bits decode for every allowed v error.
    # Symmetry plus Markov: Pr[|B| >= threshold] <= 2*E[z^B]/z^threshold.
    bound = 2 * n * product ** (2 * n * k) * final / z ** threshold
    if not 0 < bound < 1:
        raise ArithmeticError("invalid witness upper bound")
    passes = (bound.numerator ** 5 << 874) <= bound.denominator ** 5
    return {"parameters": dict(q=q, n=n, k=k, eta1=eta, eta2=eta, dv=dv),
            "u_mode": "exact raw 13-bit coefficients; zero rounding error",
            "v_error_range": list(errors), "common_safe_radius": radius,
            "one_sided_tail_threshold": threshold, "tilt_z": str(z),
            "mgf_product": rational_hex(product), "mgf_e2": rational_hex(final),
            "message_upper": rational_hex(bound),
            "log2_message_upper_display": math.log2(bound.numerator) - math.log2(bound.denominator),
            "c05_exact_comparison": passes,
            "derivation": "2*n*M_product(z)^(2*n*k)*M_e2(z)/z^(radius+1)",
            "sampler_model": "independent ideal CBD; any fixed message independent of keys",
            "matrix_assumption": "none for correctness; exact algebraic cancellation",
            "rounding_independence_assumption": "none",
            "limits": "honest average-key correctness only; no new profile, CCA or fixed-SHAKE proof"}


def main():
    result = certificate()
    files = ["research/witness_chernoff.py", "research/test_witness_chernoff.py",
             "research/verify_witness_certificate.py", "results/j2/run-004/u-dependency.json"]
    provenance = {"created_utc": datetime.now(timezone.utc).isoformat(),
                  "purpose": "additional independent certificate; prior run-004 files unchanged",
                  "input_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                   for name in files}}
    target = RUN / "correctness-certificate.json"
    manifest = RUN / "certificate-provenance.json"
    if target.exists() or manifest.exists():
        raise FileExistsError("certificate already exists; preserve it")
    encoded = (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    provenance["output_sha256"] = {target.name: hashlib.sha256(encoded).hexdigest()}
    with target.open("xb") as stream:
        stream.write(encoded)
    with manifest.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(provenance, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps({"log2_message_upper": result["log2_message_upper_display"],
                      "c05_exact_comparison": result["c05_exact_comparison"]}, indent=2))


if __name__ == "__main__":
    main()
