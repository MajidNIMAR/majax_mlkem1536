"""Independent, integer-only bridge from run-004 to R1's concrete operations.

This program imports neither the existing Chernoff implementation nor the R1
Python oracle. Exact finite checks are distinguished from an ideal-XOF model.
It is a research verifier for public synthetic vectors, not a KEM API.
"""

import argparse
from collections import Counter
from fractions import Fraction
import gzip
import hashlib
import json
import math
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
Q, N, K, ETA, DV = 7681, 256, 6, 3, 5
TAG = b"KEM1536-DEV-Q7681-R1\0"
POLY_BYTES, VECTOR_BYTES = 416, 2496
DEFAULT_CASES = (0, 1, 2, 3, 250, 500, 750, 999)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def centered(x, q=Q):
    return (x + q // 2) % q - q // 2


def compress(x, bits, q=Q):
    # Independently expressed nearest-integer rounding; q is odd.
    return ((2 * (1 << bits) * x + q) // (2 * q)) % (1 << bits)


def decompress(y, bits, q=Q):
    return (2 * q * y + (1 << bits)) // (2 << bits)


def cbd_bits(word, eta=ETA):
    mask = (1 << eta) - 1
    return (word & mask).bit_count() - ((word >> eta) & mask).bit_count()


def quantizer_contract():
    errors = Counter(centered(decompress(compress(x, DV), DV) - x) for x in range(Q))
    decisions = []
    for bit in (0, 1):
        mu = decompress(bit, 1)
        good = [e for e in range(-Q // 2 + 1, Q // 2 + 1)
                if compress((mu + e) % Q, 1) == bit]
        require(good == list(range(min(good), max(good) + 1)), "decoder region not contiguous")
        decisions.append([min(good), max(good)])
    low = max(a - min(errors) for a, _ in decisions)
    high = min(b - max(errors) for _, b in decisions)
    radius = min(-low, high)
    for bit in (0, 1):
        for e in range(-radius + min(errors), radius + max(errors) + 1):
            require(compress((decompress(bit, 1) + e) % Q, 1) == bit,
                    "safe-radius decoder implication failed")
    # Sharp for this product-of-supports argument, not an attainable joint event.
    require(compress((decompress(1, 1) + radius + 1 + max(errors)) % Q, 1) != 1,
            "expected upper-bound witness missing")
    return {"v_error_range": [min(errors), max(errors)],
            "v_residues_exhausted": Q, "decoder_intervals": decisions,
            "common_safe_radius": radius, "tail_threshold": radius + 1,
            "error_histogram_sha256": hashlib.sha256(json.dumps(sorted(errors.items())).encode()).hexdigest(),
            "rounding_independence_required": False}


def rational_record(value):
    return {"numerator_hex": format(value.numerator, "x"),
            "denominator_hex": format(value.denominator, "x")}


def verify_certificate(saved, quantizer=None):
    quantizer = quantizer or quantizer_contract()
    require(saved["parameters"] == dict(q=Q, n=N, k=K, eta1=ETA, eta2=ETA, dv=DV),
            "certificate/profile parameter mismatch")
    require(saved["v_error_range"] == quantizer["v_error_range"], "rounding support mismatch")
    require(saved["common_safe_radius"] == quantizer["common_safe_radius"], "radius mismatch")
    require(saved["one_sided_tail_threshold"] == quantizer["tail_threshold"], "threshold mismatch")
    z = Fraction(saved["tilt_z"])
    require(z == Fraction(13, 10), "unexpected rational tilt")
    cbd = Counter(cbd_bits(word) for word in range(1 << (2 * ETA)))
    require(cbd == Counter({-3: 1, -2: 6, -1: 15, 0: 20, 1: 15, 2: 6, 3: 1}),
            "CBD3 bit multiplicities differ")
    products = Counter()
    for a, na in cbd.items():
        for b, nb in cbd.items():
            products[a * b] += na * nb
    mgf_product = sum((count * z ** value for value, count in products.items()), Fraction()) / 4096
    mgf_e2 = sum((count * z ** value for value, count in cbd.items()), Fraction()) / 64
    upper = 2 * N * mgf_product ** (2 * N * K) * mgf_e2 / z ** quantizer["tail_threshold"]
    for name, value in (("mgf_product", mgf_product), ("mgf_e2", mgf_e2), ("message_upper", upper)):
        require(saved[name] == rational_record(value), f"rational certificate mismatch: {name}")
    # Exact comparisons; the displayed logarithm is not used in any decision.
    below_310_bits = (upper.numerator << 310) <= upper.denominator
    c05 = (upper.numerator ** 5 << 874) <= upper.denominator ** 5
    require(below_310_bits and c05 and saved["c05_exact_comparison"], "certificate comparison failed")
    return {"CBD3_counts": dict(sorted(cbd.items())), "CBD3_denominator": 64,
            "independent_products_per_coefficient": 2 * N * K,
            "coefficient_variance_ideal": str(Fraction(2 * N * K * ETA * ETA, 4) + Fraction(ETA, 2)),
            "message_upper_sha256": hashlib.sha256(json.dumps(rational_record(upper), sort_keys=True).encode()).hexdigest(),
            "log2_message_upper_display": math.log2(upper.numerator) - math.log2(upper.denominator),
            "exact_upper_at_most_2_pow_minus_310": below_310_bits, "C05_exact_comparison": c05,
            "ideal_independent_noise_only": True, "concrete_SHAKE_failure_bound_proved": False}


def domain(label, *parts):
    return TAG + label + b"\0" + b"".join(parts)


def noise(seed, nonce):
    stream = int.from_bytes(hashlib.shake_256(domain(b"N", seed, bytes([nonce]))).digest(192), "little")
    return [cbd_bits((stream >> (6 * j)) & 63) for j in range(N)]


def uniform(rho, i, j):
    xof = hashlib.shake_128(domain(b"A", rho, bytes([i, j])))
    length = 1024
    while True:
        raw = xof.digest(length)
        coefficients = [int.from_bytes(raw[p:p + 2], "little") & 8191 for p in range(0, length, 2)]
        coefficients = [x for x in coefficients if x < Q]
        if len(coefficients) >= N:
            return coefficients[:N]
        length *= 2


def multiply(a, b):
    """Unbounded integer convolution then X^N=-1, no modular shortcut."""
    require(len(a) == len(b) and len(a) > 0, "polynomial dimension mismatch")
    n = len(a)
    convolution = [0] * (2 * n - 1)
    for i, ai in enumerate(a):
        for j, bj in enumerate(b):
            convolution[i + j] += ai * bj
    return [convolution[i] - (convolution[i + n] if i + n < len(convolution) else 0)
            for i in range(n)]


def add(*polys):
    return [sum(terms) for terms in zip(*polys, strict=True)]


def negate(poly):
    return [-x for x in poly]


def dot(a, b):
    return add(*(multiply(x, y) for x, y in zip(a, b, strict=True)))


def pack(poly, width):
    return sum((x % Q if width == 13 else x) << (width * i)
               for i, x in enumerate(poly)).to_bytes(N * width // 8, "little")


def unpack(raw, width):
    require(len(raw) == N * width // 8, "polynomial encoding length")
    value = int.from_bytes(raw, "little")
    return [(value >> (width * i)) & ((1 << width) - 1) for i in range(N)]


def verify_vector(row):
    raw = {name: bytes(value) for name, value in row.items() if name != "case"}
    d, z, m = raw["d"], raw["z"], raw["m"]
    expanded = hashlib.sha3_512(domain(b"KG", d, bytes([K]))).digest()
    rho, sigma = expanded[:32], expanded[32:]
    require((rho, sigma) == (raw["rho"], raw["sigma"]), "KG expansion mismatch")
    a = [[uniform(rho, i, j) for j in range(K)] for i in range(K)]
    require(pack(a[0][0], 13) == raw["a00"], "matrix sample mismatch")
    s = [noise(sigma, i) for i in range(K)]
    e = [noise(sigma, K + i) for i in range(K)]
    t = [add(dot(a[i], s), e[i]) for i in range(K)]
    ek = b"".join(pack(p, 13) for p in t) + rho
    h = hashlib.sha3_256(domain(b"H", ek)).digest()
    dk = b"".join(pack(p, 13) for p in s) + ek + h + z
    require(ek == raw["ek"] and dk == raw["dk"], "honest-key sampler/relation mismatch")
    material = hashlib.sha3_512(domain(b"G", m, h)).digest()
    rseed = material[32:]
    r = [noise(rseed, i) for i in range(K)]
    e1 = [noise(rseed, K + i) for i in range(K)]
    e2 = noise(rseed, 12)
    u = [add(dot([a[j][i] for j in range(K)], r), e1[i]) for i in range(K)]
    mu = [decompress((m[i // 8] >> (i % 8)) & 1, 1) for i in range(N)]
    vraw = [x % Q for x in add(dot(t, r), e2, mu)]
    cv = [compress(x, DV) for x in vraw]
    ciphertext = b"".join(pack(p, 13) for p in u) + pack(cv, DV)
    require(ciphertext == raw["ciphertext"] and material[:32] == raw["shared"], "encapsulation mismatch")
    altered = bytearray(ciphertext)
    altered[0] = 255
    altered[1] |= 31
    rejected = hashlib.shake_256(domain(b"J", z, bytes(altered))).digest(32)
    require(rejected == raw["rejected_shared"], "public rejection-vector mismatch")
    u_from_bytes = [unpack(ciphertext[i * POLY_BYTES:(i + 1) * POLY_BYTES], 13) for i in range(K)]
    require(all(x < Q for p in u_from_bytes for x in p), "honest u is not canonical")
    require(all((x - y) % Q == 0 for p, q in zip(u, u_from_bytes, strict=True)
                for x, y in zip(p, q, strict=True)), "u encoding is not exact")
    restored = [decompress(x, DV) for x in cv]
    delta = [centered(x - y) for x, y in zip(restored, vraw, strict=True)]
    bnoise = add(dot(e, r), negate(dot(s, e1)), e2)
    received = add(restored, negate(dot(s, u_from_bytes)))
    require(all((x - expected) % Q == 0 for x, expected in zip(received, add(mu, bnoise, delta), strict=True)),
            "B=e*r-s*e1+e2 decomposition failed")
    recovered = sum(compress(x % Q, 1) << i for i, x in enumerate(received)).to_bytes(32, "little")
    require(recovered == m, "synthetic honest decryption mismatch")
    require(max(abs(x) for x in delta) <= 120, "rounding bound exceeded")
    return {"case": row["case"], "coefficients_checked": N,
            "max_abs_B": max(abs(x) for x in bnoise), "max_abs_delta_v": max(abs(x) for x in delta),
            "shared_seed_collision": sigma == rseed, "full_public_fields_checked": True,
            "decomposition_sha256": hashlib.sha256(json.dumps([bnoise, delta]).encode()).hexdigest()}


def verify_static_contract(source):
    """Fail closed on changed reviewed call sites; not a Rust semantics proof."""
    flat = re.sub(r"\s+", "", source)
    anchors = ["pubconstQ:u16=7681;", "pubconstRANK:usize=6;",
               "constPOLY_BYTES:usize=416;", "constTAG:&[u8]=b\"KEM1536-DEV-Q7681-R1\\0\";",
               "xof::<192>(b\"N\\0\",&[seed,&[nonce]])", "bit(6*j)+bit(6*j+1)+bit(6*j+2)",
               "bit(6*j+3)+bit(6*j+4)+bit(6*j+5)", "derive(b\"KG\\0\",&[d,&[6]])",
               "noise(sigma,iasu8)", "noise(sigma,6+iasu8)", "noise(seed,iasu8)",
               "noise(seed,6+iasu8)", "noise(seed,12)", "uniform(rho,j,iasu8)",
               "compress(v.coefficients()[i],5)", "decompress(unpack_coefficient(&c.0[VECTOR_BYTES..],5,i),5)",
               "v=v.subtract(&s[i].multiply(&u[i]))", "recover_message(&v)",
               "quotient((u32::from(x)<<width)+u32::from(Q/2))", "(1<<(width-1)))>>width)"]
    for anchor in anchors:
        require(anchor in flat, f"reviewed R1 source contract changed; review required: {anchor}")
    require('letvalue=u16::from_le_bytes(pair)&8191;ifvalue<Q{' in flat, "matrix rejection changed")
    return {"reviewed_source_anchors": len(anchors) + 1, "formal_program_verification": False}


def seed_collision_check():
    # If sigma=rseed the actual nonce schedule reuses r=s and e1=e.
    seed = hashlib.sha256(b"R1 certificate bridge public collision test").digest()
    s = [noise(seed, i) for i in range(K)]
    e = [noise(seed, K + i) for i in range(K)]
    require(dot(e, s) == dot(s, e), "commutative cancellation failed")
    for bit in (0, 1):
        for b in range(-ETA, ETA + 1):
            for dv in range(-120, 121):
                require(compress((decompress(bit, 1) + b + dv) % Q, 1) == bit,
                        "aligned-seed noise cancellation is not safe")
    return {"aligned_nonce_seed_collision": "r=s, e1=e, B=e2 exactly",
            "all_B_and_delta_support_combinations_checked": 2 * (2 * ETA + 1) * 241,
            "extra_2_pow_minus_256_correctness_penalty_required": False,
            "claim_scope": "honest single-exchange ideal sampler; not security or adversarial keys"}


def dishonest_key_check():
    # Canonical encodings and H(ek) consistency do not enforce t=A*s+e.
    s = b"\0" * VECTOR_BYTES
    t = [[Q // 2] + [0] * (N - 1)] + [[0] * N for _ in range(K - 1)]
    ek = b"".join(pack(p, 13) for p in t) + b"\0" * 32
    h = hashlib.sha3_256(domain(b"H", ek)).digest()
    dk = s + ek + h + b"\0" * 32
    require(len(ek) == 2528 and len(dk) == 5088, "dishonest witness size")
    require(all(x < Q for p in t for x in p), "dishonest witness must be canonical")
    message = b"\0" * 32
    material = hashlib.sha3_512(domain(b"G", message, h)).digest()
    r0, e2 = noise(material[32:], 0), noise(material[32:], 12)
    v = [(Q // 2 * r + error) % Q for r, error in zip(r0, e2, strict=True)]
    decoded = [compress(decompress(compress(x, DV), DV), 1) for x in v]
    require(any(decoded), "dishonest-key failure witness unexpectedly absent")
    return {"public_synthetic_key_only": True, "private_encoding_hash_consistent": True,
            "s_is_zero_and_t0_constant": Q // 2, "failed_message_bits": sum(decoded),
            "Rust_import_executed_by_this_verifier": False,
            "claim": "satisfies the documented format predicates; no honest-key correctness guarantee"}


def verify(cases=DEFAULT_CASES):
    cert_path = ROOT / "results/j2/run-004/correctness-certificate.json"
    manifest_path = ROOT / "results/j2/run-004/certificate-provenance.json"
    vector_path = ROOT / "results/engine/r1-001/vectors.jsonl.gz"
    vector_manifest_path = ROOT / "results/engine/r1-001/provenance.json"
    vector_manifest = json.loads(vector_manifest_path.read_text(encoding="utf-8"))
    require(digest(vector_path) == vector_manifest["output_sha256"][vector_path.name], "frozen vector hash mismatch")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    require(digest(cert_path) == manifest["output_sha256"][cert_path.name], "frozen certificate hash mismatch")
    for name, expected in manifest["input_sha256"].items():
        require(digest(ROOT / name) == expected, f"frozen certificate input changed: {name}")
    quantizer = quantizer_contract()
    cert = verify_certificate(json.loads(cert_path.read_text(encoding="utf-8")), quantizer)
    source = ROOT / "crates/kem1536/src/dev_kem.rs"
    contract = verify_static_contract(source.read_text(encoding="utf-8"))
    chosen = set(cases)
    require(len(chosen) == len(cases) and chosen and min(chosen) >= 0, "invalid case list")
    rows = []
    with gzip.open(vector_path, "rt", encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            if row["case"] in chosen:
                rows.append(verify_vector(row))
    require({row["case"] for row in rows} == chosen, "requested synthetic vector is absent")
    inputs = [source, ROOT / "crates/kem1536/src/engine_poly.rs", cert_path, manifest_path, vector_path, vector_manifest_path,
              ROOT / "docs/SPECIFICATION_DEV_Q7681_R1.md", Path(__file__).resolve()]
    return {"profile": "KEM1536-DEV-Q7681-R1", "quantizer": quantizer, "certificate": cert,
            "source_contract": contract, "synthetic_vectors": rows, "seed_collision": seed_collision_check(),
            "dishonest_key_witness": dishonest_key_check(),
            "input_sha256": {str(path.relative_to(ROOT)).replace("\\", "/"): digest(path) for path in inputs},
            "claims": {"exact_finite_reconstruction": True, "ideal_honest_average_key_correctness": True,
                       "fixed_or_adversarial_key_bound": False, "concrete_SHAKE_independence_proved": False,
                       "CCA_security_proved": False, "rare_failure_rate_measured": False}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="new output directory; existing directory is refused")
    parser.add_argument("--cases", type=int, nargs="+", default=list(DEFAULT_CASES))
    args = parser.parse_args()
    if args.output is not None:
        require(not args.output.exists(), "output exists; preserve prior results and choose a new directory")
    result = verify(tuple(args.cases))
    if args.output is not None:
        args.output.mkdir(parents=True, exist_ok=False)
        (args.output / "summary.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
