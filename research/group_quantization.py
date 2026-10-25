"""H02: staggered pair quantizers and dependence-agnostic CBD bounds.

This implements mathematical quantizers, not rank-6 KEM operations. A finite
cover argument certifies L1 rounding error <=1 when K<q<=2K, K even. Shared
rounding dependence is retained through the support function of each pair.
"""

from bisect import bisect_left
from collections import Counter
from fractions import Fraction
from functools import cache
import itertools
import math

from noise_exact import compress, decompress, probability_record
from witness_chernoff import mgf_cbd, mgf_product, rational_hex, safe_radius

Q, N, K, ETA = 7681, 256, 6, 3
TOTAL = N * K
TILTS = tuple(Fraction(j, 1000) for j in range(1001, 1501))
DV_VALUES = (2, 3, 4, 5, 6, 7, 8, 13)


def centered(value, q):
    return (value + q // 2) % q - q // 2


def reconstruction(i, j, q, bits):
    levels = 1 << bits
    if not (0 <= i < levels and 0 <= j < levels):
        raise ValueError("noncanonical pair index")
    return (decompress(2 * i + j % 2, q, bits + 1), decompress(j, q, bits))


@cache
def grids(q, bits):
    if q < 3 or q % 2 != 1 or not 1 <= bits <= (q - 1).bit_length():
        raise ValueError("odd modulus and bounded positive precision required")
    levels = 1 << bits
    if levels >= q:
        raise ValueError("pair grid restricted to levels < q")
    rows = tuple(decompress(j, q, bits) for j in range(levels))
    xs = tuple(tuple(decompress(2 * i + phase, q, bits + 1) for i in range(levels))
               for phase in (0, 1))
    return rows, xs


def neighbors(values, target):
    position = bisect_left(values, target)
    return sorted({position % len(values), (position - 1) % len(values)})


def encode_pair(x, y, q, bits):
    """A deterministic four-neighbor encoder; exact raw pair inputs only."""
    if not 0 <= x < q or not 0 <= y < q:
        raise ValueError("noncanonical input coefficient")
    rows, xs = grids(q, bits)
    candidates = []
    for j in neighbors(rows, y):
        for i in neighbors(xs[j % 2], x):
            a, b = reconstruction(i, j, q, bits)
            error = centered(a - x, q), centered(b - y, q)
            candidates.append((sum(e * e for e in error), j * (1 << bits) + i, i, j))
    _, _, i, j = min(candidates)
    return i, j


def cover_certificate(q, bits):
    rows, xs = grids(q, bits)
    levels = 1 << bits
    gaps = [((values[(i + 1) % levels] - values[i]) % q)
            for values in (rows, *xs) for i in range(levels)]
    row_gaps = [(rows[(j + 1) % levels] - rows[j]) % q for j in range(levels)]
    union = set(xs[0]) | set(xs[1])
    distinct = len(set(rows)) == levels and all(len(set(values)) == levels for values in xs)
    alternates = all((j % 2) != (((j + 1) % levels) % 2) for j in range(levels))
    certified = distinct and max(gaps) <= 2 and union == set(range(q)) and alternates
    return {"q": q, "bits_per_coordinate_label": bits, "levels": levels,
            "distinct_rows_and_columns": distinct, "maximum_circular_gap": max(gaps),
            "row_gap_counts": {str(g): row_gaps.count(g) for g in sorted(set(row_gaps))},
            "adjacent_row_phases_alternate_including_wrap": alternates,
            "two_column_phases_cover_all_residues": len(union) == q,
            "certified_L1_error_at_most_one": certified,
            "unique_codewords": levels ** 2, "fixed_pair_bits": 2 * bits,
            "proof": "on a row, a column is within one; between rows at distance two, their column phases cover every x"}


@cache
def local_risk(dx, dy, eta=3, z=Fraction(13, 10)):
    # E[z^(S1*dx+S2*dy)] for independent ideal CBD eta secrets. Used only as
    # a toy distortion metric, never as a law for actual ciphertext inputs.
    return mgf_cbd(eta, z ** dx) * mgf_cbd(eta, z ** dy)


@cache
def grouped_mgf(eta, error_support, z):
    probabilities = {s: Fraction(math.comb(2 * eta, eta + s), 1 << (2 * eta))
                     for s in range(-eta, eta + 1)}
    conditional = {s: sum((p * z ** (-s * e) for e, p in probabilities.items()), Fraction(0))
                   for s in probabilities}
    total = Fraction(0)
    for s1, p1 in probabilities.items():
        for s2, p2 in probabilities.items():
            support_value = max(abs(s1 * dx + s2 * dy) for dx, dy in error_support)
            total += p1 * p2 * conditional[s1] * conditional[s2] * z ** support_value
    return total


DIAMOND = ((-1, 0), (0, -1), (0, 0), (0, 1), (1, 0))
BOX = tuple(itertools.product((-1, 0, 1), repeat=2))


def pair_positions(groups):
    pairs = TOTAL // 2
    if not 0 <= groups <= pairs:
        raise ValueError("invalid fixed pair count")
    return [i for i in range(pairs) if ((i + 1) * groups) // pairs > (i * groups) // pairs]


def toy_study(q, bits):
    levels = 1 << bits
    points = [(i, j, reconstruction(i, j, q, bits))
              for j in range(levels) for i in range(levels)]
    reports = []
    for mode in ("scalar_fips", "staggered_nearest_L2", "staggered_local_MGF"):
        histogram = Counter()
        for x in range(q):
            for y in range(q):
                if mode == "scalar_fips":
                    restored = (decompress(compress(x, q, bits), q, bits),
                                decompress(compress(y, q, bits), q, bits))
                    error = centered(restored[0] - x, q), centered(restored[1] - y, q)
                else:
                    choices = []
                    for i, j, (a, b) in points:
                        delta = centered(a - x, q), centered(b - y, q)
                        distance = sum(e * e for e in delta)
                        score = distance if mode == "staggered_nearest_L2" else local_risk(*delta)
                        choices.append((score, distance, j * levels + i, delta))
                    error = min(choices)[3]
                histogram[error] += 1
        mass = q * q
        mse = sum(Fraction((dx * dx + dy * dy) * count, mass)
                  for (dx, dy), count in histogram.items())
        risk = sum((count * local_risk(dx, dy) / mass for (dx, dy), count in histogram.items()), Fraction(0))
        support = tuple(sorted(histogram))
        z = Fraction(13, 10)
        mgf = grouped_mgf(3, support, z)
        reports.append({"mode": mode, "states": mass, "unique_codewords": levels ** 2,
                        "fixed_pair_bits": 2 * bits, "mean_squared_error_uniform_input": str(mse),
                        "mean_local_MGF_uniform_input": str(risk),
                        "maximum_L1_error": max(abs(dx) + abs(dy) for dx, dy in support),
                        "group_domination_MGF_z13over10": str(mgf),
                        "error_histogram": [{"error": list(delta), "count": count}
                                            for delta, count in sorted(histogram.items())]})
    return {"q": q, "bits": bits, "cover": cover_certificate(q, bits), "results": reports,
            "scope": "exact uniform small-torus distortion, not rank-6 decryption failure"}


def exact_pair_bound(groups, dv, z, *, certificate=False):
    if not 0 <= groups <= TOTAL // 2:
        raise ValueError("invalid fixed count of quantized pairs")
    if not cover_certificate(Q, 12)["certified_L1_error_at_most_one"]:
        raise ArithmeticError("actual-modulus pair cover not certified")
    radius, v_range = safe_radius(Q, dv)
    product = mgf_product(ETA, z)
    pair_mgf = grouped_mgf(ETA, DIAMOND, z)
    bound = 2 * N * product ** (2 * TOTAL - 2 * groups) * mgf_cbd(ETA, z)
    bound *= pair_mgf ** groups / z ** (radius + 1)
    upper = min(Fraction(1), bound)
    passes = (upper.numerator ** 5 << 874) <= upper.denominator ** 5
    row = {"quantized_pairs": groups, "exact_coefficients": TOTAL - 2 * groups,
           "quantized_pairs_per_polynomial": [sum(b * 128 <= i < (b + 1) * 128
                                                  for i in pair_positions(groups)) for b in range(K)],
           "dv": dv, "z": str(z), "tail_threshold": radius + 1, "v_error_range": list(v_range),
           "ciphertext_bits": 13 * TOTAL - 2 * groups + N * dv,
           "ciphertext_bytes": (13 * TOTAL - 2 * groups + N * dv + 7) // 8,
           "message_upper": probability_record(upper),
           "uncapped_log2": math.log2(bound.numerator) - math.log2(bound.denominator),
           "c05_exact_comparison": passes,
           "status": "certified_in_ideal_CBD_model" if passes else "not_certified_by_this_bound"}
    if certificate:
        row["certificate"] = {"product_MGF": rational_hex(product),
                              "pair_domination_MGF": rational_hex(pair_mgf),
                              "e2_MGF": rational_hex(mgf_cbd(ETA, z)),
                              "uncapped_bound": rational_hex(bound)}
    return row


def pair_scan():
    probabilities = {s: math.comb(6, 3 + s) / 64 for s in range(-3, 4)}
    grid = []
    for tilt in TILTS:
        z = float(tilt)
        product = sum(ps * pe * z ** (s * e) for s, ps in probabilities.items() for e, pe in probabilities.items())
        cond = {s: sum(pe * z ** (-s * e) for e, pe in probabilities.items()) for s in probabilities}
        pair = sum(p1 * p2 * cond[s1] * cond[s2] * z ** max(abs(s1), abs(s2))
                   for s1, p1 in probabilities.items() for s2, p2 in probabilities.items())
        grid.append((tilt, math.log2(z),
                     math.log2(512) + 2 * TOTAL * math.log2(product)
                     + 3 * math.log2((z + 2 + 1 / z) / 4),
                     math.log2(pair) - 2 * math.log2(product)))
    results, screening = [], []
    for dv in DV_VALUES:
        threshold = safe_radius(Q, dv)[0] + 1
        candidates = []
        for z, log_z, common, penalty in grid:
            base = common - threshold * log_z
            allowed = min(TOTAL // 2, math.floor((-174.8 - base) / penalty))
            count = max(0, allowed // 4 * 4)
            screening.append({"dv": dv, "z": str(z), "base_log2": base,
                              "penalty_log2_per_pair": penalty, "proposed_pairs": count})
            if allowed >= 0:
                candidates.append((count, base + count * penalty))
        count = max((count for count, _ in candidates), default=0)
        for groups in sorted({count, min(TOTAL // 2, count + 4)}):
            chosen = min(grid, key=lambda g: g[2] - threshold * g[1] + groups * g[3])
            row = exact_pair_bound(groups, dv, chosen[0])
            approximate = chosen[2] - threshold * chosen[1] + groups * chosen[3]
            if abs(approximate - row["uncapped_log2"]) > 1e-6:
                raise ArithmeticError("pair screening/rational mismatch")
            row["id"] = f"staggered-dv{dv}-pairs{groups}"
            row["role"] = "screening_boundary" if groups == count else "next_byte_step"
            results.append(row)
    winner = min((r for r in results if r["c05_exact_comparison"]),
                 key=lambda r: (r["ciphertext_bytes"], r["message_upper"]["log2"], r["id"]))
    certificate = exact_pair_bound(winner["quantized_pairs"], winner["dv"], Fraction(winner["z"]), certificate=True)
    certificate["id"] = winner["id"]
    return {"parameters": dict(q=Q, n=N, k=K, eta1=ETA, eta2=ETA),
            "tilt_grid": {"points": len(TILTS), "first": str(TILTS[0]), "last": str(TILTS[-1])},
            "results": results, "screening": screening, "best_found_id": winner["id"],
            "winner_certificate": certificate, "profile_selected": False, "j2_closed": False,
            "limits": ["ideal independent CBD primitives; no rounding independence",
                       "fixed public adjacent-coefficient pair mask; no adaptive key/message choice",
                       "best found in explored grid; non-certification is not actual failure",
                       "no rank-6 KEM, new attack estimate, timing or fixed-SHAKE proof"]}
