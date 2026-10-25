"""Dependence-agnostic mixed-precision correctness bounds, not a KEM.

For each coefficient, -s*delta_u <= r*abs(s) pointwise. Independence is
required only for the ideal CBD primitives, never for rounding errors.
"""

from fractions import Fraction
from functools import cache
import math

from noise_exact import probability_record, rounding_law
from witness_chernoff import mgf_cbd, mgf_product, rational_hex, safe_radius

Q, N, K, ETA = 7681, 256, 6, 3
TOTAL = N * K
WIDTHS = (11, 12, 13)
DV_VALUES = (2, 3, 4, 5, 6, 7, 8, 13)
TILTS = tuple(Fraction(j, 1000) for j in range(1001, 1501))


@cache
def error_radius(width):
    if width not in WIDTHS:
        raise ValueError("study restricted to 11/12/13-bit u precision")
    law = rounding_law(Q, width)
    return max(abs(x) for x in law.weights)


@cache
def domination_mgf(eta, radius, z):
    if eta < 1 or radius < 0 or z <= 1:
        raise ValueError("positive eta, nonnegative radius and z>1 required")
    return sum((math.comb(2 * eta, eta + s) * math.comb(2 * eta, eta + e)
                * z ** (-s * e + radius * abs(s))
                for s in range(-eta, eta + 1) for e in range(-eta, eta + 1)),
               Fraction(0)) / (1 << (4 * eta))


def exact_c05(value):
    if not 0 <= value <= 1:
        raise ValueError("probability required")
    return (value.numerator ** 5 << 874) <= value.denominator ** 5


def interleaved_widths(compressed):
    """Public fixed mask: balance m 12-bit entries across 1536 positions."""
    if not 0 <= compressed <= TOTAL:
        raise ValueError("invalid compressed count")
    return [12 if ((i + 1) * compressed) // TOTAL > (i * compressed) // TOTAL else 13
            for i in range(TOTAL)]


def exact_bound(counts, dv, z, *, full_certificate=False):
    if set(counts) != set(WIDTHS) or sum(counts.values()) != TOTAL:
        raise ValueError("exactly 1536 entries split over 11/12/13 bits required")
    if any(not isinstance(value, int) or value < 0 for value in counts.values()):
        raise ValueError("nonnegative integer counts required")
    radius, v_range = safe_radius(Q, dv)
    product = mgf_product(ETA, z)
    mgfs = {width: domination_mgf(ETA, error_radius(width), z) for width in WIDTHS}
    value = 2 * N * product ** TOTAL * mgf_cbd(ETA, z) / z ** (radius + 1)
    for width, count in counts.items():
        value *= mgfs[width] ** count
    upper = min(Fraction(1), value)
    bits = sum(width * count for width, count in counts.items()) + N * dv
    result = {"u_counts": {str(key): value for key, value in sorted(counts.items())},
              "dv": dv, "z": str(z), "v_error_range": list(v_range),
              "tail_threshold": radius + 1,
              "u_error_radii": {str(width): error_radius(width) for width in WIDTHS},
              "ciphertext_bits": bits, "ciphertext_bytes": (bits + 7) // 8,
              "message_upper": probability_record(upper),
              "uncapped_log2_chernoff": math.log2(value.numerator) - math.log2(value.denominator),
              "c05_exact_comparison": exact_c05(upper),
              "status": "certified_in_ideal_CBD_model" if exact_c05(upper)
                        else "not_certified_by_this_bound"}
    if full_certificate:
        result["certificate"] = {"mgf_product": rational_hex(product),
                                 "mgf_e2": rational_hex(mgf_cbd(ETA, z)),
                                 "domination_mgfs": {str(width): rational_hex(mgf)
                                                     for width, mgf in mgfs.items()},
                                 "uncapped_bound": rational_hex(value)}
    return result


def numerical_grid():
    """Screening only: every reported acceptance is checked rationally."""
    result = []
    radii = {width: error_radius(width) for width in WIDTHS}
    for rational in TILTS:
        z = float(rational)
        product = sum(math.comb(6, 3 + a) * math.comb(6, 3 + b) * z ** (a * b)
                      for a in range(-3, 4) for b in range(-3, 4)) / 4096
        logs = {}
        for width, radius in radii.items():
            mgf = sum(math.comb(6, 3 + s) * math.comb(6, 3 + e)
                      * z ** (-s * e + radius * abs(s))
                      for s in range(-3, 4) for e in range(-3, 4)) / 4096
            logs[width] = math.log2(mgf)
        result.append({"z": rational, "log_z": math.log2(z),
                       "common": math.log2(2 * N) + TOTAL * math.log2(product)
                                 + 3 * math.log2((z + 2 + 1 / z) / 4),
                       "logs": logs})
    return result


def screen_log(grid_row, counts, threshold):
    return (grid_row["common"] + sum(counts[w] * grid_row["logs"][w] for w in WIDTHS)
            - threshold * grid_row["log_z"])


def scan():
    grid = numerical_grid()
    block_results = []
    coefficient_results = []
    screening = []
    for dv in DV_VALUES:
        threshold = safe_radius(Q, dv)[0] + 1
        for blocks11 in range(K + 1):
            for blocks12 in range(K - blocks11 + 1):
                counts = {11: N * blocks11, 12: N * blocks12,
                          13: N * (K - blocks11 - blocks12)}
                selected = min(grid, key=lambda g: screen_log(g, counts, threshold))
                row = exact_bound(counts, dv, selected["z"])
                row["id"] = f"blocks-dv{dv}-b11-{blocks11}-b12-{blocks12}"
                row["family"] = "whole_polynomial_blocks"
                row["screening_log2"] = screen_log(selected, counts, threshold)
                if abs(row["uncapped_log2_chernoff"] - row["screening_log2"]) > 1e-6:
                    raise ArithmeticError("floating screening disagrees with rational replay")
                block_results.append(row)
        proposals = []
        for g in grid:
            base = g["common"] + TOTAL * g["logs"][13] - threshold * g["log_z"]
            slope = g["logs"][12] - g["logs"][13]
            if slope <= 0:
                raise ArithmeticError("unexpected nonpositive compression penalty")
            allowed = min(TOTAL, math.floor((-174.8 - base) / slope))
            count = max(0, allowed // 8 * 8)
            screening.append({"dv": dv, "z": str(g["z"]),
                              "log2_base": base, "log2_penalty_per_12bit_entry": slope,
                              "proposed_12bit_count": count,
                              "screening_only": True})
            if allowed >= 0:
                proposals.append((count, base + count * slope, g))
        if proposals:
            count, _, selected = min(proposals, key=lambda x: (-x[0], x[1]))
        else:
            count = 0
            selected = min(grid, key=lambda g: screen_log(g, {11: 0, 12: 0, 13: TOTAL}, threshold))
        counts_to_replay = sorted({count, min(TOTAL, count + 8)})
        for m in counts_to_replay:
            counts = {11: 0, 12: m, 13: TOTAL - m}
            selected = min(grid, key=lambda g: screen_log(g, counts, threshold))
            row = exact_bound(counts, dv, selected["z"])
            row["id"] = f"interleaved-dv{dv}-m12-{m}"
            row["family"] = "fixed_interleaved_coefficient_mask"
            row["screening_log2"] = screen_log(selected, counts, threshold)
            if abs(row["uncapped_log2_chernoff"] - row["screening_log2"]) > 1e-6:
                raise ArithmeticError("coefficient screening disagrees with rational replay")
            row["role"] = "screening_boundary" if m == count else "next_byte_step"
            row["compressed_counts_per_polynomial"] = [
                sum(width == 12 for width in interleaved_widths(m)[b * N:(b + 1) * N])
                for b in range(K)]
            coefficient_results.append(row)
    rows = block_results + coefficient_results
    accepted = [row for row in rows if row["c05_exact_comparison"]]
    winner = min(accepted, key=lambda row: (row["ciphertext_bytes"],
                                          row["message_upper"]["log2"], row["id"]))
    certificate = exact_bound({int(w): count for w, count in winner["u_counts"].items()},
                              winner["dv"], Fraction(winner["z"]), full_certificate=True)
    certificate["id"] = winner["id"]
    reference = exact_bound({11: 0, 12: 0, 13: TOTAL}, 5, Fraction(13, 10))
    return {"parameters": dict(q=Q, n=N, k=K, eta1=ETA, eta2=ETA),
            "tilt_grid": {"first": str(TILTS[0]), "last": str(TILTS[-1]), "points": len(TILTS)},
            "block_results": block_results, "coefficient_results": coefficient_results,
            "screening": screening, "best_found_id": winner["id"],
            "certified_count": len(accepted), "not_certified_count": len(rows) - len(accepted),
            "reference_run004": reference, "winner_certificate": certificate,
            "profile_selected": False, "j2_closed": False,
            "limits": ["independent ideal CBD primitives; honest average-key correctness",
                       "floating tilt/count screening followed by exact decisions for reported candidates",
                       "non-certification is not a proof that the actual candidate fails C05",
                       "best found in explored families/grid, not global optimality",
                       "no rank-6 KEM, timing measurements or new attack estimates",
                       "all precision masks public and fixed; no data-dependent choice"]}
