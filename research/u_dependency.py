"""Exact ideal-law toy checks and correctness witnesses without u rounding.

These are mathematical experiments, not a rank-6 KEM implementation. The
witness permits arbitrary dependence of v rounding and any public matrix,
but retains the explicitly idealized independent CBD sampling model.
"""

from collections import Counter
from fractions import Fraction
import itertools
import math

from decapsulation_diagnostic import bounded_rounding_failures
from noise_exact import (cbd, combine, compress, decompress, probability_record,
                         rounding_law, symmetric_power)


def negacyclic(left, right, q):
    if not left or len(left) != len(right):
        raise ValueError("equal nonzero polynomial lengths required")
    n = len(left)
    result = [0] * n
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            result[(i + j) % n] += (-1 if i + j >= n else 1) * a * b
    return tuple(x % q for x in result)


def image_counts(y, q):
    """Enumerate the image, with multiplicity, of sum_i A_i*y_i."""
    if not y or any(len(poly) != len(y[0]) for poly in y):
        raise ValueError("nonempty vector of equally sized polynomials required")
    n = len(y[0])
    ring = list(itertools.product(range(q), repeat=n))
    image = Counter({(0,) * n: 1})
    for poly in y:
        single = Counter(negacyclic(a, poly, q) for a in ring)
        joint = Counter()
        for a, wa in image.items():
            for b, wb in single.items():
                joint[tuple((x + z) % q for x, z in zip(a, b))] += wa * wb
        image = joint
    return image


def total_variation(left, denominator_left, right, denominator_right):
    return sum((abs(Fraction(left.get(x, 0), denominator_left)
                    - Fraction(right.get(x, 0), denominator_right))
                for x in set(left) | set(right)), Fraction(0)) / 2


def rational_record(value):
    return {"fraction": str(value), "decimal": float(value),
            "log2": math.log2(value.numerator) - math.log2(value.denominator) if value else None}


def toy_coset_study(k):
    """All y,A,e1 at q=5,n=2. x^2+1 has roots 2 and 3 in F_5.

    y coefficients use CBD2, e1 uses CBD1. No independence of u, y and e1 is
    imposed: u is constructed from its algebraic definition for every state.
    """
    if k not in (1, 2):
        raise ValueError("exhaustive toy restricted to ranks one and two")
    q, n, bits = 5, 2, 1
    ring = list(itertools.product(range(q), repeat=n))
    y_law, error_law = cbd(2), cbd(1)
    y_polys = [(tuple(x % q for x in p), math.prod(y_law.weights[x] for x in p))
               for p in itertools.product(y_law.weights, repeat=n)]
    errors = [(p, math.prod(error_law.weights[x] for x in p))
              for p in itertools.product(error_law.weights, repeat=n)]
    image_cache = {p: Counter(negacyclic(a, p, q) for a in ring) for p, _ in y_polys}
    joint, full_joint, branches = Counter(), Counter(), Counter()
    y_total, matrix_total = y_law.denominator ** (n * k), q ** (n * k)
    checked = 0
    for weighted_y in itertools.product(y_polys, repeat=k):
        ys, y_weight = tuple(p for p, _ in weighted_y), math.prod(w for _, w in weighted_y)
        image = Counter({(0, 0): 1})
        for poly in ys:
            following = Counter()
            for a, wa in image.items():
                for b, wb in image_cache[poly].items():
                    following[tuple((x + z) % q for x, z in zip(a, b))] += wa * wb
            image = following
        inactive = [root for root in (2, 3)
                    if all((poly[0] + root * poly[1]) % q == 0 for poly in ys)]
        predicted = {p for p in ring if all((p[0] + root * p[1]) % q == 0 for root in inactive)}
        if set(image) != predicted or len(set(image.values())) != 1 or sum(image.values()) != matrix_total:
            raise ArithmeticError("conditional uniform-on-ideal law failed")
        branches[len(inactive)] += y_weight
        full = not inactive
        for e1, ew in errors:
            shifted = {tuple((a + b) % q for a, b in zip(value, e1)): count
                       for value, count in image.items()}
            if len(shifted) != len(predicted) or len(set(shifted.values())) != 1:
                raise ArithmeticError("translation did not preserve uniform coset")
            for u, count in shifted.items():
                restored = decompress(compress(u[0], q, bits), q, bits)
                delta = (restored - u[0] + q // 2) % q - q // 2
                weight = y_weight * ew * count
                joint[delta, e1[0]] += weight
                if full:
                    full_joint[delta, e1[0]] += weight
        checked += 1
    denominator = y_total * matrix_total * error_law.denominator ** n
    if sum(joint.values()) != denominator:
        raise ArithmeticError("toy probability mass failed")
    rounding = rounding_law(q, bits)
    ideal = {(delta, e): wd * we for delta, wd in rounding.weights.items()
             for e, we in error_law.weights.items()}
    ideal_denominator = rounding.denominator * error_law.denominator
    tv = total_variation(joint, denominator, ideal, ideal_denominator)
    full_tv = total_variation(full_joint, sum(full_joint.values()), ideal, ideal_denominator)
    rounding_marginal, e1_marginal = Counter(), Counter()
    for (delta, e1), weight in joint.items():
        rounding_marginal[delta] += weight
        e1_marginal[e1] += weight
    actual_product = {(delta, e1): wd * we for delta, wd in rounding_marginal.items()
                      for e1, we in e1_marginal.items()}
    dependence_tv = total_variation(joint, denominator, actual_product, denominator ** 2)
    if full_tv != 0 or tv <= 0 or dependence_tv <= 0:
        raise ArithmeticError("toy failed to distinguish conditional from unconditional law")
    sum_actual = Counter()
    sum_ideal = Counter()
    for (delta, e1), weight in joint.items():
        sum_actual[delta + e1] += weight
    for (delta, e1), weight in ideal.items():
        sum_ideal[delta + e1] += weight
    return {"parameters": {"q": q, "n": n, "k": k, "eta_y": 2, "eta_e1": 1, "du": bits},
            "y_vectors_checked": checked,
            "conditional_images_and_cosets": "all exact checks passed",
            "inactive_factor_probabilities": {str(key): rational_record(Fraction(value, y_total))
                                              for key, value in sorted(branches.items())},
            "non_surjective_y_probability": rational_record(Fraction(sum(
                value for key, value in branches.items() if key), y_total)),
            "joint_rounding_e1_tv_from_independent_reference": rational_record(tv),
            "joint_tv_from_product_of_actual_marginals": rational_record(dependence_tv),
            "rounding_marginal_tv_from_uniform_input_reference": rational_record(
                total_variation(rounding_marginal, denominator, rounding.weights, rounding.denominator)),
            "sum_e1_rounding_tv_from_independent_reference": rational_record(
                total_variation(sum_actual, denominator, sum_ideal, ideal_denominator)),
            "joint_tv_conditioned_on_full_ideal": rational_record(full_tv),
            "denominator": denominator,
            "joint_counts": [{"rounding": delta, "e1": e1, "weight": weight}
                             for (delta, e1), weight in sorted(joint.items())],
            "scope": "exact small-ring counterexample, not rank-6 failure probability"}


def meets_c05(value):
    """Exact comparison p <= 2^(-174.8) = 2^(-874/5)."""
    if not 0 <= value <= 1:
        raise ValueError("probability required")
    return (value.numerator ** 5 << 874) <= value.denominator ** 5


def lossless_u_witness(q, eta, dv_values):
    """Exact one-coordinate intrinsic law; arbitrary bounded v rounding.

    u is transmitted exactly. Matrix cancellation is algebraic, so no matrix
    uniformity, ideal event, or rounding independence is used for this bound.
    Independent ideal CBD coefficients are still required. Bounds average over
    secret/noise sampling; they are not worst-key or malicious-ciphertext bounds.
    """
    n, k = 256, 6
    raw_bits = (q - 1).bit_length()
    if set(rounding_law(q, raw_bits).weights) != {0}:
        raise ArithmeticError("u restoration is not lossless")
    small = cbd(eta)
    product = combine(small, small, product=True)
    # e*y and -s*e1 have the same symmetric law here, so 2*n*k powers
    # form the intrinsic noise before the final CBD e2 contribution.
    offset, weights, denominator = symmetric_power(product, 2 * n * k)
    results = []
    for dv in dv_values:
        v_rounding = rounding_law(q, dv)
        a, b = min(v_rounding.weights), max(v_rounding.weights)
        bounds = bounded_rounding_failures(offset, weights, denominator, small, q, a, b)
        single_lower = min(lower for lower, _ in bounds)
        message_upper = min(Fraction(1), n * max(upper for _, upper in bounds))
        uniform_upper = min(Fraction(1), n * sum(upper for _, upper in bounds) / 2)
        results.append({"dv": dv, "v_error_range": [a, b],
                        "bit0_lower": probability_record(bounds[0][0]),
                        "bit0_upper": probability_record(bounds[0][1]),
                        "bit1_lower": probability_record(bounds[1][0]),
                        "bit1_upper": probability_record(bounds[1][1]),
                        "message_lower_any_fixed_message": probability_record(single_lower),
                        "message_union_upper_any_fixed_message": probability_record(message_upper),
                        "message_union_upper_uniform_bits": probability_record(uniform_upper),
                        "c05_exact_upper_comparison": meets_c05(message_upper),
                        "c05_exact_lower_exceeds_threshold": not meets_c05(single_lower),
                        "honest_2pow32_decaps_union_upper": probability_record(
                            min(Fraction(1), (1 << 32) * message_upper)),
                        "ciphertext_bytes_same_logical_layout": n * (k * raw_bits + dv) // 8})
    return {"parameters": {"n": n, "k": k, "q": q, "eta1": eta, "eta2": eta},
            "u_encoding": {"mode": "exact raw coefficients", "bits": raw_bits, "error": 0},
            "sampler_model": "independent ideal CBD primitives; no fixed-SHAKE equivalence claim",
            "matrix_model": "arbitrary; cancellation removes it from intrinsic residual",
            "no_rounding_independence_assumption": True,
            "key_scope": "average over honestly sampled keys, any message fixed independently of keys",
            "arithmetic": "exact integers and rational bounds; no Gaussian or tail truncation",
            "intrinsic_variance": str(2 * n * k * small.variance() ** 2 + small.variance()),
            "results": results}
