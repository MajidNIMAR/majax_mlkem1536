"""Isolate P0 correctness defects without selecting a replacement profile.

All probabilities are exact in the CBD/uniform-independent-u model. The
bounded-v interval calculation permits arbitrary dependence of the final
rounding error on the message and pre-rounding noise. It does NOT remove the
independence/uniformity assumption for u or prove correctness of a real KEM.
"""

from fractions import Fraction
import math

from noise_exact import (Law, analyze, cbd, combine, compress, decompress,
                         probability_record, rounding_law, symmetric_power)


def decoder_interval(q: int, bit: int) -> tuple[int, int]:
    if q < 3 or q % 2 != 1 or bit not in (0, 1):
        raise ValueError("odd q >= 3 and a binary message are required")
    if bit == 0:
        return -(q // 4), q // 4
    residues = [x for x in range(q) if compress(x, q, 1) == 1]
    mu = decompress(1, q, 1)
    return min(residues) - mu, max(residues) - mu


def bounded_rounding_failures(offset: int, weights: list[int], denominator: int,
                              final: Law, q: int, error_min: int,
                              error_max: int) -> list[tuple[Fraction, Fraction]]:
    """Marginal lower/upper failure bounds for any error in [min, max].

    Correct residues form periodic intervals [L,U]. They are reachable by at
    least one allowed error for T in [L-max,U-min], and reached by every error
    for T in [L-min,U-max]. Periodic intervals are counted with exact integers.
    Requiring the error span to be shorter than both decoding arcs ensures
    the intersection cannot wrap around and join a different interval.
    """
    if not weights or any(w < 0 for w in weights) or sum(weights) != denominator:
        raise ValueError("invalid base distribution")
    if error_min > error_max or final.denominator != sum(final.weights.values()):
        raise ValueError("invalid final distribution or error interval")
    intervals = [decoder_interval(q, bit) for bit in (0, 1)]
    if error_max - error_min >= min(u - l + 1 for l, u in intervals):
        raise ValueError("rounding span must be shorter than both decoding arcs")
    prefix = [0]
    for weight in weights:
        prefix.append(prefix[-1] + weight)
    support_upper = offset + len(weights) - 1

    def periodic_mass(lower, upper, extra):
        if upper < lower:
            return 0
        if upper - lower + 1 >= q:
            return denominator
        first = (offset + extra - upper) // q - 1
        last = (support_upper + extra - lower) // q + 1
        total = 0
        for period in range(first, last + 1):
            start = max(0, lower - extra + period * q - offset)
            end = min(len(weights), upper - extra + period * q - offset + 1)
            if end > start:
                total += prefix[end] - prefix[start]
        if not 0 <= total <= denominator:
            raise ArithmeticError("invalid periodic interval mass")
        return total

    result = []
    for lower, upper in intervals:
        reachable = sum(w * periodic_mass(lower - error_max, upper - error_min, x)
                        for x, w in final.weights.items())
        guaranteed = sum(w * periodic_mass(lower - error_min, upper - error_max, x)
                         for x, w in final.weights.items())
        mass = denominator * final.denominator
        bounds = Fraction(mass - reachable, mass), Fraction(mass - guaranteed, mass)
        if not 0 <= bounds[0] <= bounds[1] <= 1:
            raise ArithmeticError("invalid failure bracket")
        result.append(bounds)
    return result


def variance_components(parameters: dict) -> dict:
    p = parameters
    count = p["n"] * p["k"]
    v1, v2 = cbd(p["eta1"]).variance(), cbd(p["eta2"]).variance()
    ru = rounding_law(p["q"], p["du"])
    # s is centered, but ru need not be: Var(s*ru)=Var(s)*E[ru^2].
    # Half-up rounding has a small nonzero mean for these odd moduli.
    second_u = ru.variance() + ru.mean() ** 2
    vv = rounding_law(p["q"], p["dv"]).variance()
    components = {"e_times_y": count * v1 * v1,
                  "s_times_e1": count * v1 * v2,
                  "s_times_rounding_u": count * v1 * second_u,
                  "e2": v2, "rounding_v": vv}
    total = sum(components.values(), Fraction(0))
    return {"terms": {key: {"exact": str(value), "decimal": float(value),
                            "percent_of_variance": float(100 * value / total)}
                      for key, value in components.items()},
            "intrinsic_variance": str(components["e_times_y"]
                                      + components["s_times_e1"] + components["e2"]),
            "total_variance": str(total), "standard_deviation": math.sqrt(total),
            "rounding_u_mean": str(ru.mean()),
            "rounding_u_second_moment": str(second_u),
            "interpretation": "variance shares do not measure contributions to rare-event tails"}


def diagnose(parameters: dict) -> dict:
    p = parameters
    independent = analyze(**p)
    secret, errors = cbd(p["eta1"]), cbd(p["eta2"])
    ru, rv = rounding_law(p["q"], p["du"]), rounding_law(p["q"], p["dv"])
    pair = combine(combine(secret, secret, product=True),
                   combine(secret, combine(errors, ru), product=True))
    offset, weights, denominator = symmetric_power(pair, p["n"] * p["k"])
    lower_error, upper_error = min(rv.weights), max(rv.weights)
    brackets = bounded_rounding_failures(offset, weights, denominator, errors,
                                         p["q"], lower_error, upper_error)
    # Exact all-independent marginal used only to check interval inclusion.
    # No logarithmic comparison is used for this consistency check.
    independent_bounds = bounded_rounding_failures(
        offset, weights, denominator, combine(errors, rv), p["q"], 0, 0)
    for bit, (lower, upper) in enumerate(brackets):
        exact, exact_upper = independent_bounds[bit]
        if exact != exact_upper:
            raise ArithmeticError("a fixed error must yield an exact probability")
        if not lower <= exact <= upper:
            raise ArithmeticError("independent marginal lies outside robust bracket")
        if probability_record(exact) != independent[f"bit{bit}_failure"]:
            raise ArithmeticError("separate interval counting disagrees with frozen arithmetic")
    average_lower = sum(pair[0] for pair in brackets) / 2
    average_upper = sum(pair[1] for pair in brackets) / 2
    smallest_lower = min(pair[0] for pair in brackets)
    components = variance_components(p)
    if components["total_variance"] != independent["coefficient_variance"]:
        raise ArithmeticError("variance decomposition does not match exact law")
    return {"independent_rounding_result": independent,
            "variance_decomposition": components,
            "arbitrary_bounded_v": {
                "error_range": [lower_error, upper_error],
                "remaining_assumptions": "independent CBD; independent uniform pre-compression u",
                "removed_assumption": "no independence or uniformity needed for rounding_v",
                "bit0_lower": probability_record(brackets[0][0]),
                "bit0_upper": probability_record(brackets[0][1]),
                "bit1_lower": probability_record(brackets[1][0]),
                "bit1_upper": probability_record(brackets[1][1]),
                "message_lower_uniform_bits": probability_record(average_lower),
                "message_lower_any_fixed_message": probability_record(smallest_lower),
                "message_union_upper_uniform_bits": probability_record(min(1, p["n"] * average_upper)),
                "message_union_upper_any_message": probability_record(
                    min(1, p["n"] * max(pair[1] for pair in brackets))),
                "crosscheck_independent_marginals": "exact rational agreement"}}
