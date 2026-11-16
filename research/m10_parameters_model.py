"""Pure parameter/resource decisions; finite models are not KEM security proofs."""
from fractions import Fraction
from itertools import combinations, product
import math


def require(value, message):
    if not value:
        raise ValueError(message)


def fraction_record(value):
    value = Fraction(value)
    return {"numerator_hex": format(value.numerator, "x"), "denominator_hex": format(value.denominator, "x")}


def common_mapping_bounds(space, tested_candidates, targets):
    """U iid hidden points, q distinct tested points in a common domain.

    The exact hit probability is 1-(1-q/M)^U. Bonferroni gives a compact
    rational interval even for U=2^40, without constructing huge powers.
    """
    require(type(space) is int and space > 0 and type(tested_candidates) is int
            and 0 <= tested_candidates <= space and type(targets) is int and targets >= 0,
            "finite search domain/counters required")
    p = Fraction(tested_candidates, space)
    return max(Fraction(0), targets * p - (targets * (targets - 1) // 2) * p * p), min(Fraction(1), targets * p)


def independent_key_message_hit(space, allocation):
    """Per-key predicates: q_i tests of the independent message under key i."""
    require(space > 0 and all(type(q) is int and 0 <= q <= space for q in allocation), "invalid allocation")
    failure = Fraction(1)
    for q in allocation:
        failure *= 1 - Fraction(q, space)
    return 1 - failure


def grover_success(space, marked, iterations):
    """Exact success of the Grover iterate, without evaluating transcendental terms."""
    require(type(space) is int and space > 0 and type(marked) is int and 0 <= marked <= space
            and type(iterations) is int and iterations >= 0, "invalid Grover model")
    p = Fraction(marked, space)
    good = bad = Fraction(1)
    for _ in range(iterations):
        good, bad = (1 - 2 * p) * good + 2 * (1 - p) * bad, -2 * p * good + (1 - 2 * p) * bad
        require(p * good * good + (1 - p) * bad * bad == 1, "Grover norm changed")
    return p * good * good


def finite_search_checks():
    common, allocations, quantum = 0, 0, 0
    for space in (2, 3, 4, 5, 8):
        for count in range(space + 1):
            tested = set(range(count))
            for targets in range(4):
                hits = sum(any(x in tested for x in hidden) for hidden in product(range(space), repeat=targets))
                observed = Fraction(hits, space ** targets)
                exact = 1 - (1 - Fraction(count, space)) ** targets
                lower, upper = common_mapping_bounds(space, count, targets)
                require(observed == exact and lower <= exact <= upper, "common mapping interval failed")
                common += 1
        for allocation in product(range(space + 1), repeat=3):
            if sum(allocation) > space:
                continue
            exact = independent_key_message_hit(space, allocation)
            require(exact <= Fraction(sum(allocation), space), "cross-key message union exceeded total-query bound")
            allocations += 1
        for marked in range(space + 1):
            for queries in range(6):
                exact = grover_success(space, marked, queries)
                require(0 <= exact <= min(Fraction(1), Fraction((2 * queries + 1) ** 2 * marked, space)), "Grover envelope failed")
                quantum += 1
    return {"common_domain_exact_panels": common, "cross_key_message_allocations": allocations,
            "exact_Grover_panels": quantum, "general_quantum_search_optimality_proved_here": False}


def symmetric_panels():
    space = 1 << 256
    result = []
    for target_exponent in (0, 20, 40):
        targets = 1 << target_exponent
        for query_exponent in (0, 32, 64, 96, 128):
            queries = 1 << query_exponent
            lower, upper = common_mapping_bounds(space, queries, targets)
            result.append({"targets": targets, "tested_candidates_or_quantum_queries": queries,
                "common_mapping": {"objectives": ["key-generation seed across keys", "messages under one fixed public key"],
                    "classical_iid_targets_exact_formula": "1-(1-q/2^256)^U; q distinct tested candidates",
                    "classical_lower": fraction_record(lower), "classical_upper": fraction_record(upper),
                    "Grover_success_envelope_with_at_most_U_marked_points": fraction_record(min(Fraction(1), Fraction((2*queries+1)**2*targets, space))),
                    "coherent_target_membership_and_U_entry_storage_not_free": True},
                "different_public_key_message_predicates": {"classical_total_predicate_query_upper": fraction_record(min(Fraction(1), Fraction(queries, space))),
                    "Grover_uniform_pair_domain_envelope": fraction_record(min(Fraction(1), Fraction((2*queries+1)**2, space))),
                    "search_domain_size": targets * space, "marked_pair_count": targets,
                    "automatic_division_of_query_cost_by_target_count": False},
                "search_bits": 256, "query_cost_is_gate_depth_or_physical_memory": False,
                "global_KEM_security_claimed": False})
    return result


def wire_sizes():
    profiles = {"R1": (6, 13, 13, 5), "ML-KEM-1024": (4, 12, 11, 5)}
    result = {}
    for name, (rank, public_bits, du, dv) in profiles.items():
        public = rank * 256 * public_bits // 8 + 32
        private = rank * 256 * public_bits // 8 + public + 64
        ciphertext = (rank * 256 * du + 256 * dv) // 8
        result[name] = {"encapsulation_key_bytes": public, "expanded_decapsulation_key_bytes": private,
                        "ciphertext_bytes": ciphertext, "shared_secret_bytes": 32,
                        "one_key_and_ciphertext_bytes": public + ciphertext}
    result["difference_R1_minus_reference"] = {key: result["R1"][key] - result["ML-KEM-1024"][key]
                                               for key in result["R1"]}
    result["key_and_ciphertext_ratio"] = fraction_record(Fraction(result["R1"]["one_key_and_ciphertext_bytes"],
                                                                 result["ML-KEM-1024"]["one_key_and_ciphertext_bytes"]))
    return result


def memory_diagnostic(family, log2_cost, caps=(40, 60, 80)):
    mem, vectors = log2_cost.get("mem"), log2_cost.get("N")
    result = {"log2_native_mem": mem, "log2_native_vector_count_N": vectors,
              "N_is_not_RAM": True, "physical_peak_RAM_validated": False,
              "constrained_RAM_optimum_recomputed": False}
    if family == "dual" and type(mem) in (int, float) and math.isfinite(mem):
        result.update(native_mem_unit="stored elements modulo q in the pinned dual solver",
                      dense_u16_storage_convention_bytes_per_element=2,
                      log2_dense_u16_storage_bytes=mem + 1,
                      inside_declared_storage_cap={str(cap): mem + 1 <= cap for cap in caps},
                      interpretation="storage sensitivity only; reduction overhead and all physical peak resources are not proved")
    else:
        result.update(native_mem_unit="unreported or not validated for this family",
                      inside_declared_storage_cap=None)
    return result


def bounded_memory_counterexample():
    # Filtering only each algorithm's unconstrained optimum would discard A,
    # although it has a feasible slower point which beats B under the cap.
    a = [(1, 100), (3, 1)]
    b = [(4, 1)]
    cap = 1
    unconstrained = {"A": min(a), "B": min(b)}
    constrained = {"A": min(p for p in a if p[1] <= cap), "B": min(p for p in b if p[1] <= cap)}
    require(unconstrained["A"][1] > cap and constrained["A"][0] < constrained["B"][0], "memory counterexample disappeared")
    return {"points_time_memory": {"A": [list(p) for p in a], "B": [list(p) for p in b]}, "cap": cap,
            "unconstrained": {k: list(p) for k, p in unconstrained.items()},
            "constrained": {k: list(p) for k, p in constrained.items()},
            "filtering_unconstrained_optima_is_not_reoptimization": True}
