"""Historical Kyber Core-SVP comparison, with checked scalar acceleration."""

from functools import lru_cache
import importlib
import math
import random
import sys
import time

from upstream_tools import ensure_tools


def scalar_first_length(q: int, nq: int, n1: int, beta: int) -> float:
    # Sum of the positive arithmetic progression in the randomized GSA shape.
    # The original builds a whole list to return its first entry. Keep its
    # volume equation, cap at dimension, and solve the triangular inequality.
    delta = ((math.pi*beta)**(1/beta)*beta/(2*math.pi*math.e))**(1/(2*beta-2))
    step = 2*math.log(delta)
    volume = nq*math.log(q)
    length = min(nq+n1, int((math.sqrt(1+8*volume/step)-1)/2))
    while length < nq+n1 and step*(length+1)*(length+2)/2 <= volume:
        length += 1
    while step*length*(length+1)/2 > volume:
        length -= 1
    return math.exp(step*length+(volume-step*length*(length+1)/2)/length)


def checked_attack_module():
    sys.path.insert(0, str(ensure_tools()))
    attack = importlib.import_module("MLWE_security")
    original = importlib.import_module("model_BKZ").BKZ_first_length
    generator = random.Random(1536)  # Public synthetic validation grid only.
    maximum_error = 0.0
    for _ in range(180):
        q = generator.choice((3329, 7681))
        nq = generator.choice((512, 768, 1024, 1536))
        n1 = generator.randint(50, 1792)
        beta = generator.randint(50, nq+n1-1)
        expected = original(q, nq, n1, beta)
        actual = scalar_first_length(q, nq, n1, beta)
        relative_error = abs(actual/expected-1)
        maximum_error = max(maximum_error, relative_error)
        if relative_error > 1e-10:
            raise ArithmeticError("scalar BKZ acceleration disagrees with upstream")
    attack.BKZ_first_length = lru_cache(maxsize=50000)(scalar_first_length)
    attack.BKZ_last_block_length = lru_cache(maxsize=50000)(attack.BKZ_last_block_length)
    return attack, {"cases": 180, "max_relative_error": maximum_error,
                    "tolerance": 1e-10, "upstream_sample_step": attack.STEPS_m}


def analyze_attacks(scenarios: list[dict]) -> dict:
    attack, validation = checked_attack_module()
    results = []
    for scenario in scenarios:
        parameters = scenario["parameters"]
        n, k, q, eta = (parameters[key] for key in ("n", "k", "q", "eta1"))
        rows = []
        for family, function in (("primal", attack.LWE_primal_cost),
                                 ("dual", attack.LWE_dual_cost)):
            for name, svp in (("classical", attack.svp_classical),
                              ("quantum", attack.svp_quantum),
                              ("optimistic_quantum", attack.svp_plausible)):
                started = time.perf_counter()
                samples, beta, cost = attack.MLWE_optimize_attack(
                    q, n*k, n*(k+1), math.sqrt(eta/2), cost_attack=function,
                    cost_svp=svp, verbose=False)
                # Check the reported point in the original unaccelerated
                # implementation as well as checking shapes on a synthetic grid.
                accelerated_first = attack.BKZ_first_length
                attack.BKZ_first_length = importlib.import_module("model_BKZ").BKZ_first_length
                try:
                    original_cost = function(q, n*k, samples, math.sqrt(eta/2), beta, svp)
                finally:
                    attack.BKZ_first_length = accelerated_first
                if abs(original_cost-cost) > 1e-7:
                    raise ArithmeticError("reported optimum differs from original attack model")
                rows.append({"family": family, "cost_model": name,
                             "samples": samples, "beta": beta,
                             "log2_core_svp_cost": cost,
                             "original_cost_recheck": original_cost,
                             "elapsed_seconds": time.perf_counter()-started})
        results.append({"id": scenario["id"], "parameters": parameters,
                        "lwe_dimension": n*k, "max_samples": n*(k+1),
                        "sigma": math.sqrt(eta/2), "attacks": rows})
    return {"scope": "historical primal/dual Core-SVP heuristic; not total KEM security",
            "source": "pq-crystals/security-estimates@75c26949a902ca297b181375bfb7cfaf22cce784",
            "scalar_acceleration_validation": validation,
            "cost_log2_per_beta": {"classical": math.log2(math.sqrt(3/2)),
                                   "quantum": math.log2(math.sqrt(13/9)),
                                   "optimistic_quantum": math.log2(math.sqrt(4/3))},
            "missing": ["modern primal and dual hybrid attacks", "algebraic/module-specific attacks",
                        "failure-oracle attacks", "complete CCA reduction and symmetric limits",
                        "side channels and implementation analysis"], "results": results}
