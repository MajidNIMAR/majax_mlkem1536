"""One explicit attack/model/instance in a dedicated Sage process."""

import argparse
import contextlib
import io
import json
from pathlib import Path
import sys
import time
import traceback


def estimate(job):
    from sage.all import log, oo
    from modern_tools import sources

    cached = sources()
    if job["tool"] == "community":
        sys.path.insert(0, str(cached["lattice-estimator"]))
        from estimator import LWE, ND
        from estimator.reduction import RC
        from estimator import lwe
    else:
        sys.path.insert(0, str(cached["mlwe-hybrids"] / "PrimalHybrid"))
        from lattice_estimator.estimator import LWE, ND
        from lattice_estimator.estimator.reduction import RC
        import lwe_rot_primal

    p = job["parameters"]
    distribution = ND.CenteredBinomial(p["eta"])
    params = LWE.Parameters(n=256*p["k"], q=p["q"], Xs=distribution,
                            Xe=distribution, m=job["samples"], tag=job["scenario"])
    if job["cost_model"] == "BCSS23-quantum-asymptotic":
        from sieve_models import bcss23_model
        model = bcss23_model()
    else:
        model = {"MATZOV-classical": RC.MATZOV,
                 "ADPS16-classical": RC.ADPS16}[job["cost_model"]]
    captured = io.StringIO()
    with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
        if job["tool"] == "ring-2026":
            function = lwe_rot_primal.rot_primal_hybrid
            cost = function(params, poly_degree=256,
                            babai=job["algorithm"] == "rot_bdd_mitm_hybrid",
                            mitm=job["algorithm"] == "rot_bdd_mitm_hybrid",
                            mitm_heuristic="square root", red_shape_model="gsa",
                            red_cost_model=model)
        else:
            functions = {"usvp": LWE.primal_usvp, "bdd": LWE.primal_bdd,
                         "bdd_hybrid": LWE.primal_hybrid,
                         "bdd_mitm_hybrid": LWE.primal_hybrid,
                         "dual": LWE.dual, "dual_hybrid": LWE.dual_hybrid,
                         "bkw": lwe.coded_bkw, "arora-gb": lwe.arora_gb}
            kwargs = {}
            if job["algorithm"] not in ("bkw", "arora-gb"):
                kwargs["red_cost_model"] = model
            if job["algorithm"] in ("usvp", "bdd", "bdd_hybrid", "bdd_mitm_hybrid"):
                kwargs["red_shape_model"] = "gsa"
            if job["algorithm"].startswith("bdd_"):
                kwargs["babai"] = job["algorithm"] == "bdd_mitm_hybrid"
                kwargs["mitm"] = job["algorithm"] == "bdd_mitm_hybrid"
            cost = functions[job["algorithm"]](params, **kwargs)
    logs = {}
    for key in ("rop", "red", "svp", "mem", "guess", "N", "prob", "repetitions"):
        if key not in cost:
            continue
        value = cost[key]
        if value == oo:
            logs[key] = "+infinity"
        elif value == 0:
            logs[key] = "-infinity"
        else:
            logs[key] = float(log(value, 2))
    applicability = ("exploratory dense-CBD use of sparse-secret rotation estimator"
                     if job["tool"] == "ring-2026" else "heuristic LWE estimator model")
    return {"status": "ok", "applicability": applicability,
            "cost": {str(k): str(v) for k, v in cost.items()},
            "log2_cost": logs, "estimator_messages": captured.getvalue()[-2000:]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    job = json.loads(args.job)
    started = time.perf_counter()
    try:
        result = estimate(job)
    except Exception as error:
        result = {"status": "error", "error_type": type(error).__name__, "error": str(error),
                  "traceback": traceback.format_exc()[-3500:]}
    result = {"job": job, **result, "elapsed_seconds": time.perf_counter()-started}
    args.output.write_text(json.dumps(result, indent=2, allow_nan=False)+"\n", encoding="utf-8")
