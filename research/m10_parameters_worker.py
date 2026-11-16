"""One frozen finite-sample estimator job, executed only under pinned Sage."""
import argparse
import contextlib
import hashlib
import io
import json
import platform
from pathlib import Path
import sys
import time
import traceback


def execute(job, estimator):
    from sage.all import log
    from sage.version import version as sage_version
    from cost_serialization import log2_record
    sys.path.insert(0, str(estimator))
    from estimator import LWE, ND
    from estimator.reduction import RC
    from sieve_models import bcss23_model
    params = LWE.Parameters(n=job["dimension"], q=job["q"],
                            Xs=ND.CenteredBinomial(job["eta"]), Xe=ND.CenteredBinomial(job["eta"]),
                            m=job["samples"], tag=job["profile"])
    model = RC.MATZOV if job["cost_model"] == "MATZOV-classical" else bcss23_model()
    kwargs = {"red_cost_model": model}
    family = job["family"]
    if family in ("usvp", "bdd", "primal_hybrid_mitm"):
        kwargs["red_shape_model"] = "gsa"
    if family == "primal_hybrid_mitm":
        # This pinned implementation hard-codes amplify(0.99, probability)
        # in PrimalHybrid.cost; it has no success_probability keyword there.
        kwargs.update(mitm=True, babai=False)
    if family == "dual":
        kwargs["success_probability"] = .99
    functions = {"usvp": LWE.primal_usvp, "bdd": LWE.primal_bdd,
                 "primal_hybrid_mitm": LWE.primal_hybrid, "dual": LWE.dual,
                 "dual_hybrid_matzov": LWE.dual_hybrid}
    messages = io.StringIO()
    started = time.monotonic()
    with contextlib.redirect_stdout(messages), contextlib.redirect_stderr(messages):
        cost = functions[family](params, **kwargs)
    return {"job": job, "status": "returned", "cost": {str(k): str(v) for k, v in cost.items()},
            "log2_cost": {key: log2_record(cost[key], log) for key in
                          ("rop", "red", "svp", "guess", "mem", "N", "prob", "repetitions") if key in cost},
            "normalized_parameters": repr(params.normalize()), "parameters": repr(params),
            "sage": sage_version, "python": platform.python_version(), "estimator_messages": messages.getvalue(),
            "calculation_wall_seconds": time.monotonic() - started,
            "success_contract": job["success_contract"], "cost_is_global_security_lower_bound": False,
            "reported_memory_unit": "dual mem is solver storage in elements mod q; MATZOV N is vector count, not RAM",
            "worker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--estimator", required=True, type=Path)
    args = parser.parse_args()
    job = json.loads(args.input.read_text())
    try:
        result = execute(job, args.estimator)
    except Exception as error:
        result = {"job": job, "status": "exception", "error_type": type(error).__name__,
                  "error": str(error), "traceback": traceback.format_exc(),
                  "worker_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, allow_nan=False)
        stream.write("\n")
