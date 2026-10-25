"""Re-evaluate best-explored points using the author's functions at 2048 bits.

The BKZ upper bound is replaced explicitly; lower incomplete gamma and erfc
are evaluated with mpmath at 160 decimal digits to avoid cancellations.
This is a numerical cross-check, not independent cryptanalysis of the model.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

from run_coded_dual import ROOT, original_functions, sources, write


def replay(run, output):
    library, source = sources()
    sys.path.insert(0, str(library))
    import mpmath as mp
    from sage.all import RealField
    from estimator.reduction import RC
    mp.mp.dps = 160
    real = RealField(2048)
    reduction = RC.MATZOV.__class__(nn="list_decoding-classical")

    def number(value):
        return mp.mpf(str(value.n(digits=170))) if hasattr(value, "n") else mp.mpf(value)

    def integral(alpha, q, beta, distance):
        s = number(beta) / 2
        c = number(alpha) * (mp.pi * number(distance) / number(q)) ** 2
        result = s * mp.gammainc(s, 0, c) / c ** s
        return real(str(result))

    def log_survival(T, N):
        return real(str(mp.log(mp.erfc(number(T) / mp.sqrt(number(N))) / 2, 2)))

    study = json.loads((run / "study.json").read_text(encoding="utf-8"))
    results = []
    for saved in study["minima"]:
        p = saved["inputs"]
        dimension = p["samples"] + p["n"] - p["nenu"] - p["nfft"]
        functions = original_functions(source, real, reduction, beta_cap=dimension)
        functions["weighted_threshold_integral"] = integral
        functions["survival_normal"] = log_survival
        native = functions["complexity"](p["eta"], p["q"], p["samples"], p["nenu"],
                                           p["n"] - p["nenu"] - p["nfft"], p["nfft"], p["kfft"],
                                           reduction, real("0.05"), real("0.6"),
                                           dict(experimental_Clsc=False, ratio_GV=real(1)), ret_dict=True, mlwe=p["mlwe"])
        cost = float(native["complexity"].log(2))
        row = dict(index=saved["index"], inputs=p, native_beta0=int(native["beta0"]), native_beta1=int(native["beta1"]),
                   native_log2_rop=cost, delta_log2_rop=cost - saved["log2_rop"],
                   delta_log2_repetitions=float(real(native["R"]).log(2)) - saved["log2_repetitions"],
                   delta_log2_threshold=float(native["treshold"].log(2) - native["N"].log(2)) - saved["log2_relative_threshold"])
        row["passed"] = (abs(row["delta_log2_rop"]) < 1e-8 and abs(row["delta_log2_repetitions"]) < 1e-8
                         and abs(row["delta_log2_threshold"]) < 1e-8
                         and row["native_beta0"] == saved["beta0"] and row["native_beta1"] == saved["beta1"])
        results.append(row)
        print(json.dumps(row), flush=True)
    write(output, dict(precision=dict(sage_bits=2048, mpmath_decimal_digits=160), results=results,
                       limitations="numerical cross-check of the same conditional model; no attack-model proof"))
    inputs = ["research/verify_coded_dual_numeric.py", "research/run_coded_dual.py",
              "references/coded-dual-audit/utilitaries.py.txt", (run / "study.json").relative_to(ROOT).as_posix()]
    provenance = dict(created_utc=datetime.now(timezone.utc).isoformat(),
                      input_sha256={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in inputs},
                      output_sha256={output.name: hashlib.sha256(output.read_bytes()).hexdigest()})
    write(output.with_name("numeric-provenance.json"), provenance)
    if not all(r["passed"] for r in results):
        raise ArithmeticError("high-precision numeric replay mismatch")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run, output = args.run.resolve(), args.output.resolve()
    if not run.is_relative_to(ROOT) or not output.is_relative_to(ROOT) or output.parent != run:
        raise ValueError("run and new verification output must stay together below NIST")
    replay(run, output)
