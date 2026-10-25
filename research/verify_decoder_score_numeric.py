"""160-decimal numerical cross-checks of selected CBD biases and covariances.

No project arithmetic import; evaluates the defining characteristic formula
with mpmath from the pinned local runtime. Not a proof of full attack models.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def save(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    args = parser.parse_args()
    run = args.run.resolve()
    if not run.is_relative_to(ROOT):
        raise ValueError("run must stay below NIST")
    import mpmath as mp
    mp.mp.dps = 160

    def log_phi(r, q, eta):
        return 2*eta*mp.fsum(mp.log(mp.cos(mp.pi*((x+q//2)%q-q//2)/q)) for x in r)

    rows = [json.loads(s) for s in (run/"residuals.jsonl").read_text(encoding="utf-8").splitlines()]
    banks = json.loads((run/"score-banks.json").read_text(encoding="utf-8"))
    summaries = json.loads((run/"study.json").read_text(encoding="utf-8"))["results"]
    checks = []
    for summary, bank in zip(summaries, banks):
        values = [r for r in rows if r["experiment"] == summary["experiment"]]
        q, eta = summary["q"], summary["eta"]
        for index in (0,1,2,3,63,127,191,255):
            observed = values[index]
            computed = float(log_phi(observed["residual"], q, eta)/mp.log(2))
            checks.append(dict(kind="residual_bias", experiment=summary["experiment"], index=index,
                               delta_log2=computed-observed["log2_CBD"]))
        for i,j in ((0,0),(0,1),(0,31),(15,31)):
            a,b = values[i]["residual"], values[j]["residual"]
            cross = (mp.exp(log_phi([x+y for x,y in zip(a,b)], q, eta))
                     + mp.exp(log_phi([x-y for x,y in zip(a,b)], q, eta)))/2
            value = cross-mp.exp(log_phi(a,q,eta)+log_phi(b,q,eta))
            expected = next(r for r in bank["upper_covariances"] if r["i"]==i and r["j"]==j)
            sign = int(mp.sign(value))
            delta = 0 if not sign else float(mp.log(abs(value),2))-expected["log2_abs"]
            checks.append(dict(kind="score_covariance", experiment=summary["experiment"], i=i,j=j,
                               sign_matched=sign==expected["sign"], delta_log2=delta))
    controls = json.loads((run/"equal-norm-controls.json").read_text(encoding="utf-8"))
    for i,row in enumerate(controls):
        value = float(log_phi(row["residual"],row["q"],row["eta"])/mp.log(2))
        checks.append(dict(kind="equal_norm_bias", index=i, delta_log2=value-row["log2_CBD"]))
    passed = all(abs(c["delta_log2"]) < 1e-8 and c.get("sign_matched",True) for c in checks)
    output = run/"numeric-verification.json"
    save(output, dict(mpmath_decimal_digits=160, checks=checks, all_passed=passed,
                      maximum_absolute_log2_delta=max(abs(c["delta_log2"]) for c in checks)))
    names = ["research/verify_decoder_score_numeric.py"] + [(run/n).relative_to(ROOT).as_posix() for n in ("residuals.jsonl","score-banks.json","equal-norm-controls.json","study.json")]
    save(run/"numeric-provenance.json",dict(created_utc=datetime.now(timezone.utc).isoformat(),
                                            input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in names},
                                            output_sha256={output.name:hashlib.sha256(output.read_bytes()).hexdigest()}))
    print(json.dumps(dict(checks=len(checks),all_passed=passed,maximum_delta=max(abs(c["delta_log2"]) for c in checks))),flush=True)
    if not passed:
        raise ArithmeticError("high-precision decoder score mismatch")


if __name__ == "__main__":
    main()
