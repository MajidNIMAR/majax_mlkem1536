"""Standard-library integrity and internal checks of coded-dual run-008.

This checks the preserved numerical results, not a full Sage recomputation
or the correctness of the attack's heuristic probability model.
"""

import hashlib
import json
import math
from pathlib import Path

from coded_dual_model import LN2, logadd, validate, zero_success, zero_weights

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "results/j2/run-008"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def verify():
    for manifest in ("provenance.json", "numeric-provenance.json"):
        provenance = read(RUN / manifest)
        for group, base in (("input_sha256", ROOT), ("output_sha256", RUN)):
            for name, expected in provenance[group].items():
                path = (base / name).resolve()
                if not path.is_relative_to(base) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                    raise ValueError(f"coded-dual checksum mismatch: {name}")
    study = read(RUN / "study.json")
    calibration = read(RUN / "calibration.json")
    if len(calibration) != 6 or not all(r["passed"] for r in calibration):
        raise ValueError("six successful published-point calibrations required")
    for r in calibration:
        if abs(r["delta_native_published"]) >= 1e-8 or abs(r["delta_adapter_native"]) >= 1e-8:
            raise ValueError("reference-point numerical tolerance exceeded")
    rows = [json.loads(line) for line in (RUN / "evaluations.jsonl").read_text(encoding="utf-8").splitlines()]
    if len(rows) != study["evaluations"] or [r["index"] for r in rows] != list(range(len(rows))):
        raise ValueError("evaluation count/index mismatch")
    counts = {s: sum(r["status"] == s for r in rows) for s in sorted({r["status"] for r in rows})}
    if counts != study["statuses"] or study["profile_selected"] or study["j2_closed"]:
        raise ValueError("study scope/status mismatch")
    for r in rows:
        p = r["inputs"]
        validate(*(p[k] for k in ("n", "degree", "q", "eta", "samples", "nenu", "nfft", "kfft")))
        if r["status"] != "conditional_model_cost":
            continue
        if not (200 <= r["beta0"] <= r["beta_cap"] == r["lattice_dimension"]):
            raise ValueError("invalid lattice/BKZ bound")
        if not r["beta_predecessor_fails"] or not r["beta_coarse_monotonicity"] or r["beta_hits_cap"]:
            raise ValueError("unresolved BKZ boundary diagnostic")
        if r["log2_epsilon"] > math.log2(0.05) + 1e-9 or r["zero_guess_success"] < 0.6 - 1e-10:
            raise ValueError("heuristic probability targets not met")
        total = logadd(r["log2_sample_cost"] * LN2,
                       (r["log2_repetitions"] + r["log2_decode_all"]) * LN2,
                       (r["log2_repetitions"] + r["log2_fft"]) * LN2) / LN2
        if abs(total - r["log2_rop"]) > 1e-9:
            raise ValueError("cost-component sum mismatch")
    for winner in study["minima"]:
        p = winner["inputs"]
        matching = [r for r in rows if r["inputs"]["n"] == p["n"] and r["inputs"]["mlwe"] == p["mlwe"]
                    and r["status"] == "conditional_model_cost"]
        if winner != min(matching, key=lambda r: r["log2_rop"]):
            raise ValueError("best-explored point mismatch")
        population = p["n"] if p["mlwe"] else p["nenu"] + p["nfft"]
        success = zero_success(2 ** winner["log2_repetitions"], zero_weights(population, p["nenu"], p["eta"]))
        if abs(success - winner["zero_guess_success"]) > 1e-9:
            raise ValueError("zero-subset probability replay mismatch")
        if winner["reduction_table_extrapolated"] != (winner["beta0"] > 1024 or winner["beta1"] > 1024):
            raise ValueError("reduction-table extrapolation flag mismatch")
    numeric = read(RUN / "numeric-verification.json")
    if len(numeric["results"]) != 4 or not all(r["passed"] for r in numeric["results"]):
        raise ValueError("four high-precision numerical replays required")
    for row, winner in zip(numeric["results"], study["minima"]):
        if row["index"] != winner["index"] or row["inputs"] != winner["inputs"]:
            raise ValueError("high-precision target binding mismatch")
        if any(abs(row[k]) >= 1e-8 for k in ("delta_log2_rop", "delta_log2_repetitions", "delta_log2_threshold")):
            raise ValueError("high-precision replay tolerance exceeded")
    for diagnostic, winner in zip(study["cap_diagnostics"], study["minima"]):
        limited = diagnostic["cap_1000"]
        if diagnostic["winner_index"] != winner["index"] or limited["inputs"] != winner["inputs"]:
            raise ValueError("cap diagnostic binding mismatch")
        if winner["beta0"] > 1000 and limited["status"] != "no_feasible_beta_within_cap":
            raise ValueError("original cap unexpectedly admissible")
    return dict(snapshot="run-008", integrity="passed", published_calibrations=6,
                preserved_evaluations=len(rows), statuses=counts, high_precision_replays=4,
                verification="integrity and numerical consistency; not full Sage recomputation",
                applicability="conditional GV/score/zero-guess heuristics", profile_selected=False, j2_closed=False)


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
