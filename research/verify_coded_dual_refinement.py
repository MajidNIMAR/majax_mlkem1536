"""Integrity and independent reconstruction of local-neighborhood checks.

No Sage recomputation; the persisted numerical cross-check is bound to each
retained point. Local stability is conditional on the unchanged attack model.
"""

import hashlib
import itertools
import json
import math
from pathlib import Path

from coded_dual_model import LN2, logadd, validate
from verify_coded_dual_results import verify as verify_parent

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "results/j2/run-009"
AXES = ("samples", "nenu", "nfft", "kfft")
TOLERANCE = 1e-10


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def point(row):
    return tuple(row["inputs"][axis] for axis in AXES)


def neighborhood(center, steps, paired):
    result = set()
    for offsets in itertools.product((-1, 0, 1), repeat=4):
        nonzero = sum(v != 0 for v in offsets)
        if nonzero == 1 or paired and nonzero == 2:
            result.add(tuple(c + v * step for c, v, step in zip(center, offsets, steps)))
    return result


def valid(n, p):
    m, ne, nf, kf = p
    return 1 <= m <= n and 0 <= ne <= 96 and 8 <= nf <= 256 and 1 <= kf < nf and ne + nf < n and m + n - ne - nf >= 200


def verify():
    verify_parent()
    for manifest in ("provenance.json", "numeric-provenance.json"):
        provenance = read(RUN / manifest)
        for group, base in (("input_sha256", ROOT), ("output_sha256", RUN)):
            for name, expected in provenance[group].items():
                path = (base / name).resolve()
                if not path.is_relative_to(base) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                    raise ValueError(f"refinement checksum mismatch: {name}")
    old_rows = [json.loads(s) for s in (ROOT / "results/j2/run-008/evaluations.jsonl").read_text(encoding="utf-8").splitlines()]
    new_rows = [json.loads(s) for s in (RUN / "evaluations.jsonl").read_text(encoding="utf-8").splitlines()]
    rows = old_rows + new_rows
    study = read(RUN / "study.json")
    if [r["index"] for r in rows] != list(range(len(rows))) or study["evaluations_total"] != len(rows):
        raise ValueError("refinement index/count mismatch")
    if study["inherited_evaluations"] != len(old_rows) or study["evaluations_new"] != len(new_rows):
        raise ValueError("inherited/new count mismatch")
    if study["tolerance_log2"] != TOLERANCE or not study["model_unchanged"] or study["profile_selected"] or study["j2_closed"]:
        raise ValueError("refinement scope mismatch")
    statuses = {s: sum(r["status"] == s for r in new_rows) for s in sorted({r["status"] for r in new_rows})}
    if statuses != study["new_statuses"]:
        raise ValueError("refinement status mismatch")
    for r in new_rows:
        p = r["inputs"]
        validate(*(p[k] for k in ("n", "degree", "q", "eta", "samples", "nenu", "nfft", "kfft")))
        if not valid(p["n"], point(r)):
            raise ValueError("out-of-domain evaluation")
        if r["status"] != "conditional_model_cost":
            if r["status"] not in ("zero_guess_target_unreachable_within_2^100", "no_feasible_beta_within_cap"):
                raise ValueError("unresolved search evaluation")
            continue
        if (r["log2_epsilon"] > math.log2(0.05) + 1e-9 or r["zero_guess_success"] < 0.6 - 1e-10
                or not r["beta_predecessor_fails"] or not r["beta_coarse_monotonicity"] or r["beta_hits_cap"]):
            raise ValueError("model/BKZ diagnostic mismatch")
        total = logadd(r["log2_sample_cost"] * LN2, (r["log2_repetitions"] + r["log2_decode_all"]) * LN2,
                       (r["log2_repetitions"] + r["log2_fft"]) * LN2) / LN2
        if abs(total - r["log2_rop"]) > 1e-9:
            raise ValueError("refined cost sum mismatch")
    for trail in study["trajectories"]:
        indices = trail["trajectory"]
        if not indices or indices[0] != trail["start_index"] or indices[-1] != trail["end_index"]:
            raise ValueError("trajectory endpoints mismatch")
        if len(indices) != trail["sweeps"] or trail["status"] != "stable_in_declared_neighborhood":
            raise ValueError("trajectory stop mismatch")
        for before, after in zip(indices, indices[1:]):
            a, b = rows[before], rows[after]
            if point(b) not in neighborhood(point(a), trail["steps"], trail["two_coordinate_moves"]):
                raise ValueError("invalid trajectory move")
            if b["log2_rop"] >= a["log2_rop"] - TOLERANCE:
                raise ValueError("nondecreasing trajectory")
        final = rows[trail["end_index"]]
        expected = {p for p in neighborhood(point(final), trail["steps"], trail["two_coordinate_moves"]) if valid(trail["n"], p)}
        actual = [rows[i] for i in trail["terminal_neighbors"]]
        if {point(r) for r in actual} != expected or len(actual) != len(expected):
            raise ValueError("terminal-neighborhood coverage mismatch")
        for r in actual:
            if r["inputs"]["n"] != trail["n"] or r["inputs"]["mlwe"] != trail["mlwe"]:
                raise ValueError("neighbor belongs to another panel")
            if r["status"] == "conditional_model_cost" and r["log2_rop"] < final["log2_rop"] - TOLERANCE:
                raise ValueError("improving terminal neighbor")
    parent_minima = read(ROOT / "results/j2/run-008/study.json")["minima"]
    if len(study["minima"]) != 4 or len(study["stability_certificates"]) != 4:
        raise ValueError("four refined panels required")
    for winner, certificate, old in zip(study["minima"], study["stability_certificates"], parent_minima):
        if winner != rows[winner["index"]] or certificate["winner_index"] != winner["index"]:
            raise ValueError("refined point binding mismatch")
        n, mlwe = winner["inputs"]["n"], winner["inputs"]["mlwe"]
        panel = [r for r in rows if r["inputs"]["n"] == n and r["inputs"]["mlwe"] == mlwe and r["status"] == "conditional_model_cost"]
        if winner["log2_rop"] > min(r["log2_rop"] for r in panel) + TOLERANCE:
            raise ValueError("better explored point omitted")
        expected = neighborhood(point(winner), (1, 1, 1, 1), True)
        actual = [rows[i] for i in certificate["neighbor_indices"]]
        invalid = {tuple(p) for p in certificate["invalid_neighbors"]}
        if {point(r) for r in actual} != {p for p in expected if valid(n, p)} or invalid != {p for p in expected if not valid(n, p)}:
            raise ValueError("unit/pair stability certificate incomplete")
        if abs(certificate["improvement_log2_from_parent"] - old["log2_rop"] + winner["log2_rop"]) > 1e-9:
            raise ValueError("parent improvement mismatch")
        if any(r["status"] == "conditional_model_cost" and r["log2_rop"] < winner["log2_rop"] - TOLERANCE for r in actual):
            raise ValueError("winner not locally stable")
    numeric = read(RUN / "numeric-verification.json")["results"]
    if len(numeric) != 4:
        raise ValueError("four numeric replays required")
    for r, winner in zip(numeric, study["minima"]):
        if not r["passed"] or r["index"] != winner["index"] or r["inputs"] != winner["inputs"]:
            raise ValueError("numeric replay binding mismatch")
        if any(abs(r[k]) >= 1e-8 for k in ("delta_log2_rop", "delta_log2_repetitions", "delta_log2_threshold")):
            raise ValueError("numeric replay tolerance exceeded")
    return dict(snapshot="run-009", inherited=len(old_rows), new=len(new_rows), statuses=statuses,
                verified_trajectories=len(study["trajectories"]), locally_stable_points=4,
                unit_and_two_coordinate_neighbors_per_point=32, high_precision_replays=4,
                global_optimality_claimed=False, profile_selected=False, j2_closed=False)


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
