"""Continue run-008 without altering its model or preserved inputs.

Four step scales end with every valid unit move on one or two coordinates.
Stability is local to this finite neighborhood and the explicit search box.
"""

import argparse
from datetime import datetime, timezone
import itertools
import json
from pathlib import Path
import platform
import sys
import time

from coded_dual_model import CodedDualModel
from run_coded_dual import ROOT, read, sha, sources, write
from verify_coded_dual_results import verify as verify_parent

TOLERANCE = 1e-10
AXES = ("samples", "nenu", "nfft", "kfft")
STAGES = (((16, 4, 8, 2), False), ((8, 2, 4, 1), False),
          ((4, 1, 2, 1), False), ((1, 1, 1, 1), True))


def coordinates(row):
    return tuple(row["inputs"][axis] for axis in AXES)


def neighbors(point, steps, pairs=False):
    if len(point) != 4 or len(steps) != 4 or any(s < 1 or not isinstance(s, int) for s in steps):
        raise ValueError("four coordinates and positive integer steps required")
    moves = []
    for size in (1, 2) if pairs else (1,):
        for axes in itertools.combinations(range(4), size):
            for signs in itertools.product((-1, 1), repeat=size):
                changed = list(point)
                for axis, sign in zip(axes, signs):
                    changed[axis] += steps[axis] * sign
                moves.append(tuple(changed))
    return sorted(moves)


def in_domain(n, point):
    m, ne, nf, kf = point
    return (1 <= m <= n and 0 <= ne <= 96 and 8 <= nf <= 256
            and 1 <= kf < nf and ne + nf < n and m + n - ne - nf >= 200)


def descend(start, evaluate, valid, steps, pairs=False, max_sweeps=1000):
    current = start
    trajectory = [current["index"]]
    for sweep in range(max_sweeps):
        candidate_rows = [evaluate(p) for p in neighbors(coordinates(current), steps, pairs) if valid(p)]
        if any(r["status"] not in ("conditional_model_cost", "zero_guess_target_unreachable_within_2^100",
                                   "no_feasible_beta_within_cap") for r in candidate_rows):
            raise ArithmeticError("unresolved neighbor; local stability cannot be claimed")
        costs = [r for r in candidate_rows if r["status"] == "conditional_model_cost"]
        best = min(costs + [current], key=lambda r: (r["log2_rop"], coordinates(r)))
        if best["log2_rop"] >= current["log2_rop"] - TOLERANCE:
            return current, dict(start_index=start["index"], end_index=current["index"],
                                 steps=list(steps), two_coordinate_moves=pairs, sweeps=sweep + 1,
                                 trajectory=trajectory, terminal_neighbors=[r["index"] for r in candidate_rows],
                                 status="stable_in_declared_neighborhood")
        current = best
        trajectory.append(current["index"])
    raise RuntimeError("search safety cap reached; no stability result may be claimed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output == ROOT or not output.is_relative_to(ROOT) or output.exists():
        raise ValueError("new output directory below NIST required")
    verify_parent()
    parent = read("results/j2/run-008/study.json")
    inherited = [json.loads(line) for line in (ROOT / "results/j2/run-008/evaluations.jsonl").read_text(encoding="utf-8").splitlines()]
    library, _ = sources()
    sys.path.insert(0, str(library))
    from sage.all import RealField
    from sage.version import version as sage_version
    from estimator.reduction import RC
    model = CodedDualModel(RC.MATZOV.__class__(nn="list_decoding-classical"), RealField(2048))
    all_rows = list(inherited)
    cache = {(r["inputs"]["n"], r["inputs"]["mlwe"], coordinates(r)): r for r in inherited}
    new_rows, traces, minima, certificates = [], [], [], []
    output.mkdir(parents=True)
    started = time.monotonic()
    with (output / "evaluations.jsonl").open("x", encoding="utf-8", newline="\n") as stream:
        for initial, diagnostic in zip(parent["minima"], parent["cap_diagnostics"]):
            fixed = initial["inputs"]
            n, mlwe = fixed["n"], fixed["mlwe"]

            def evaluate(point):
                key = n, mlwe, point
                if key in cache:
                    return cache[key]
                job = {k: v for k, v in fixed.items() if k not in AXES} | dict(zip(AXES, point))
                row = model.evaluate(**job)
                row.update(index=len(all_rows), phase="multiscale_refinement_run009")
                cache[key] = row
                all_rows.append(row)
                new_rows.append(row)
                stream.write(json.dumps(row, allow_nan=False) + "\n")
                stream.flush()
                if len(new_rows) % 100 == 0:
                    print(f"new evaluations preserved: {len(new_rows)}", flush=True)
                return row

            seed_indices = sorted({initial["index"]} | {t["best_index"] for t in diagnostic["refinement_trails"]})
            for seed_index in seed_indices:
                current = inherited[seed_index]
                for steps, pairs in STAGES:
                    current, trace = descend(current, evaluate, lambda p: in_domain(n, p), steps, pairs)
                    trace.update(n=n, mlwe=mlwe, seed_index=seed_index)
                    traces.append(trace)
            panel = [r for r in all_rows if r["inputs"]["n"] == n and r["inputs"]["mlwe"] == mlwe
                     and r["status"] == "conditional_model_cost"]
            winner = min(panel, key=lambda r: r["log2_rop"])
            winner, trace = descend(winner, evaluate, lambda p: in_domain(n, p), (1, 1, 1, 1), True)
            trace.update(n=n, mlwe=mlwe, seed_index=None, role="final_selection_audit")
            traces.append(trace)
            minima.append(winner)
            certificate = dict(winner_index=winner["index"], neighbor_indices=trace["terminal_neighbors"],
                               invalid_neighbors=[list(p) for p in neighbors(coordinates(winner), (1, 1, 1, 1), True) if not in_domain(n, p)],
                               improvement_log2_from_parent=initial["log2_rop"] - winner["log2_rop"],
                               domain_boundary=any((coordinates(winner)[0] in (1, n), coordinates(winner)[1] in (0, 96),
                                                    coordinates(winner)[2] in (8, 256), coordinates(winner)[3] in (1, coordinates(winner)[2] - 1))))
            certificates.append(certificate)
            print(f"stable locally n={n} mlwe={mlwe}: {winner['log2_rop']:.12f}, point={coordinates(winner)}", flush=True)
    statuses = {s: sum(r["status"] == s for r in new_rows) for s in sorted({r["status"] for r in new_rows})}
    study = dict(parent_snapshot="run-008", inherited_evaluations=len(inherited), evaluations_new=len(new_rows),
                 evaluations_total=len(all_rows), new_statuses=statuses, minima=minima,
                 stability_certificates=certificates, trajectories=traces, tolerance_log2=TOLERANCE,
                 domain=dict(samples="1..n", nenu="0..96", nfft="8..256", kfft="1..nfft-1", constraints="nenu+nfft<n; lattice dimension>=200"),
                 model_unchanged=True, profile_selected=False, j2_closed=False,
                 limits=parent["limits"] + ["local stability only for unit moves on one or two coordinates within the declared domain",
                                            "equal-cost plateaus and larger or three-coordinate moves can conceal better points"])
    write(output / "study.json", study)
    inputs = ["research/refine_coded_dual.py", "research/test_coded_dual_refinement.py",
              "research/verify_coded_dual_refinement.py", "research/coded_dual_model.py",
              "research/run_coded_dual.py", "research/verify_coded_dual_numeric.py", "scripts/coded-dual-refine.sh",
              "results/j2/run-008/study.json", "results/j2/run-008/evaluations.jsonl", "results/j2/run-008/provenance.json",
              "results/j2/run-008/numeric-provenance.json"]
    write(output / "provenance.json", dict(created_utc=datetime.now(timezone.utc).isoformat(), python=platform.python_version(),
                                            sage=sage_version, seconds=time.monotonic() - started,
                                            input_sha256={name: sha(ROOT / name) for name in inputs},
                                            output_sha256={name: sha(output / name) for name in ("study.json", "evaluations.jsonl")}))
    print(json.dumps(dict(new=len(new_rows), total=len(all_rows), statuses=statuses, trajectories=len(traces))), flush=True)


if __name__ == "__main__":
    main()
