"""Calibrate a coded-dual adapter, then execute a bounded GV sensitivity panel.

Run with the pinned project-local Sage runtime; ordinary verification does
not require Sage. Supplied native binaries and pickle files are never loaded.
"""

import argparse
import ast
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import sys
import time
import zipfile

from coded_dual_model import CodedDualModel

ROOT = Path(__file__).resolve().parents[1]


def read(name):
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def sources():
    manifest = read("references/coded-dual-evaluation/manifest.json")
    archive = ROOT / manifest["cache_archive"]
    if sha(archive) != manifest["sha256"]:
        raise ValueError("pinned coded-dual archive mismatch")
    destination = ROOT / manifest["cache_directory"]
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            relative = Path(*Path(member.filename).parts[1:])
            if member.is_dir() or "__pycache__" in relative.parts or relative.suffix != ".py":
                continue
            path = (destination / relative).resolve()
            if not path.is_relative_to(destination.resolve()):
                raise ValueError("unsafe source member")
            content = bundle.read(member)
            if not path.exists():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
            if path.read_bytes() != content:
                raise ValueError(f"coded-dual cached source mismatch: {relative}")
    original = destination / "OptimizeCodedDualAttack/utilitaries.py"
    if original.read_bytes() != (ROOT / "references/coded-dual-audit/utilitaries.py.txt").read_bytes():
        raise ValueError("inspected mathematical source differs from archive")
    return destination / "OptimizeCodedDualAttack/estimator", original


def original_functions(source, real_field, reduction, beta_cap=None):
    # Only the previously inspected mathematical functions are compiled.
    # Discard all upstream top-level code/imports, polar bindings and pickle I/O.
    import sage.all as sage
    allowed = {"root_Hermite", "cost_sample", "cost_FFT", "cost_decode", "compute_p0",
               "survival_normal", "weighted_threshold_integral", "find_relative_threshold_tmp",
               "find_relative_threshold", "compute_eta_max", "compute_eta", "compute_eta_rot",
               "find_min_R_lwe", "find_min_R_mlwe", "complexity"}
    tree = ast.parse(source.read_text(encoding="utf-8"))
    tree.body = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in allowed]
    if {node.name for node in tree.body} != allowed:
        raise ValueError("reference-function allowlist mismatch")
    if beta_cap is not None:
        replacements = 0
        for node in ast.walk(tree):
            if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
                    and node.value.value == 1000
                    and any(isinstance(t, ast.Name) and t.id == "beta0_sup" for t in node.targets)):
                node.value = ast.copy_location(ast.Constant(beta_cap), node.value)
                replacements += 1
        if replacements != 1:
            raise ValueError("reference BKZ-bound adaptation mismatch")
    names = {name: getattr(sage, name) for name in ("sqrt", "log", "exp", "e", "pi", "erf",
                                                  "gamma", "gamma_inc", "binomial", "floor", "cached_function")}
    names.update(RR=real_field, RC=reduction, math=math)
    exec(compile(tree, str(source), "exec"), names)
    return names


def calibration(model, functions, real_field, reduction):
    results = []
    for case in read("references/coded-dual-evaluation/calibration-cases.json"):
        code = dict(q=int(case["q"]), k=int(case["kfft"]), n=int(case["nfft"]), L_size=1,
                    mean_decoding_norm=real_field(case["avg_dlsc"]), sigma_decoding_norm=real_field(case["sdv_dlsc"]),
                    str_repr_code="published statistics only", aux_nb_decoding_randomWord=0)
        native = functions["complexity"](int(case["alpha"]), int(case["q"]), int(case["m"]),
                                           int(case["nenu"]), int(case["nlat"]), int(case["nfft"]),
                                           int(case["kfft"]), reduction, real_field("0.05"), real_field("0.6"),
                                           dict(experimental_Clsc=True, code=code), ret_dict=True, mlwe=case["mlwe"])
        adapted = model.evaluate(n=case["n"], degree=256, q=int(case["q"]), eta=int(case["alpha"]),
                                 samples=int(case["m"]), nenu=int(case["nenu"]), nfft=int(case["nfft"]),
                                 kfft=int(case["kfft"]), mlwe=case["mlwe"],
                                 experimental=(float(case["avg_dlsc"]), float(case["sdv_dlsc"])))
        native_log = float(native["complexity"].log(2))
        row = dict(reference=case, native_log2_rop=native_log, adapter=adapted,
                   native_beta0=int(native["beta0"]), native_beta1=int(native["beta1"]),
                   native_log2_repetitions=float(real_field(native["R"]).log(2)),
                   delta_native_published=native_log - float(case["complexity"]),
                   delta_adapter_native=adapted.get("log2_rop", 0) - native_log)
        row["passed"] = (abs(row["delta_native_published"]) < 1e-8
                         and abs(row["delta_adapter_native"]) < 1e-8
                         and adapted.get("beta0") == int(native["beta0"]) == int(case["beta0"])
                         and adapted.get("beta1") == int(native["beta1"]) == int(case["beta1"]))
        results.append(row)
        print(f"calibration n={case['n']} mlwe={case['mlwe']}: passed={row['passed']}, delta={row['delta_adapter_native']:.3g}", flush=True)
    return results


def panel(model, output):
    rows, cache = [], {}
    stream = (output / "evaluations.jsonl").open("x", encoding="utf-8", newline="\n")

    def evaluate(n, q, eta, mlwe, coordinates, phase):
        m, ne, nf, kf = coordinates
        key = n, q, eta, mlwe, m, ne, nf, kf
        if key in cache:
            return cache[key]
        job = dict(n=n, degree=256, q=q, eta=eta, samples=m, nenu=ne, nfft=nf, kfft=kf, mlwe=mlwe)
        try:
            row = model.evaluate(**job)
        except Exception as error:
            row = dict(inputs=job, status="error", error_type=type(error).__name__, error=str(error))
        row.update(index=len(rows), phase=phase)
        rows.append(row)
        cache[key] = row
        stream.write(json.dumps(row, allow_nan=False) + "\n")
        stream.flush()
        if len(rows) % 50 == 0:
            print(f"evaluations preserved: {len(rows)}", flush=True)
        return row

    minima, diagnostics = [], []
    for n, q, eta in ((1024, 3329, 2), (1536, 7681, 3)):
        for mlwe in (False, True):
            before = len(rows)
            for fraction in (0.65, 0.8, 0.95):
                for ne in (0, 16, 32, 48):
                    for nf in (64, 96, 128):
                        for kf in (8, 12, 16, 20):
                            evaluate(n, q, eta, mlwe, (round(n * fraction), ne, nf, kf), "coarse")
            valid = [r for r in rows[before:] if r["status"] == "conditional_model_cost"]
            if not valid:
                raise ArithmeticError("no feasible model point in coarse panel")
            # Add the authors' published dimension splits, rescaled for rank
            # six, but evaluate them with the same GV assumptions as the grid.
            for m, ne, nf, kf in ((814, 28, 113, 16), (782, 33, 111, 16)):
                scale = n / 1024
                candidate = evaluate(n, q, eta, mlwe, tuple(round(v * scale) for v in (m, ne, nf, kf)), "published_split_seed_GV")
                if candidate["status"] == "conditional_model_cost":
                    valid.append(candidate)
            seeds = sorted(valid, key=lambda r: r["log2_rop"])[:3]
            trails = []
            for seed in seeds:
                winner = seed
                # Bounded coordinate descent from three starting points.
                for sweep in range(12):
                    improved = False
                    for axis, step in enumerate((16, 4, 8, 2)):
                        v = winner["inputs"]
                        origin = (v["samples"], v["nenu"], v["nfft"], v["kfft"])
                        for direction in (-1, 1):
                            point = list(origin)
                            point[axis] += direction * step
                            m, ne, nf, kf = point
                            if not (1 <= m <= n and 0 <= ne <= 96 and 8 <= nf <= 256 and 1 <= kf < nf and ne + nf < n):
                                continue
                            candidate = evaluate(n, q, eta, mlwe, tuple(point), "local_refinement")
                            if candidate["status"] == "conditional_model_cost" and candidate["log2_rop"] < winner["log2_rop"] - 1e-10:
                                winner, improved = candidate, True
                    if not improved:
                        break
                trails.append(dict(seed_index=seed["index"], best_index=winner["index"], sweeps=sweep + 1,
                                   refinement_limit_reached=improved and sweep == 11))
            winner = min((r for r in rows[before:] if r["status"] == "conditional_model_cost"), key=lambda r: r["log2_rop"])
            minima.append(winner)
            # An explicit old cap rerun documents clipping, without replacing
            # the uncapped result or calling an infeasible endpoint a cost.
            limited = model.evaluate(**winner["inputs"], beta_cap=1000)
            diagnostics.append(dict(winner_index=winner["index"], cap_1000=limited,
                                    refinement_trails=trails))
            print(f"best explored n={n} mlwe={mlwe}: log2rop={winner['log2_rop']:.9f}, beta={winner['beta0']}", flush=True)
    stream.close()
    return rows, minima, diagnostics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT) or output == ROOT or output.exists():
        raise ValueError("new output directory below NIST required")
    library, source = sources()
    sys.path.insert(0, str(library))
    from sage.all import RealField
    from sage.version import version as sage_version
    from estimator.reduction import RC
    real_field = RealField(2048)
    reduction = RC.MATZOV.__class__(nn="list_decoding-classical")
    model = CodedDualModel(reduction, real_field)
    output.mkdir(parents=True)
    start = time.monotonic()
    checks = calibration(model, original_functions(source, real_field, reduction), real_field, reduction)
    write(output / "calibration.json", checks)
    if not all(c["passed"] for c in checks):
        raise ArithmeticError("calibration failed; no exploratory panel executed")
    rows, minima, diagnostics = panel(model, output)
    statuses = {s: sum(r["status"] == s for r in rows) for s in sorted({r["status"] for r in rows})}
    study = dict(scenarios=[dict(n=1024, degree=256, q=3329, eta=2), dict(n=1536, degree=256, q=7681, eta=3)],
                 reduction_model="author-bundled MATZOV list_decoding-classical",
                 code_model="GV-radius ratio 1; no experimental q7681 decoder statistics",
                 memory_cap=None, targets=1, oracle="none", sample_budget="key only; subsets m<=n",
                 zero_guess_model="author conditional-binomial heuristic; not an exact finite-rotation probability",
                 guessed_zero_success_target=0.6, false_candidate_normal_model_budget=0.05,
                 calibration_passed=True, evaluations=len(rows), statuses=statuses,
                 minima=minima, cap_diagnostics=diagnostics, profile_selected=False, j2_closed=False,
                 limits=["best found in bounded search, not global optimum",
                         "conditional heuristic costs, not executed attacks or global KEM security",
                         "normal wrong-score assumption only; revised covariance and full score tails remain open",
                         "published statistics calibrate only the six reference points",
                         "no extrapolation of q3329 polar-code statistics to q7681",
                         "MLWE heuristic population=n; no factor 1536 rotations or blanket one-bit subtraction",
                         "MATZOV finite-size coefficients documented up to beta 1024; rank-six extrapolation is flagged",
                         "format-specific H01/H02 distributions and CCA remain open"])
    write(output / "study.json", study)
    inputs = ["research/coded_dual_model.py", "research/test_coded_dual_model.py", "research/run_coded_dual.py",
              "research/verify_coded_dual_results.py", "research/verify_coded_dual_numeric.py",
              "scripts/coded-dual.sh", "references/coded-dual-audit/utilitaries.py.txt"]
    inputs += [p.relative_to(ROOT).as_posix() for p in sorted((ROOT / "references/coded-dual-evaluation").iterdir())]
    provenance = dict(created_utc=datetime.now(timezone.utc).isoformat(), python=platform.python_version(),
                      sage=sage_version, seconds=time.monotonic() - start,
                      input_sha256={name: sha(ROOT / name) for name in inputs},
                      output_sha256={name: sha(output / name) for name in ("study.json", "calibration.json", "evaluations.jsonl")})
    write(output / "provenance.json", provenance)
    print(json.dumps(dict(evaluations=len(rows), statuses=statuses, seconds=provenance["seconds"])), flush=True)


if __name__ == "__main__":
    main()
