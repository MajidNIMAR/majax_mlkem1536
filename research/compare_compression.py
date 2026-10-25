"""Compare formats at matched correctness targets and map existing LWE costs.

No new attack costs: format-specific ciphertext/CCA analysis remains open.
Floating searches propose candidates; reported target decisions are rational.
"""

import argparse
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path

from group_quantization import DV_VALUES, TILTS, TOTAL, exact_pair_bound
from mixed_precision import exact_bound, numerical_grid, screen_log
from witness_chernoff import safe_radius

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "results/j2/run-007"
PARAMETERS = dict(n=256, k=6, q=7681, eta=3)
TARGETS = (Fraction(874, 5), Fraction(200), Fraction(225))
FAMILIES = ("usvp", "bdd", "bdd_hybrid", "bdd_mitm_hybrid", "dual", "dual_hybrid")


def load(name):
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def target_met(value, exponent):
    if not 0 <= value <= 1 or exponent <= 0:
        raise ValueError("probability and positive exponent required")
    return (value.numerator ** exponent.denominator << exponent.numerator) <= value.denominator ** exponent.denominator


def certificate_value(row):
    bound = row["certificate"]["uncapped_bound"]
    return min(Fraction(1), Fraction(int(bound["numerator_hex"], 16), int(bound["denominator_hex"], 16)))


def attack_mapping():
    all_rows = load("results/j2/run-002/modern-attacks.json")["results"]
    selected = [(i, r) for i, r in enumerate(all_rows) if r["job"]["parameters"] == PARAMETERS]
    if len(selected) != 30:
        raise ValueError("expected thirty identical-parameter attack evaluations")
    references = [{"result_index": i, "job": r["job"], "status": r["status"],
                   "log2_cost": r.get("log2_cost", {})} for i, r in selected]
    minima = []
    for model in ("MATZOV-classical", "BCSS23-quantum-asymptotic"):
        for budget in ("key", "extended"):
            panel = [(i, r) for i, r in selected if r["job"]["cost_model"] == model
                     and r["job"]["sample_budget"] == budget
                     and r["job"]["algorithm"] in FAMILIES and r["status"] == "ok"]
            if len(panel) != 6:
                raise ValueError("incomplete six-family panel")
            index, winner = min(panel, key=lambda item: item[1]["log2_cost"]["rop"])
            minima.append(dict(cost_model=model, sample_budget=budget, result_index=index,
                               algorithm=winner["job"]["algorithm"], log2_rop=winner["log2_cost"]["rop"]))
    return dict(parameters=PARAMETERS, formats=["exact-u", "H01", "H02"],
                source="results/j2/run-002/modern-attacks.json", new_costs_computed=False,
                references=references, minima=minima,
                scope="identical public-key LWE inputs only; extended samples are a sensitivity scenario",
                unresolved=["ciphertext-specific distributions and H02 pair dependence",
                            "coded dual with rotations and revised scores",
                            "CCA reduction, adversarial failures and leakage oracles",
                            "bounded-memory and complete quantum cost models"])


def pair_grid(scalar_grid):
    probabilities = {s: math.comb(6, 3 + s) / 64 for s in range(-3, 4)}
    result = []
    for rational, scalar in zip(TILTS, scalar_grid):
        z = float(rational)
        conditional = {s: sum(p * z ** (-s * e) for e, p in probabilities.items()) for s in probabilities}
        pair = sum(p1 * p2 * conditional[s1] * conditional[s2] * z ** max(abs(s1), abs(s2))
                   for s1, p1 in probabilities.items() for s2, p2 in probabilities.items())
        result.append(dict(z=rational, log_z=scalar["log_z"],
                           base=scalar["common"] + TOTAL * scalar["logs"][13],
                           penalty=math.log2(pair) - 2 * scalar["logs"][13]))
    return result


def compare():
    grid = numerical_grid()
    pairs = pair_grid(grid)
    rows = []
    for target in TARGETS:
        for family, step in (("exact-u", 1), ("H01", 8), ("H02", 4)):
            proposals = []
            for dv in DV_VALUES:
                h = safe_radius(7681, dv)[0] + 1
                for g in (pairs if family == "H02" else grid):
                    if family == "H02":
                        base, penalty = g["base"] - h * g["log_z"], g["penalty"]
                        cap = TOTAL // 2
                    else:
                        base = screen_log(g, {11: 0, 12: 0, 13: TOTAL}, h)
                        penalty = g["logs"][12] - g["logs"][13]
                        cap = TOTAL if family == "H01" else 0
                    allowed = min(cap, math.floor((-float(target) - base) / penalty))
                    if allowed < 0:
                        continue
                    count = allowed // step * step
                    bits = 13 * TOTAL + 256 * dv - count * (2 if family == "H02" else 1)
                    proposals.append(((bits + 7) // 8, base + count * penalty, dv, count, g["z"]))
            _, approximate, dv, count, z = min(proposals)
            if family == "H02":
                row = exact_pair_bound(count, dv, z, certificate=True)
            else:
                row = exact_bound({11: 0, 12: count, 13: TOTAL - count}, dv, z, full_certificate=True)
            value = certificate_value(row)
            if not target_met(value, target) or abs(row["message_upper"]["log2"] - approximate) > 1e-6:
                raise ArithmeticError("numerical proposal not confirmed exactly")
            rows.append(dict(family=family, target_exponent=str(target), compressed_count=count,
                             target_met_exactly=True, result=row))
            print(f"target {target}: {family}, {row['ciphertext_bytes']} bytes, log2={row['message_upper']['log2']:.9f}", flush=True)
    return dict(parameters=PARAMETERS, tilt_points=500, targets=[str(t) for t in TARGETS],
                results=rows, attack_mapping=attack_mapping(),
                profile_selected=False, j2_closed=False,
                limits=["independent ideal CBD primitives; no rounding independence",
                        "rational validation of selected floating-grid proposals, not proof of global optimality",
                        "continuous u bitstream; no runtime, constant-time or engine measurements",
                        "correctness bounds are not measured failure rates or security bits"])


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify():
    provenance = load("results/j2/run-007/provenance.json")
    for key, base in (("input_sha256", ROOT), ("output_sha256", RUN)):
        for name, expected in provenance[key].items():
            path = (base / name).resolve()
            if not path.is_relative_to(base) or digest(path) != expected:
                raise ValueError(f"comparison checksum mismatch: {name}")
    study = load("results/j2/run-007/comparison.json")
    if study["attack_mapping"] != attack_mapping() or study["profile_selected"] or study["j2_closed"]:
        raise ValueError("comparison scope/mapping mismatch")
    if len(study["results"]) != 9:
        raise ValueError("nine matched-target results required")
    for item in study["results"]:
        row = item["result"]
        if item["family"] == "H02":
            replay = exact_pair_bound(item["compressed_count"], row["dv"], Fraction(row["z"]), certificate=True)
        else:
            replay = exact_bound({int(k): v for k, v in row["u_counts"].items()}, row["dv"], Fraction(row["z"]), full_certificate=True)
        if replay != row or not target_met(certificate_value(row), Fraction(item["target_exponent"])):
            raise ValueError("matched-target rational replay failed")
    return dict(snapshot="run-007", rational_results_replayed=9,
                mapped_prior_attacks=30, new_attack_costs=0, profile_selected=False, j2_closed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--output", type=Path, default=RUN)
    args = parser.parse_args()
    if args.verify:
        print(json.dumps(verify(), indent=2))
        return
    output = args.output.resolve()
    if output == ROOT or not output.is_relative_to(ROOT) or output.exists():
        raise ValueError("new output directory below NIST required")
    inputs = ["research/compare_compression.py", "research/test_compare_compression.py",
              "research/group_quantization.py", "research/mixed_precision.py", "research/noise_exact.py",
              "research/witness_chernoff.py", "research/modern_worker.py",
              "results/j2/run-002/modern-attacks.json", "results/j2/run-005/winner-certificate.json",
              "results/j2/run-006/winner-certificate.json"]
    inputs += [str(p.relative_to(ROOT)).replace("\\", "/") for p in sorted((ROOT / "references/coded-dual-audit").iterdir())]
    hashes = {name: digest(ROOT / name) for name in inputs}
    study = compare()
    output.mkdir(parents=True)
    (output / "comparison.json").write_text(json.dumps(study, indent=2) + "\n", encoding="utf-8")
    provenance = dict(created_utc=datetime.now(timezone.utc).isoformat(), input_sha256=hashes,
                      output_sha256={"comparison.json": digest(output / "comparison.json")})
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
