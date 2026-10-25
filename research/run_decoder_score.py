"""Reconstruct run-010 residuals, retaining coordinate and score dependence."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import platform

from block_decoder import make_code
from decoder_score import LN2, centered, distribution_summary, exact_toy, integer_moments, log_phi, score_bank
from run_block_decoder import targets

ROOT = Path(__file__).resolve().parents[1]


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def equal_norm_controls():
    rows = []
    for q, eta, dimension, amplitudes in ((3329, 2, 111, (300, 750, 1500)), (7681, 3, 140, (600, 1500, 3000))):
        for amplitude in amplitudes:
            for shape, nonzero in (("axis", [amplitude]), ("pythagorean", [amplitude * 3 // 5, amplitude * 4 // 5]),
                                   ("spread_25", [amplitude // 5] * 25)):
                r = nonzero + [0] * (dimension - len(nonzero))
                squared = sum(v * v for v in r)
                if squared != amplitude ** 2:
                    raise ArithmeticError("equal-norm control failed")
                rows.append(dict(q=q, eta=eta, amplitude=amplitude, shape=shape, residual=r, squared_norm=squared,
                                 log2_CBD=log_phi(r, q, eta) / LN2,
                                 log2_Gaussian_upper=-eta * math.pi ** 2 * squared / q ** 2 / LN2))
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT) or output == ROOT or output.exists():
        raise ValueError("new output directory below NIST required")
    from verify_block_decoder_results import verify as verify_parent
    verify_parent()
    study = json.loads((ROOT / "results/j2/run-010/study.json").read_text(encoding="utf-8"))
    parent = [json.loads(line) for line in (ROOT / "results/j2/run-010/observations.jsonl").read_text(encoding="utf-8").splitlines()]
    output.mkdir(parents=True)
    summaries, moments, banks = [], [], []
    with (output / "residuals.jsonl").open("x", encoding="utf-8", newline="\n") as stream:
        for experiment in study["experiments"]:
            code = experiment["code"]
            q, eta = code["q"], 2 if code["q"] == 3329 else 3
            observations = [r for r in parent if r["experiment"] == experiment["experiment"]]
            points = targets(q, code["n"], len(observations), experiment["seed_ascii"].encode("ascii"))
            residuals = []
            for target, row in zip(points, observations):
                word = [a * g % q for a, block in zip(row["labels"], code["generators"]) for g in block]
                residual = [centered(x-y, q) for x, y in zip(target, word)]
                if sum(v * v for v in residual) != row["squared_norm"]:
                    raise ArithmeticError("parent residual norm mismatch")
                exact = log_phi(residual, q, eta) / LN2
                gaussian = -eta * math.pi ** 2 * row["squared_norm"] / q ** 2 / LN2
                stream.write(json.dumps(dict(experiment=experiment["experiment"], index=row["index"], residual=residual,
                                             squared_norm=row["squared_norm"], log2_CBD=exact, log2_Gaussian_upper=gaussian)) + "\n")
                residuals.append(residual)
            result = distribution_summary(residuals, q, eta, code["block_sizes"])
            summaries.append(dict(experiment=experiment["experiment"], q=q, eta=eta, block_sizes=code["block_sizes"], **result))
            moments.append(dict(experiment=experiment["experiment"], **integer_moments(residuals)))
            banks.append(dict(experiment=experiment["experiment"], **score_bank(residuals, q, eta)))
            print(f"{experiment['experiment']}: CBD log2mean={result['empirical_log2_mean_CBD']:.9f}, "
                  f"Gaussian excess={result['log2_Gaussian_over_joint']:.9f}, coordinate-product excess={result['log2_coordinate_product_over_joint']:.9f}", flush=True)
    toys = [exact_toy(make_code(q, n, k, family)) for q, n, k in ((5, 3, 1), (5, 4, 2), (7, 4, 2))
            for family in ("repeated", "radix")]
    write(output / "toy-laws.json", toys)
    write(output / "coordinate-moments.json", moments)
    write(output / "score-banks.json", banks)
    write(output / "equal-norm-controls.json", equal_norm_controls())
    write(output / "study.json", dict(results=summaries, profile_selected=False, j2_closed=False, attack_costs_updated=False,
                                      model="code-only cosine contributions; one shared independent ideal iid-CBD secret",
                                      limits=["no dual-lattice vectors, FFT stage or full correct/wrong-guess attack score",
                                              "256 fixed synthetic residuals per experiment; averages do not certify population expectations or rare tails",
                                              "coordinate product is an artificial independent-marginal law, not the joint residual law",
                                              "block factorization is exact for independent uniform input blocks; products of sample means remain estimates",
                                              "32-term fixed-bank moments do not validate independence for the enormous lists in run-009",
                                              "equal-norm controls and covariance formulas concern the ideal CBD auxiliary model only",
                                              "no success probability, security level, profile or C05 update"]))
    inputs = ["research/decoder_score.py", "research/test_decoder_score.py", "research/run_decoder_score.py",
              "research/verify_decoder_score_results.py", "research/verify_decoder_score_independent.py",
              "research/verify_decoder_score_numeric.py", "research/block_decoder.py", "research/run_block_decoder.py",
              "results/j2/run-010/study.json", "results/j2/run-010/observations.jsonl", "results/j2/run-010/provenance.json",
              "results/j2/run-010/independent-provenance.json", "references/decoder-score-2026/sources.json"]
    outputs = ("residuals.jsonl", "toy-laws.json", "coordinate-moments.json", "score-banks.json", "equal-norm-controls.json", "study.json")
    write(output / "provenance.json", dict(created_utc=datetime.now(timezone.utc).isoformat(), python=platform.python_version(),
                                            input_sha256={name: digest(ROOT / name) for name in inputs},
                                            output_sha256={name: digest(output / name) for name in outputs}))


if __name__ == "__main__":
    main()
