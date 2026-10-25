"""Integrity, sample reconstruction and exact distance checks of run-010.

No NumPy, Sage, benchmark rerun or exhaustive decoder search is needed.
"""

import hashlib
import json
import math
from pathlib import Path

from block_decoder import make_code
from run_block_decoder import SAMPLES, statistics, target_hash, targets

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "results/j2/run-010"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def close(a, b):
    return math.isclose(a, b, rel_tol=1e-12, abs_tol=1e-9)


def verify():
    for manifest in ("provenance.json", "independent-provenance.json"):
        provenance = read(RUN / manifest)
        for group, base in (("input_sha256", ROOT), ("output_sha256", RUN)):
            for name, expected in provenance[group].items():
                path = (base / name).resolve()
                if not path.is_relative_to(base) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                    raise ValueError(f"block decoder checksum mismatch: {name}")
    study = read(RUN / "study.json")
    if len(study["experiments"]) != 8 or study["profile_selected"] or study["j2_closed"] or study["attack_costs_updated"]:
        raise ValueError("decoder experiment scope mismatch")
    parent = read(ROOT / "results/j2/run-009/study.json")["minima"]
    observations = [json.loads(s) for s in (RUN / "observations.jsonl").read_text(encoding="utf-8").splitlines()]
    if len(observations) != 8 * SAMPLES:
        raise ValueError("sample observation count mismatch")
    for position, experiment in enumerate(study["experiments"]):
        reference = parent[position // 2]
        code = experiment["code"]
        expected = make_code(code["q"], code["n"], code["k"], code["family"]).record()
        if code != expected or (code["q"], code["n"], code["k"]) != tuple(reference["inputs"][k] for k in ("q", "nfft", "kfft")):
            raise ValueError("decoder/attack-point parameters mismatch")
        if experiment["parent_point_index"] != reference["index"] or experiment["mlwe_heuristic"] != reference["inputs"]["mlwe"]:
            raise ValueError("attack-point binding mismatch")
        rows = [r for r in observations if r["experiment"] == experiment["experiment"]]
        if [r["index"] for r in rows] != list(range(SAMPLES)):
            raise ValueError("sample indices mismatch")
        points = targets(code["q"], code["n"], SAMPLES, experiment["seed_ascii"].encode("ascii"))
        squares = []
        for row, target in zip(rows, points):
            labels = row["labels"]
            if len(labels) != code["k"] or any(not isinstance(a, int) or not 0 <= a < code["q"] for a in labels):
                raise ValueError("noncanonical decoded message")
            word = [a * g % code["q"] for a, block in zip(labels, code["generators"]) for g in block]
            squared = sum(min(abs(x-y), code["q"] - abs(x-y)) ** 2 for x, y in zip(target, word))
            if row["target_sha256"] != target_hash(target) or squared != row["squared_norm"]:
                raise ValueError("sample reconstruction/distance mismatch")
            if code["family"] == "radix" and row["coordinate_distance_terms"] != code["q"] * code["n"]:
                raise ValueError("enumeration term count mismatch")
            if code["family"] == "repeated" and row["candidate_scores"] > 2 * (code["n"] + code["k"]):
                raise ValueError("interval search bound exceeded")
            squares.append(squared)
        radius = math.exp((1 - code["k"] / code["n"]) * math.log(code["q"])
                          + math.lgamma(code["n"] / 2 + 1) / code["n"] - math.log(math.pi) / 2)
        if not close(radius, experiment["GV_radius_proxy"]):
            raise ValueError("GV radius proxy mismatch")
        recalculated = statistics(squares, radius)
        for name, value in recalculated.items():
            actual = experiment["observations"][name]
            if (isinstance(value, int) and value != actual) or (not isinstance(value, int) and not close(value, actual)):
                raise ValueError(f"sample statistic mismatch: {name}")
    timing = read(RUN / "timings.json")
    if len(timing["measurements"]) != 8:
        raise ValueError("eight benchmark records required")
    for t, experiment in zip(timing["measurements"], study["experiments"]):
        if t["experiment"] != experiment["experiment"] or t["batch_size"] != 8 or len(t["batches_ns"]) != 7:
            raise ValueError("benchmark protocol mismatch")
        if any(not isinstance(d, int) or d <= 0 for d in t["batches_ns"]) or sorted(t["batches_ns"])[3] / 8 != t["median_ns_per_decode"]:
            raise ValueError("benchmark arithmetic mismatch")
    independent = read(RUN / "independent-verification.json")
    if not independent["all_matched"] or independent["actual_modulus_blocks"] != 64 or independent["classified_targets"] != 6302:
        raise ValueError("independent decoder verification missing")
    return dict(snapshot="run-010", experiments=8, reconstructed_observations=len(observations),
                actual_modulus_oracles=64, independent_toy_targets=6302,
                attack_costs_updated=False, profile_selected=False, j2_closed=False)


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
