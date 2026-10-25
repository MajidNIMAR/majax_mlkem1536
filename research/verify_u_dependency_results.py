"""Integrity, scope and prior-result checks for J2 run-004."""

from fractions import Fraction
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "results/j2/run-004"


def verify():
    provenance = json.loads((RUN / "provenance.json").read_text(encoding="utf-8"))
    for group, base in (("input_sha256", ROOT), ("output_sha256", RUN)):
        for relative, expected in provenance[group].items():
            path = (base / relative).resolve()
            if not path.is_relative_to(base) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError(f"u dependency checksum mismatch: {relative}")
    manifest = json.loads((ROOT / "references/correctness-2026/manifest.json").read_text(encoding="utf-8"))
    for source in manifest["sources"]:
        path = (ROOT / "references/correctness-2026" / source["file"]).resolve()
        if not path.is_relative_to(ROOT / "references/correctness-2026") or hashlib.sha256(path.read_bytes()).hexdigest() != source["sha256"]:
            raise ValueError("correctness source checksum mismatch")
    data = json.loads((RUN / "u-dependency.json").read_text(encoding="utf-8"))
    if data["profile_selection"] != "none" or data["j2_closed"] or len(data["toys"]) != 2:
        raise ValueError("scope drift")
    for toy in data["toys"]:
        if toy["joint_tv_conditioned_on_full_ideal"]["fraction"] != "0":
            raise ValueError("conditional uniformity failed")
        if Fraction(toy["joint_rounding_e1_tv_from_independent_reference"]["fraction"]) <= 0:
            raise ValueError("dependence not demonstrated")
        if Fraction(toy["joint_tv_from_product_of_actual_marginals"]["fraction"]) <= 0:
            raise ValueError("actual rounding/e1 independence not rejected")
    witnesses = {item["parameters"]["q"]: item for item in data["lossless_u_witnesses"]}
    old = json.loads((ROOT / "results/j2/run-003/decapsulation.json").read_text(encoding="utf-8"))
    old_rows = {row["id"]: row for row in old["results"]}
    for dv, old_id in ((5, "p0-lossless-u"), (12, "p0-lossless-both")):
        row = next(row for row in witnesses[3329]["results"] if row["dv"] == dv)
        prior = old_rows[old_id]["arbitrary_bounded_v"]
        for bit in (0, 1):
            for direction in ("lower", "upper"):
                key = f"bit{bit}_{direction}"
                if row[key] != prior[key]:
                    raise ValueError("prior exact lossless-u marginal changed")
    for row in witnesses[7681]["results"]:
        if not row["c05_exact_upper_comparison"] or row["c05_exact_lower_exceeds_threshold"]:
            raise ValueError("positive correctness witness not reproduced")
    return {"snapshot": "run-004", "checksums": "passed", "toy_ranks": 2,
            "lossless_u_scenarios": 4, "prior_marginal_matches": 8,
            "rounding_independence_needed_for_witness": False,
            "profile_selected": False, "j2_closed": False}


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
