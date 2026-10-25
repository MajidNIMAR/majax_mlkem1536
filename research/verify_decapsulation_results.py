"""Verify the focused correctness snapshot without recomputing its tails."""

from fractions import Fraction
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "results/j2/run-003"


def verify():
    provenance = json.loads((RUN / "provenance.json").read_text(encoding="utf-8"))
    for group, base in (("input_sha256", ROOT), ("output_sha256", RUN)):
        for relative, digest in provenance[group].items():
            path = (base / relative).resolve()
            if not path.is_relative_to(base) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError(f"decapsulation checksum mismatch: {relative}")
    data = json.loads((RUN / "decapsulation.json").read_text(encoding="utf-8"))
    rows = {row["id"]: row for row in data["results"]}
    if len(rows) != 6 or data["selection"] != "none; feasibility remains open":
        raise ValueError("diagnosis scope drift")
    historical = json.loads((ROOT / "results/j2/run-001/noise.json").read_text(encoding="utf-8"))
    old_rows = {row["id"]: row for row in historical["results"]}
    for current, original in (("baseline-1024", "baseline-1024"), ("p0-1536", "p0-1536"),
                              ("p0-lossless-u", "q3329-du12"),
                              ("p0-lossless-both", "q3329-lossless")):
        fresh = rows[current]["independent_rounding_result"]
        for key in ("bit0_failure", "bit1_failure", "message_union_bound_uniform_bits"):
            if fresh[key] != old_rows[original][key]:
                raise ValueError("exact probability changed relative to run-001")
    for row in rows.values():
        parts = row["variance_decomposition"]
        if sum(Fraction(value["exact"]) for value in parts["terms"].values()) != Fraction(parts["total_variance"]):
            raise ValueError("variance identity failed")
        robust = row["arbitrary_bounded_v"]
        if robust["crosscheck_independent_marginals"] != "exact rational agreement":
            raise ValueError("missing rational interval crosscheck")
    if rows["p0-1536"]["arbitrary_bounded_v"]["message_lower_any_fixed_message"]["log2"] <= data["threshold_log2"]:
        raise ValueError("P0 bounded-v rejection not reproduced")
    if rows["p0-lossless-both"]["independent_rounding_result"]["message_lower_bound_single_coefficient"]["log2"] <= data["threshold_log2"]:
        raise ValueError("lossless diagnostic not reproduced")
    return {"snapshot": "run-003", "checksums": "passed", "scenarios": len(rows),
            "run001_probability_matches": 4, "replacement_profile_selected": False}


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
