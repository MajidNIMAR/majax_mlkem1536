"""Verify the frozen J2 run against its recorded inputs and outputs."""

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "results/j2/run-001"


def verify() -> dict:
    provenance = json.loads((RUN / "provenance.json").read_text(encoding="utf-8"))
    for group, base in (("input_sha256", ROOT), ("output_sha256", RUN)):
        for relative, expected in provenance[group].items():
            path = (base / relative).resolve()
            if not path.is_relative_to(base):
                raise ValueError("invalid manifest path")
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError(f"frozen run checksum mismatch: {relative}")
    noise = json.loads((RUN / "noise.json").read_text(encoding="utf-8"))
    if len(noise["results"]) != 8:
        raise ValueError("eight documented noise scenarios required")
    for row in noise["results"]:
        if row["crosscheck_log2_absolute_difference"] > 1e-6:
            raise ValueError("independent noise crosscheck failed")
    attacks = json.loads((RUN / "attacks.json").read_text(encoding="utf-8"))
    if len(attacks["results"]) != 4:
        raise ValueError("four attack comparisons required")
    for row in attacks["results"]:
        if len(row["attacks"]) != 6:
            raise ValueError("six attack/model combinations required")
        for attack in row["attacks"]:
            if abs(attack["log2_core_svp_cost"]-attack["original_cost_recheck"]) > 1e-7:
                raise ValueError("original attack model recheck failed")
    return {"snapshot": "run-001", "input_files": len(provenance["input_sha256"]),
            "output_files": len(provenance["output_sha256"]),
            "noise_scenarios": 8, "attack_estimates": 24, "checksums": "passed"}


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
