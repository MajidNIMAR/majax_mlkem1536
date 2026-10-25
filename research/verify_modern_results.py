"""Integrity and scope checks for J2 run-002 (no Sage needed)."""

from collections import Counter
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "results/j2/run-002"


def verify():
    provenance = json.loads((RUN / "provenance.json").read_text(encoding="utf-8"))
    for group, base in (("input_sha256", ROOT), ("output_sha256", RUN)):
        for relative, expected in provenance[group].items():
            path = (base / relative).resolve()
            content = path.read_bytes()
            if group == "input_sha256" and relative in provenance.get("normalized_lf_inputs", []):
                content = content.replace(b"\r\n", b"\n")
            if not path.is_relative_to(base) or hashlib.sha256(content).hexdigest() != expected:
                raise ValueError(f"modern study checksum mismatch: {relative}")
    data = json.loads((RUN / "modern-attacks.json").read_text(encoding="utf-8"))
    if len(data["results"]) != provenance["planned_jobs"] or provenance["planned_jobs"] != 120:
        raise ValueError("incomplete output file set")
    statuses = Counter()
    for row in data["results"]:
        job = row["job"]
        parameters = job["parameters"]
        expected_samples = parameters["n"]*(parameters["k"]+(job["sample_budget"] == "extended"))
        if job["samples"] != expected_samples or parameters["n"] != 256 or job["targets"] != 1:
            raise ValueError("sample/dimension/target policy drift")
        statuses[row["status"]] += 1
        if row["status"] == "ok" and "rop" not in row["log2_cost"]:
            raise ValueError("successful estimate has no total cost")
    return {"snapshot": "run-002", "checksums": "passed", "attempted": len(data["results"]),
            "export_retries_preserved": sum("prior_export_attempt" in row for row in data["results"]),
            "statuses": dict(statuses), "coverage": "complete tool matrix" if set(statuses) == {"ok"}
            else "incomplete; failures retained, do not infer a global minimum"}


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
