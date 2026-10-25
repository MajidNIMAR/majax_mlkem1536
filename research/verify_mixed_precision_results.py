"""Verify J2 run-005 and replay its exact best-found correctness certificate."""

from fractions import Fraction
import hashlib
import json
from pathlib import Path

from mixed_precision import DV_VALUES, exact_bound

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "results/j2/run-005"


def verify():
    provenance = json.loads((RUN / "provenance.json").read_text(encoding="utf-8"))
    for group, base in (("input_sha256", ROOT), ("output_sha256", RUN)):
        for name, expected in provenance[group].items():
            path = (base / name).resolve()
            if not path.is_relative_to(base) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError(f"mixed precision checksum mismatch: {name}")
    data = json.loads((RUN / "mixed-precision.json").read_text(encoding="utf-8"))
    saved = json.loads((RUN / "winner-certificate.json").read_text(encoding="utf-8"))
    rows = data["block_results"] + data["coefficient_results"]
    if len(data["block_results"]) != 28 * len(DV_VALUES) or data["profile_selected"] or data["j2_closed"]:
        raise ValueError("study matrix or scope drift")
    if sum(row["c05_exact_comparison"] for row in rows) != data["certified_count"]:
        raise ValueError("classification count drift")
    winner = min((row for row in rows if row["c05_exact_comparison"]),
                 key=lambda row: (row["ciphertext_bytes"], row["message_upper"]["log2"], row["id"]))
    if winner["id"] != data["best_found_id"] or saved["id"] != winner["id"]:
        raise ValueError("best-found selection drift")
    replay = exact_bound({int(w): count for w, count in saved["u_counts"].items()}, saved["dv"],
                         Fraction(saved["z"]), full_certificate=True)
    if replay["certificate"] != saved["certificate"] or not replay["c05_exact_comparison"]:
        raise ValueError("rational certificate replay failed")
    previous = json.loads((ROOT / "results/j2/run-004/correctness-certificate.json").read_text(encoding="utf-8"))
    reference = exact_bound({11: 0, 12: 0, 13: 1536}, 5, Fraction(13, 10), full_certificate=True)
    if reference["certificate"]["uncapped_bound"] != previous["message_upper"]:
        raise ValueError("lossless baseline changed")
    return {"snapshot": "run-005", "checksums": "passed", "reported_bounds": len(rows),
            "best_found": winner["id"], "bytes": replay["ciphertext_bytes"],
            "certificate_replay": "exact", "profile_selected": False, "j2_closed": False}


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
