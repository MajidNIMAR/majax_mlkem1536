"""Integrity and rational replay of H02 run-006; standard Python only."""

from fractions import Fraction
import hashlib
import json
from pathlib import Path

from group_quantization import cover_certificate, exact_pair_bound

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "results/j2/run-006"


def verify():
    provenance = json.loads((RUN / "provenance.json").read_text(encoding="utf-8"))
    for group, base in (("input_sha256", ROOT), ("output_sha256", RUN)):
        for name, expected in provenance[group].items():
            path = (base / name).resolve()
            if not path.is_relative_to(base) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError(f"group quantization checksum mismatch: {name}")
    cover = json.loads((RUN / "cover.json").read_text(encoding="utf-8"))
    if cover != cover_certificate(7681, 12) or not cover["certified_L1_error_at_most_one"]:
        raise ValueError("actual-modulus pair cover mismatch")
    study = json.loads((RUN / "pair-study.json").read_text(encoding="utf-8"))
    saved = json.loads((RUN / "winner-certificate.json").read_text(encoding="utf-8"))
    if len(study["results"]) != 16 or study["profile_selected"] or study["j2_closed"]:
        raise ValueError("study scope changed")
    winner = min((r for r in study["results"] if r["c05_exact_comparison"]),
                 key=lambda r: (r["ciphertext_bytes"], r["message_upper"]["log2"], r["id"]))
    if saved["id"] != winner["id"] or saved["id"] != study["best_found_id"]:
        raise ValueError("best-found selection changed")
    replay = exact_pair_bound(saved["quantized_pairs"], saved["dv"], Fraction(saved["z"]), certificate=True)
    if replay["certificate"] != saved["certificate"] or not replay["c05_exact_comparison"]:
        raise ValueError("pair certificate replay failed")
    toys = json.loads((RUN / "toy-quantizers.json").read_text(encoding="utf-8"))["results"]
    if len(toys) != 5:
        raise ValueError("five exhaustive toy experiments required")
    for toy in toys:
        for row in toy["results"]:
            if sum(item["count"] for item in row["error_histogram"]) != toy["q"] ** 2:
                raise ValueError("toy histogram mass mismatch")
    return {"snapshot": "run-006", "checksums": "passed", "toy_tori": 5,
            "actual_modulus_cover": "certified", "rational_certificate": "replayed",
            "best_found": saved["id"], "bytes": saved["ciphertext_bytes"],
            "profile_selected": False, "j2_closed": False}


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
