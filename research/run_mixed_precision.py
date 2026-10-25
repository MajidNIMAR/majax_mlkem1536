"""Run the mixed-precision hypothesis without overwriting prior snapshots."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform

from mixed_precision import scan

ROOT = Path(__file__).resolve().parents[1]


def write_json(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/generated/mixed-precision")
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT) or output == ROOT:
        raise ValueError("output must stay below NIST")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise FileExistsError("nonempty output is immutable")
    inputs = ["research/mixed_precision.py", "research/test_mixed_precision.py",
              "research/run_mixed_precision.py", "research/verify_mixed_precision_results.py",
              "research/witness_chernoff.py", "research/noise_exact.py",
              "profiles/kem1536-p0.toml", "results/j2/run-004/correctness-certificate.json"]
    provenance = {"created_utc": datetime.now(timezone.utc).isoformat(),
                  "python": platform.python_version(), "platform": platform.platform(),
                  "input_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                   for name in inputs}}
    data = scan()
    output.mkdir(parents=True, exist_ok=True)
    certificate = data.pop("winner_certificate")
    screening = data.pop("screening")
    outputs = {"mixed-precision.json": data, "winner-certificate.json": certificate,
               "screening.json": {"purpose": "floating proposals only, no acceptance certificate", "rows": screening}}
    for name, value in outputs.items():
        write_json(output / name, value)
    provenance["output_sha256"] = {name: hashlib.sha256((output / name).read_bytes()).hexdigest()
                                   for name in outputs}
    write_json(output / "provenance.json", provenance)
    print(json.dumps({"best_found_id": data["best_found_id"],
                      "ciphertext_bytes": certificate["ciphertext_bytes"],
                      "u_counts": certificate["u_counts"], "dv": certificate["dv"],
                      "log2_upper": certificate["message_upper"]["log2"],
                      "certified": data["certified_count"],
                      "not_certified": data["not_certified_count"]}, indent=2), flush=True)


if __name__ == "__main__":
    main()
