"""Preserve H02 finite toy quantizers, cover and rational pair certificates."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform

from group_quantization import cover_certificate, pair_scan, toy_study

ROOT = Path(__file__).resolve().parents[1]


def write(path, data):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/generated/group-quantization")
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT) or output == ROOT:
        raise ValueError("outputs must stay below NIST")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise FileExistsError("existing output is immutable")
    inputs = ["research/group_quantization.py", "research/test_group_quantization.py",
              "research/run_group_quantization.py", "research/verify_group_quantization_results.py",
              "research/noise_exact.py", "research/witness_chernoff.py",
              "research/mixed_precision.py",
              "results/j2/run-005/winner-certificate.json", "profiles/kem1536-p0.toml"]
    provenance = {"created_utc": datetime.now(timezone.utc).isoformat(),
                  "python": platform.python_version(), "platform": platform.platform(),
                  "input_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in inputs}}
    toys = []
    for q, bits in ((5, 2), (7, 2), (13, 3), (17, 3), (31, 4)):
        result = toy_study(q, bits)
        toys.append(result)
        print(f"toy q={q}, bits={bits}: " + str([(r['mode'], r['mean_squared_error_uniform_input'])
                                                for r in result['results']]), flush=True)
    study = pair_scan()
    certificate, screening = study.pop("winner_certificate"), study.pop("screening")
    outputs = {"toy-quantizers.json": {"results": toys}, "cover.json": cover_certificate(7681, 12),
               "pair-study.json": study, "winner-certificate.json": certificate,
               "screening.json": {"purpose": "floating proposals only", "rows": screening}}
    output.mkdir(parents=True, exist_ok=True)
    for name, data in outputs.items():
        write(output / name, data)
    provenance["output_sha256"] = {name: hashlib.sha256((output / name).read_bytes()).hexdigest() for name in outputs}
    write(output / "provenance.json", provenance)
    print(json.dumps({"best_found": study["best_found_id"], "pairs": certificate["quantized_pairs"],
                      "dv": certificate["dv"], "bytes": certificate["ciphertext_bytes"],
                      "log2_upper": certificate["message_upper"]["log2"]}, indent=2), flush=True)


if __name__ == "__main__":
    main()
