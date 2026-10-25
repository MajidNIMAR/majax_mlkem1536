"""Preserve an exact small-ring dependence study and lossless-u witnesses."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform

from u_dependency import lossless_u_witness, toy_coset_study

ROOT = Path(__file__).resolve().parents[1]


def write_json(path, data):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(data, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/generated/u-dependency")
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT) or output == ROOT:
        raise ValueError("output must stay below NIST")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise FileExistsError("nonempty output is immutable; select a new run")
    inputs = ["research/u_dependency.py", "research/test_u_dependency.py",
              "research/run_u_dependency.py", "research/verify_u_dependency_results.py",
              "research/noise_exact.py", "research/decapsulation_diagnostic.py",
              "profiles/kem1536-p0.toml", "results/j2/run-003/decapsulation.json",
              "references/correctness-2026/manifest.json"]
    provenance = {"created_utc": datetime.now(timezone.utc).isoformat(),
                  "python": platform.python_version(), "platform": platform.platform(),
                  "input_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                   for name in inputs},
                  "profile_selection": "none", "j2_closed": False}
    toys = [toy_coset_study(k) for k in (1, 2)]
    for toy in toys:
        print(f"toy k={toy['parameters']['k']}: joint TV="
              f"{toy['joint_rounding_e1_tv_from_independent_reference']['fraction']}", flush=True)
    witnesses = []
    for q, eta, dvs in ((3329, 2, (5, 12)), (7681, 3, (5, 13))):
        result = lossless_u_witness(q, eta, dvs)
        witnesses.append(result)
        for row in result["results"]:
            print(f"q={q}, eta={eta}, raw-u, dv={row['dv']}: log2 worst-bit union upper="
                  f"{row['message_union_upper_any_fixed_message']['log2']:.9f}; "
                  f"C05 upper={row['c05_exact_upper_comparison']}", flush=True)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "u-dependency.json", {"toys": toys, "lossless_u_witnesses": witnesses,
               "threshold": "2^(-874/5)", "threshold_decision": "exact fifth-power integer comparison",
               "profile_selection": "none", "j2_closed": False,
               "limits": ["toy numerical results do not transfer to n=256,k=6",
                          "raw-u witnesses change ciphertext encoding; no new KEM is implemented",
                          "ideal CBD correctness is not fixed-SHAKE or worst-key correctness",
                          "modern attack coverage, memory, CCA and oracle analysis remain open"]})
    provenance["output_sha256"] = {"u-dependency.json": hashlib.sha256(
        (output / "u-dependency.json").read_bytes()).hexdigest()}
    write_json(output / "provenance.json", provenance)


if __name__ == "__main__":
    main()
