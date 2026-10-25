"""Run a focused P0 diagnosis, with immutable snapshots and input hashes."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import tomllib

from decapsulation_diagnostic import diagnose

ROOT = Path(__file__).resolve().parents[1]


def definitions():
    p0 = dict(n=256, k=6, q=3329, eta1=2, eta2=2, du=11, dv=5)
    profile = tomllib.loads((ROOT / "profiles/kem1536-p0.toml").read_text(encoding="utf-8"))
    if any(profile["parameters"][key] != value for key, value in p0.items()):
        raise ValueError("frozen P0 identity changed")
    return [(name, p0 | changes) for name, changes in (
        ("baseline-1024", {"k": 4}), ("rank5-diagnostic", {"k": 5}),
        ("p0-1536", {}), ("p0-lossless-u", {"du": 12}),
        ("p0-lossless-v", {"dv": 12}), ("p0-lossless-both", {"du": 12, "dv": 12}))]


def write_json(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/generated/decapsulation")
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT) or output == ROOT:
        raise ValueError("output must be below NIST")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise FileExistsError("choose a new output directory; existing results are immutable")
    inputs = ["research/decapsulation_diagnostic.py", "research/run_decapsulation.py",
              "research/test_decapsulation_diagnostic.py", "research/verify_decapsulation_results.py",
              "research/noise_exact.py", "profiles/kem1536-p0.toml",
              "results/j2/run-001/noise.json", "results/j2/run-001/provenance.json"]
    provenance = {"created_utc": datetime.now(timezone.utc).isoformat(),
                  "python": platform.python_version(), "platform": platform.platform(),
                  "scope": "P0 diagnosis only; no replacement profile or security selection",
                  "input_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                   for name in inputs}}
    rows = []
    for name, parameters in definitions():
        result = {"id": name, "parameters": parameters, **diagnose(parameters)}
        rows.append(result)
        independent = result["independent_rounding_result"]
        robust = result["arbitrary_bounded_v"]
        print(f"{name}: log2 union={independent['message_union_bound_uniform_bits']['log2']:.9f}; "
              f"bounded-v single lower={robust['message_lower_uniform_bits']['log2']:.9f}", flush=True)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "decapsulation.json", {
        "threshold_log2": -174.8, "results": rows,
        "selection": "none; feasibility remains open",
        "limitations": ["CBD and uniform independent u marginals remain assumptions",
                        "bounded-v result is not a proof for the implemented KEM",
                        "no independence of output coefficients required by union bound",
                        "no malicious ciphertexts, weak-key tail or new attack estimates"]})
    provenance["output_sha256"] = {"decapsulation.json": hashlib.sha256(
        (output / "decapsulation.json").read_bytes()).hexdigest()}
    write_json(output / "provenance.json", provenance)


if __name__ == "__main__":
    main()
