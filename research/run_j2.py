"""Reproduce J2 calculations. Default outputs are ignored working artifacts."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import platform
from pathlib import Path
import tomllib

from attack_models import analyze_attacks
from noise_crosscheck import crosscheck
from noise_exact import analyze
from upstream_tools import ROOT, ensure_tools


def scenarios() -> list[dict]:
    profile = tomllib.loads((ROOT / "profiles/kem1536-p0.toml").read_text(encoding="utf-8"))
    # Fail if the frozen research scenario drifts from its originating profile.
    p0 = dict(n=256, k=6, q=3329, eta1=2, eta2=2, du=11, dv=5)
    for key, value in p0.items():
        if profile["parameters"][key] != value:
            raise ValueError(f"P0 changed: {key}; define a new research run")
    definitions = [
        ("baseline-1024", {"k": 4}), ("p0-1536", {}),
        ("q3329-dv6", {"dv": 6}), ("q3329-du12", {"du": 12}),
        ("q3329-lossless", {"du": 12, "dv": 12}),
        ("q7681-eta2", {"q": 7681}),
        ("q7681-eta3", {"q": 7681, "eta1": 3, "eta2": 3}),
        ("q7681-eta3-du12", {"q": 7681, "eta1": 3, "eta2": 3, "du": 12}),
    ]
    return [{"id": name, "parameters": p0 | changes} for name, changes in definitions]


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--part", choices=("all", "noise", "attacks"), default="all")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/generated/j2")
    parser.add_argument("--snapshot", action="store_true", help="require a new empty output directory")
    args = parser.parse_args()
    destination = args.output.resolve()
    if not destination.is_relative_to(ROOT):
        raise ValueError("research outputs must stay inside NIST")
    if args.snapshot and destination.exists():
        raise FileExistsError("snapshot already exists; choose a new run identifier")
    ensure_tools()
    destination.mkdir(parents=True, exist_ok=True)
    inputs = [*sorted((ROOT / "research").glob("*.py")),
              ROOT / "research/requirements-research.txt", ROOT / "research/tools-manifest.json",
              ROOT / "profiles/kem1536-p0.toml", ROOT / "references/manifest.json"]
    provenance = {"created_utc": datetime.now(timezone.utc).isoformat(),
                  "python": platform.python_version(), "platform": platform.platform(),
                  "part": args.part, "input_sha256": {
                      str(path.relative_to(ROOT)).replace("\\", "/"):
                      hashlib.sha256(path.read_bytes()).hexdigest() for path in inputs}}
    definitions = scenarios()
    if args.part in ("noise", "all"):
        rows = []
        for definition in definitions:
            result = analyze(**definition["parameters"])
            secondary = crosscheck(definition["parameters"])
            difference = abs(result["historical_two_sided_union"]["log2"]-
                             secondary["log2_historical_two_sided_union"])
            if difference > 1e-6:
                raise ArithmeticError("exact and independent floating tail models disagree")
            rows.append({"id": definition["id"], **result, "crosscheck": secondary,
                         "crosscheck_log2_absolute_difference": difference})
            print(f"{definition['id']}: noise log2 union = "
                  f"{result['message_union_bound_uniform_bits']['log2']:.9f}", flush=True)
        write_json(destination / "noise.json", {"threshold_log2": -174.8, "results": rows})
    if args.part in ("attacks", "all"):
        selected = [s for s in definitions if s["id"] in
                    ("baseline-1024", "p0-1536", "q7681-eta2", "q7681-eta3")]
        attack_results = analyze_attacks(selected)
        write_json(destination / "attacks.json", attack_results)
        for result in attack_results["results"]:
            minima = {name: min(r["log2_core_svp_cost"] for r in result["attacks"]
                                if r["cost_model"] == name)
                      for name in ("classical", "quantum", "optimistic_quantum")}
            print(f"{result['id']}: minimum historical Core-SVP log2 costs {minima}", flush=True)
    provenance["output_sha256"] = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(destination.glob("*.json")) if path.name != "provenance.json"}
    write_json(destination / "provenance.json", provenance)


if __name__ == "__main__":
    main()
