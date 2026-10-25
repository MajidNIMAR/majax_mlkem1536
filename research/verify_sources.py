"""Verify frozen sources and independently identify ACVP rejection cases."""

from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import tomllib


def verify() -> dict:
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "references/manifest.json").read_text(encoding="utf-8"))
    if manifest["schema_version"] != 1:
        raise ValueError("unsupported source-manifest schema")
    recorded_paths = set()
    for entry in manifest["files"]:
        path = (root / entry["path"]).resolve()
        if not path.is_relative_to(root) or entry["path"] in recorded_paths:
            raise ValueError("invalid or duplicate source path")
        recorded_paths.add(entry["path"])
        content = path.read_bytes()
        if len(content) != entry["bytes"] or hashlib.sha256(content).hexdigest() != entry["sha256"]:
            raise ValueError(f"source integrity mismatch: {entry['path']}")
    lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
    selected = [p for p in lock["package"] if p["name"] == "ml-kem"]
    reference = manifest["reference_implementation"]
    if len(selected) != 1 or selected[0]["version"] != reference["version"]:
        raise ValueError("reference implementation version mismatch")
    if selected[0]["checksum"] != reference["crate_sha256"]:
        raise ValueError("reference implementation checksum mismatch")
    coverage = Counter()
    rejections = 0
    sets = ["ML-KEM-keyGen-FIPS203", "ML-KEM-encapDecap-FIPS203",
            "ML-KEM-encapDecap-FIPS203-tr1"]
    for dataset in sets:
        directory = root / "vectors/nist-acvp" / dataset
        prompt = json.loads((directory / "prompt.json").read_text(encoding="utf-8"))
        expected = json.loads((directory / "expectedResults.json").read_text(encoding="utf-8"))
        for field in ["vsId", "algorithm", "mode", "revision"]:
            if prompt[field] != expected[field]:
                raise ValueError(f"mismatched vector metadata: {dataset}/{field}")
        answers = {g["tgId"]: {t["tcId"]: t for t in g["tests"]} for g in expected["testGroups"]}
        for group in prompt["testGroups"]:
            if group["parameterSet"] != "ML-KEM-1024":
                continue
            function = "keyGen" if prompt["mode"] == "keyGen" else group["function"]
            coverage[function] += len(group["tests"])
            ids = [t["tcId"] for t in group["tests"]]
            if len(set(ids)) != len(ids) or set(ids) != set(answers[group["tgId"]]):
                raise ValueError("incomplete or duplicate official answers")
            if function == "decapsulation":
                for test in group["tests"]:
                    z = bytes.fromhex(test["z"]) if "z" in test else bytes.fromhex(test["dk"])[-32:]
                    fallback = hashlib.shake_256(z + bytes.fromhex(test["c"])).digest(32)
                    expected_key = bytes.fromhex(answers[group["tgId"]][test["tcId"]]["k"])
                    rejections += int(fallback == expected_key)
    required = dict(keyGen=25, encapsulation=50, decapsulation=30,
                    decapsulationKeyCheck=20, encapsulationKeyCheck=20)
    if dict(coverage) != required or rejections != 15:
        raise ValueError("unexpected official vector coverage")
    return {"source_integrity": "passed", "frozen_files": len(recorded_paths),
            "reference_crate": f"ml-kem {reference['version']}",
            "acvp_source_commit": manifest["acvp_source_commit"],
            "selected_parameter_set": "ML-KEM-1024", "coverage": dict(coverage),
            "total_selected_cases": sum(coverage.values()),
            "implicit_rejection_cases": rejections}


if __name__ == "__main__":
    try:
        print(json.dumps(verify(), indent=2))
    except (ValueError, KeyError, OSError) as error:
        print(f"Source verification failed: {error}", file=sys.stderr)
        sys.exit(1)
