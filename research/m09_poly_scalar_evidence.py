"""Bounded data-only verification of the single scalar-table prototype."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import struct
import tarfile
from pathlib import PurePosixPath

ROOT = Path(__file__).resolve().parents[1]


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def analyze(members):
    def read(name):
        return json.loads(members[name])

    prereg = read("preregistration.json")
    require(sha(members["protocol.md"]) == prereg["protocol_sha256"], "scalar protocol changed")
    require(sha(members["parent-source.json"]) == prereg["parent_manifest_sha256"], "parent snapshot changed")
    require(sha(members["baseline-source.json"]) == prereg["baseline_manifest_sha256"], "baseline manifest changed")
    for label in ("baseline", "candidate"):
        expected = read(label + "-source.json")["source_sha256"]
        actual = {n.removeprefix(label + "-source/"): sha(raw) for n, raw in members.items() if n.startswith(label + "-source/")}
        require(actual == expected, "scalar snapshot inventory changed")
    parent = read("parent-source.json")["source_sha256"]
    candidate = read("candidate-source.json")["source_sha256"]
    require(set(parent) == set(candidate), "scalar candidate closure changed")
    require({n for n in parent if parent[n] != candidate[n]} == {"crates/kem1536/src/engine_poly.rs"}, "scalar variant changed more than engine_poly")
    recovery = read("linux-resume-request.json")
    require(sha(members["measurement-controller-before-resume.py"]) == recovery["original_controller_sha256"], "original scalar control changed")
    require(sha(members["linux-0-baseline-micro-run.json"]) == recovery["preserved_run_sha256"], "preserved Linux record changed")
    require(sha(members["linux-0-baseline-micro.stderr"]) == recovery["preserved_stderr_sha256"], "preserved WSL warning changed")
    count, summaries = 0, {}
    for host in ("windows", "linux"):
        micro = f"candidate/{host}/micro" + (".exe" if host == "windows" else "")
        transform = members[f"candidate/{host}/transform.txt"].decode()
        require(not re.search(r"\b(?:xmm|ymm|zmm)\d+\b", transform), "vector register appeared in scalar transform")
        require(not re.search(r"\t(?:idiv|div)[bwlq]?\s", transform), "integer division appeared in scalar transform")
        for root in (5685, 5653):
            table = struct.pack("<255H", *[pow(root, offset * 256 // (2 * (1 << stage)), 7681)
                                            for stage in range(8) for offset in range(1 << stage)])
            require(members[micro].count(table) == 1, "exact public table not present once")
        runs = read(host + "-runs.json")
        expected_order = [(s, label, kind) for s in range(4)
                          for label in (("baseline", "candidate") if s % 2 == 0 else ("candidate", "baseline"))
                          for kind in ("micro", "kem")]
        require([(r["series"], r["label"], r["kind"]) for r in runs] == expected_order, "scalar AB/BA panel order differs")
        groups = {}
        for record in runs:
            label, kind, series = record["label"], record["kind"], record["series"]
            binary_name = f"{label}/{host}/{kind}" + (".exe" if host == "windows" else "")
            if label == "baseline":
                built_hash = read(f"baseline/{host}/build.json")[kind]["sha256"]
            else:
                build = read(f"candidate/{host}/{kind}-build.json")
                built_hash = build["binary_sha256"]
                require(build["source_manifest_sha256"] == sha(members["candidate-source.json"]), "scalar image source binding differs")
            require(sha(members[binary_name]) == built_hash == record["binary_sha256"], "scalar measurement image differs")
            raw = members[record["raw"]]
            require(sha(raw) == record["raw_sha256"] and record["exit_code"] == 0 and record["host"] == host, "scalar acquisition failed/changed")
            stderr = members[record["raw"].removesuffix(".jsonl") + ".stderr"].replace(b"\r\n", b"\n")
            require(stderr == b"" or (host == "linux" and stderr ==
                    b"wsl: Failed to start the systemd user session for 'majid'. See journalctl for more details.\n"), "unclassified scalar measurement stderr")
            rows = [json.loads(line) for line in raw.splitlines()]
            operations = ("forward", "inverse", "multiply_add") if kind == "micro" else ("keygen", "encaps", "decaps_valid", "decaps_rejected")
            samples = 500 if kind == "micro" else 250
            require(len(rows) == samples * len(operations), "scalar observation count differs")
            require({(r["operation"], r["iteration"]) for r in rows} == {(op, i) for op in operations for i in range(samples)}, "scalar observation grid differs")
            for row in rows:
                batch = row.get("batch", 1)
                require(type(row["nanoseconds"]) is int and row["nanoseconds"] > 0 and row["series"] == series, "invalid scalar duration/series")
                require(batch == (32 if kind == "micro" else 1), "scalar batch differs")
                groups.setdefault((label, row["operation"]), []).append(row["nanoseconds"] / batch)
            count += len(rows)
        panels = {}
        for (label, operation), values in groups.items():
            values.sort()
            panels.setdefault(operation, {})[label] = {"count": len(values), "median_ns": statistics.median(values),
                                                       "p95_ns": values[math.ceil(.95 * len(values)) - 1]}
        for operation, panel in panels.items():
            ratios = {n: panel["candidate"][n] / panel["baseline"][n] for n in ("median_ns", "p95_ns")}
            panel["ratios"] = ratios
            panel["kem_budget_passed"] = None if operation in ("forward", "inverse", "multiply_add") else ratios["median_ns"] <= 1.05 and ratios["p95_ns"] <= 1.20
        summaries[host] = panels
    failures = [f"{h}/{op}" for h, panels in summaries.items() for op, p in panels.items() if p["kem_budget_passed"] is False]
    gain = {host: any(p["ratios"]["median_ns"] <= .95 for p in panels.values() if p["kem_budget_passed"] is not None)
            for host, panels in summaries.items()}
    return {"observations": count, "KEM_latency_budgets_passed": not failures, "failed_KEM_panels": failures,
            "five_percent_gain_per_host": gain, "summary": summaries,
            "scope": "scalar prototype finite latency and micro image checks; final full images and erasure qualification separate"}


def verify_folder(folder):
    members = {p.relative_to(folder).as_posix(): p.read_bytes() for p in folder.rglob("*") if p.is_file()}
    return analyze(members)


def archive_members(path):
    members, total = {}, 0
    with tarfile.open(path, "r:gz") as archive:
        for item in archive:
            name = PurePosixPath(item.name)
            require(item.isfile() and not name.is_absolute() and ".." not in name.parts
                    and str(name) == item.name and item.name not in members and item.size <= 32_000_000,
                    "invalid scalar archive member")
            total += item.size
            require(total <= 100_000_000, "scalar archive expansion exceeds bound")
            members[item.name] = archive.extractfile(item).read()
    return members


def seal(folder, output):
    output.mkdir(parents=True, exist_ok=False)
    paths = sorted(p for p in folder.rglob("*") if p.is_file())
    hashes = {p.relative_to(folder).as_posix(): sha(p.read_bytes()) for p in paths}
    with tarfile.open(output / "acquisition.tar.gz", "x:gz", compresslevel=6) as archive:
        for path in paths:
            archive.add(path, arcname=path.relative_to(folder).as_posix(), recursive=False)
    members = archive_members(output / "acquisition.tar.gz")
    require({n: sha(raw) for n, raw in members.items()} == hashes, "scalar seal changed bytes")
    result = analyze(members)
    (output / "verification.json").write_text(json.dumps(result, indent=2) + "\n")
    (output / "provenance.json").write_text(json.dumps({"schema": 1, "members_sha256": hashes,
        "archive_sha256": sha((output / "acquisition.tar.gz").read_bytes()),
        "verification_sha256": sha((output / "verification.json").read_bytes()),
        "baseline_images_reused": True, "new_candidate_images": 4,
        "full_final_qualification_claimed": False}, indent=2) + "\n")


def verify_archive(folder):
    provenance = json.loads((folder / "provenance.json").read_text())
    require(sha((folder / "acquisition.tar.gz").read_bytes()) == provenance["archive_sha256"], "scalar archive hash differs")
    members = archive_members(folder / "acquisition.tar.gz")
    require({n: sha(raw) for n, raw in members.items()} == provenance["members_sha256"], "scalar archived inventory differs")
    result = analyze(members)
    require(sha((folder / "verification.json").read_bytes()) == provenance["verification_sha256"], "scalar stored result differs")
    require(result == json.loads((folder / "verification.json").read_text()), "scalar recalculated result differs")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--folder", type=Path, default=ROOT / "artifacts/generated/m09-poly-002")
    parser.add_argument("--save", type=Path)
    parser.add_argument("--seal", type=Path)
    parser.add_argument("--verify-archive", type=Path)
    args = parser.parse_args()
    if args.seal:
        seal(args.folder, args.seal)
    result = verify_archive(args.verify_archive or args.seal) if (args.verify_archive or args.seal) else verify_folder(args.folder)
    if args.save:
        with args.save.open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
    print(json.dumps(result, indent=2))
