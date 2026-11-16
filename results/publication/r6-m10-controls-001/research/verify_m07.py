"""Replay finite M07 evidence, distinguishing invalid data from missed budgets.

No local Git history, compiler, benchmark, fuzzing or executable is invoked.
Stack values are touched-byte observations in the recorded probe, not bounds.
"""
import argparse
from datetime import datetime
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

from run_m07 import BASELINE_CORE, MEMORY_OPERATIONS, OPERATIONS, summarize, validate_memory
from verify_r1_certificate_bridge import verify_static_contract

PROFILE = "KEM1536-DEV-Q7681-R1"
HOSTS = ("windows", "linux")
LABELS = ("baseline", "candidate")
PRIMARY = ("keygen", "encaps", "decaps_valid", "decaps_reject")
EXPECTED_BUDGETS = {
    "memory_repetitions_per_pattern": 20,
    "reference_latency_samples_per_operation_per_series": 200,
    "reference_latency_series": 5, "reference_latency_warmup": 25,
    "primary_stack_reduction_bytes": 2048, "import_stack_growth_budget_bytes": 512,
    "paired_latency_median_ratio_max": 1.10, "paired_latency_p95_ratio_max": 1.20,
    "paired_latency_samples": 1000, "paired_latency_series": 5,
    "paired_latency_warmup": 100, "paired_latency_cpu": 10,
}


class InvalidData(ValueError):
    """Evidence is incomplete, changed, inconsistent or outside its schema."""


def require(condition, message):
    if not condition:
        raise InvalidData(message)


def member(root, name):
    require(isinstance(name, str) and name and "\\" not in name,
            "invalid evidence member name")
    parts = name.split("/")
    require(not PurePosixPath(name).is_absolute() and all(p not in ("", ".", "..")
            and ":" not in p for p in parts), "evidence member escapes root")
    path = root
    for part in parts:
        path = path / part
        require(not path.is_symlink() and not getattr(path.lstat() if path.exists() else None,
                "st_file_attributes", 0) & 0x400, "evidence member traverses a link")
    require(path.resolve().is_relative_to(root.resolve()), "evidence member escapes root")
    return path


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"),
                      parse_constant=lambda value: (_ for _ in ()).throw(InvalidData("nonfinite JSON")))


def check_hashes(root, hashes):
    require(isinstance(hashes, dict) and hashes, "empty hash inventory")
    for name, checksum in hashes.items():
        require(isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum), "invalid SHA-256")
        require(sha(member(root, name)) == checksum, f"checksum differs: {name}")


def json_lines(raw):
    require(raw and raw.strip(), "empty observation stream")
    return [json.loads(line) for line in raw.splitlines()]


def checked_summary(saved, computed, label):
    require(saved == computed, f"saved summary differs: {label}")


def check_sources(out, acceptance, decision):
    require(acceptance.get("schema") == 1 and acceptance.get("profile") == PROFILE,
            "wrong acceptance identity")
    for key, expected in EXPECTED_BUDGETS.items():
        value = acceptance.get(key)
        require(type(value) is type(expected) and value == expected, f"declared budget changed: {key}")
    require(acceptance.get("new_binary_review_required") is True
            and acceptance.get("budget_is_operational_not_statistical_significance") is True,
            "acceptance scope flags differ")
    require(sha(out / "acceptance.json") == decision.get("acceptance_sha256"), "decision binding differs")
    require(re.fullmatch(r"[0-9a-f]{40,64}", decision.get("commit", "")), "invalid recorded decision commit")
    require(len(acceptance.get("baseline_file_sha256", {})) == 94, "baseline decision inventory differs")
    check_hashes(out, acceptance["baseline_file_sha256"])
    maps, contracts = {}, {}
    for label, expected_count in (("baseline", 39), ("candidate", 40)):
        manifest = read(out / f"{label}-source.json")
        require(manifest.get("profile") == PROFILE, "wrong source profile")
        hashes = manifest["source_sha256"]
        require(len(hashes) == expected_count, "compiled source inventory count differs")
        folder = out / f"{label}-source"
        actual = {path.relative_to(folder).as_posix() for path in folder.rglob("*") if path.is_file()}
        require(actual == set(hashes), "compiled source inventory differs")
        check_hashes(folder, hashes)
        maps[label] = hashes
        contracts[label] = verify_static_contract((folder / "crates/kem1536/src/dev_kem.rs").read_text("utf-8"))
    require(all(maps["baseline"][name] == checksum for name, checksum in BASELINE_CORE.items()),
            "baseline is not M06")
    require(contracts["baseline"]["realization"].startswith("M06-")
            and contracts["candidate"]["realization"].startswith("M07-"), "reviewed source contracts differ")
    allowed = {"crates/kem1536/src/dev_kem.rs", "research/run_m07.py"}
    require(set(maps["candidate"]) == set(maps["baseline"]) | {"docs/DECISION_M07_BUDGETS.md"},
            "candidate source surface differs")
    for name in set(maps["baseline"]) - allowed:
        require(maps["baseline"][name] == maps["candidate"][name], f"matched compiled input changed: {name}")
    require(maps["baseline"]["crates/kem1536/src/dev_kem.rs"] != maps["candidate"]["crates/kem1536/src/dev_kem.rs"],
            "candidate production source unchanged")
    candidate_manifest = read(out / "candidate-source.json")
    require(candidate_manifest["acceptance_sha256"] == decision["acceptance_sha256"], "candidate decision binding differs")
    before = datetime.fromisoformat(decision["recorded_utc"])
    after = datetime.fromisoformat(candidate_manifest["captured_utc"])
    require(before.tzinfo is not None and after.tzinfo is not None and before <= after,
            "candidate capture predates the recorded decision")
    return maps, contracts


def check_builds(out, label):
    builds = {}
    for host in HOSTS:
        data = read(out / label / host / "build.json")
        require(data["profile"] == PROFILE and data["host"] == host, "build identity differs")
        require(data["source_manifest_sha256"] == sha(out / f"{label}-source.json"), "build source binding differs")
        require(set(data["binaries"]) == {"probe", "latency", "research", "delivered"}, "build kinds differ")
        for kind, binary in data["binaries"].items():
            suffix = ".exe" if host == "windows" else ""
            require(binary["path"] == f"{label}/{host}/bin/{kind}{suffix}", "binary path differs")
            require(sha(member(out, binary["path"])) == binary["sha256"], "binary hash differs")
            target = "x86_64-pc-windows-gnu" if host == "windows" else "x86_64-unknown-linux-gnu"
            require("release: 1.91.1\n" in binary["rustc"] and f"host: {target}\n" in binary["rustc"],
                    "compiler identity differs")
            require(binary["emit_stack_metadata"] is (host == "linux" and kind == "probe"), "stack metadata scope differs")
            require(all(flag in binary["command"] for flag in ("--release", "--locked", "--offline")), "build flags differ")
        builds[host] = data["binaries"]
    return builds


def check_memory(out, label, host, binary, repetitions):
    folder = out / label / host
    raw = (folder / "memory.jsonl").read_bytes()
    receipt = read(folder / "memory-run.json")
    require(receipt["binary_sha256"] == binary["sha256"]
            and receipt["raw_sha256"] == hashlib.sha256(raw).hexdigest(), "memory run binding differs")
    require(receipt["command"][-1] == str(repetitions), "memory repetition command differs")
    if "exit_code" in receipt:
        require(type(receipt["exit_code"]) is int and receipt["exit_code"] == 0, "memory execution failed")
        errors = (folder / "memory.stderr").read_bytes()
        require(receipt["stderr_sha256"] == hashlib.sha256(errors).hexdigest(), "memory stderr differs")
    else:
        require(label == "baseline" and host == "windows", "missing memory exit receipt")
    rows = json_lines(raw)
    computed = validate_memory(rows, repetitions)
    checked_summary(read(folder / "memory-summary.json"), computed, f"memory/{label}/{host}")
    return computed, rows


def check_latency(folder, builds, labels, samples, warmup, series, cpu, host):
    schedule = read(folder / "schedule.json")
    require((schedule["samples"], schedule["warmup"], schedule["series"], schedule["CPU"])
            == (samples, warmup, series, cpu), "latency dimensions differ")
    for flag, value in (("OS_randomness_included", True), ("drop_and_validation_outside_timing", True),
                        ("frequency_fixed", False), ("physical_core_exclusive", False), ("host_activity_isolated", False)):
        require(schedule[flag] is value, "latency scope flag differs")
    expected = [(label, number) for number in range(series)
                for label in (labels if number % 2 == 0 else labels[::-1])]
    require([(row["version"], row["series"]) for row in schedule["schedule"]] == expected,
            "alternating latency schedule differs")
    rows = []
    previous_end = None
    for item in schedule["schedule"]:
        label, number = item["version"], item["series"]
        require(type(item["exit_code"]) is int and item["exit_code"] == 0, "latency execution failed")
        raw = gzip.decompress((folder / f"{label}-{number}.stdout.gz").read_bytes())
        errors = (folder / f"{label}-{number}.stderr").read_bytes()
        require(hashlib.sha256(raw).hexdigest() == item["stdout_sha256"]
                and hashlib.sha256(errors).hexdigest() == item["stderr_sha256"], "latency stream hash differs")
        command = item["command"]
        require(command[-3:] == list(map(str, (number, samples, warmup)))
                and any(part.replace("\\", "/").endswith(builds[label][host]["latency"]["path"])
                        for part in command), "latency executable/arguments differ")
        start, end = map(datetime.fromisoformat, (item["started_utc"], item["finished_utc"]))
        require(start.tzinfo is not None and end.tzinfo is not None and start <= end
                and (previous_end is None or previous_end <= start), "latency run times overlap or reverse")
        previous_end = end
        parsed = json_lines(raw)
        require(all(set(row) == {"operation", "series", "iteration", "nanoseconds"}
                    and row["series"] == number for row in parsed), "latency stdout schema differs")
        rows.extend(dict(version=label, **row) for row in parsed)
    retained = json_lines(gzip.decompress((folder / "observations.jsonl.gz").read_bytes()))
    require(retained == rows, "retained observations differ from actual stdout")
    computed = summarize(rows, labels, samples, series)
    checked_summary(read(folder / "statistics.json"), computed, f"latency/{host}")
    return computed


def compare_memory(summaries, raw, budgets):
    checks = []
    for host in HOSTS:
        base, candidate = (summaries[label][host] for label in LABELS)
        for operation in MEMORY_OPERATIONS:
            if operation == "noop" or operation.startswith("calibration_"):
                continue
            b, c = base[operation], candidate[operation]
            bstack, cstack = b["touched_stack_bytes"], c["touched_stack_bytes"]
            limit = (bstack["minimum"] - budgets["primary_stack_reduction_bytes"] if operation in PRIMARY
                     else bstack["maximum"] + budgets["import_stack_growth_budget_bytes"])
            checks.append({"host": host, "operation": operation, "metric": "touched_stack_maximum",
                           "candidate": cstack["maximum"], "limit": limit, "pass": cstack["maximum"] <= limit})
            for metric in ("total_requested_bytes", "peak_live_requested_bytes"):
                limit = b["requested_allocation_ranges"][metric][1]
                value = c["requested_allocation_ranges"][metric][1]
                checks.append({"host": host, "operation": operation, "metric": metric,
                               "candidate": value, "limit": limit, "pass": value <= limit})
            def attempts(label):
                return max(sum(row[key] for key in ("alloc_calls", "alloc_zeroed_calls", "realloc_calls"))
                           for row in raw[label][host] if row["operation"] == operation)
            value, limit = attempts("candidate"), attempts("baseline")
            checks.append({"host": host, "operation": operation, "metric": "allocation_attempts",
                           "candidate": value, "limit": limit, "pass": value <= limit})
            retained = "retained_requested_bytes_at_api_return"
            bvalues, cvalues = (set(row[retained] for row in raw[label][host] if row["operation"] == operation)
                                for label in LABELS)
            checks.append({"host": host, "operation": operation, "metric": retained,
                           "baseline": sorted(bvalues), "candidate": sorted(cvalues), "pass": cvalues == bvalues})
    return checks


def compare_latency(statistics_by_host, budgets):
    checks = []
    for host, data in statistics_by_host.items():
        for operation in OPERATIONS:
            for metric, key in (("median_ns", "paired_latency_median_ratio_max"), ("p95_ns", "paired_latency_p95_ratio_max")):
                baseline, candidate = (data[f"{label}/{operation}"][metric] for label in LABELS)
                limit = budgets[key]
                checks.append({"host": host, "operation": operation, "metric": metric,
                               "baseline": baseline, "candidate": candidate, "ratio": candidate / baseline,
                               "limit": limit, "pass": candidate <= baseline * limit})
    return checks


def check_regression(out, builds, candidate_sources):
    folder = out / "regression"
    data = read(folder / "summary.json")
    require(data["profile"] == PROFILE and data["constant_time_proved"] is False
            and set(data["platforms"]) == set(HOSTS), "regression scope differs")
    check_hashes(folder / "sources", data["source_sha256"])
    required = {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml", *BASELINE_CORE}
    require(required <= set(data["source_sha256"]), "regression compiled sources absent")
    for name in set(data["source_sha256"]) & set(candidate_sources):
        require(data["source_sha256"][name] == candidate_sources[name], "regression source differs from candidate")
    for host in HOSTS:
        row = data["platforms"][host]
        expected = builds["candidate"][host]["research"]["sha256"]
        require(data["binary_sha256"][host] == row["binary_sha256"] == expected, "regression binary differs")
        require(row["compared_to_frozen_M01"] == {"dev-vectors": 1000, "dev-rejection-vectors": 10000}
                and row["all_fields_equal"] is True and row["frozen_M02_mutations_compared"] == 10000
                and row["formats"]["inputs"] == 20000 and row["formats"]["panics_observed"] == 0,
                "complete regression panel required")
    require(data["platforms"]["windows"]["formats"] == data["platforms"]["linux"]["formats"], "regression formats disagree")
    return {"profile": PROFILE, "binary_sha256": data["binary_sha256"],
            "vectors_per_host": 1000, "rejections_per_host": 10000,
            "mutations_per_host": 10000, "formats_per_host": 20000}


def analyze(out):
    out = Path(out).resolve()
    try:
        acceptance, decision = read(out / "acceptance.json"), read(out / "decision-commit.json")
        sources, contracts = check_sources(out, acceptance, decision)
        builds = {label: check_builds(out, label) for label in LABELS}
        summaries, raw = {label: {} for label in LABELS}, {label: {} for label in LABELS}
        for label in LABELS:
            for host in HOSTS:
                summaries[label][host], raw[label][host] = check_memory(out, label, host, builds[label][host]["probe"], 20)
        reference, paired = {}, {}
        for host in HOSTS:
            reference[host] = check_latency(out / "reference-latency" / host, builds, ("baseline",), 200, 25, 5, 10, host)
            paired[host] = check_latency(out / "paired-latency" / host, builds, LABELS, 1000, 100, 5, 10, host)
        regression = check_regression(out, builds, sources["candidate"])
        checks = compare_memory(summaries, raw, acceptance) + compare_latency(paired, acceptance)
        return {"schema": 1, "profile": PROFILE, "data_valid": True,
                "candidate_within_budgets": all(row["pass"] for row in checks),
                "acceptance_sha256": sha(out / "acceptance.json"),
                "decision_commit": decision["commit"], "source_contracts": contracts,
                "source_manifest_sha256": {label: sha(out / f"{label}-source.json") for label in LABELS},
                "build_receipt_sha256": {f"{label}/{host}": sha(out / label / host / "build.json") for label in LABELS for host in HOSTS},
                "memory": summaries, "reference_latency": reference, "paired_latency": paired,
                "regression": regression, "budget_checks": checks,
                "scope": "Finite API-return observations and archived regression receipts; touched stack is not a stack bound, requested Rust heap is not RSS; no constant-time/erasure/security proof or new binary review is implied."}
    except InvalidData:
        raise
    except (OSError, LookupError, TypeError, ValueError, ArithmeticError, AttributeError) as error:
        raise InvalidData(f"invalid M07 evidence: {error}") from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("analyze", "verify"))
    parser.add_argument("--output", type=Path, required=True, help="M07 evidence directory")
    parser.add_argument("--report", type=Path, help="analyze: new report to save; verify: saved report to compare")
    args = parser.parse_args()
    try:
        report = analyze(args.output)
        if args.action == "analyze" and args.report:
            with args.report.open("x", encoding="utf-8", newline="\n") as stream:
                json.dump(report, stream, indent=2, allow_nan=False)
                stream.write("\n")
        if args.action == "verify":
            saved = args.report or args.output / "verification.json"
            require(not args.report or saved.is_file(), "requested saved report is absent")
            if saved.exists():
                checked_summary(read(saved), report, "M07 verification report")
        print(json.dumps(report, indent=2, allow_nan=False))
        if args.action == "verify" and not report["candidate_within_budgets"]:
            return 2
        return 0
    except InvalidData as error:
        print(json.dumps({"data_valid": False, "error": str(error)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
