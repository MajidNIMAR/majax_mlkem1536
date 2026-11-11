"""Offline M08 source/build, consumer, memory, latency and regression replay.

No Git, compiler, executable, disassembler, benchmark or fuzz campaign is run.
This checks finite evidence and operational budgets, not global security,
constant time, complete erasure or actual OS-affinity attestation.
"""
import argparse
from datetime import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from run_m08 import (CORE, CORE_OPERATIONS, IMPORT_OPERATIONS, MEMORY_OPERATIONS,
                     summarize, validate_memory)
from verify_m07 import (InvalidData, check_hashes, check_regression, checked_summary,
                        member, read, require, sha)
from verify_r1_certificate_bridge import verify_static_contract

PROFILE = "KEM1536-DEV-Q7681-R1"
HOSTS = ("windows", "linux")
LABELS = ("baseline", "candidate")
KINDS = ("probe", "consumer", "latency", "research", "delivered", "timing")
ACCEPTANCE_SHA = "8ee72adbff7d30d949d3959d2373a851f2fc32b3c9e3fa85515a9acc4befb097"
PLAN_SHA = "a4215680a48373f9643acc5f3fe30242ea47f8212563ee940c9b052444e799c2"
PREREG_COMMIT = "7ad56980df6c969d51e35b67dbf846c139f9d19a"
AFFINITY_SHA = "a88af4bf3f1294b99bc144f4788ead9ca3ad46e0983bfa29addf3767e80f999c"
CONTROL_CHANGE = ("Before paired acquisitions: save each attempt's command/exit/times, validate consumer scope/status. "
                  "Compiled inputs except dev_kem.rs and preregistered criteria remain identical.")
EXPECTED_ACCEPTANCE = dict(schema="m08-acceptance-v1", profile=PROFILE,
    memory_repetitions_per_pattern=20, memory_stack_max_growth_bytes=512,
    heap_request_increase_allowed=False, retained_output_bytes_must_match=True,
    paired_samples_per_operation_per_series=1000, paired_warmup=100, paired_series=5,
    CPU=10, median_ratio_max=1.10, p95_ratio_max=1.20, full_corpora_must_match=True,
    targeted_import_spill_review_required=True, universal_erasure_or_constant_time_claimed=False)
SOURCE_NAMES = set(""".cargo/config.toml
Cargo.lock
Cargo.toml
crates/kem1024-reference/Cargo.toml
crates/kem1024-reference/src/lib.rs
crates/kem1536/Cargo.toml
crates/kem1536/src/dev_hardening.rs
crates/kem1536/src/dev_kem.rs
crates/kem1536/src/engine_poly.rs
crates/kem1536/src/lib.rs
crates/kem1536/src/reference_ring.rs
crates/kem1536/src/secret_box.rs
crates/kem1536/tests/delivery_contract.rs
crates/kem1536-bench/Cargo.toml
crates/kem1536-bench/src/bin/m03-replay.rs
crates/kem1536-bench/src/bin/m06-measure.rs
crates/kem1536-bench/src/bin/m06-replay.rs
crates/kem1536-bench/src/bin/m07-measure.rs
crates/kem1536-bench/src/delivery.rs
crates/kem1536-bench/src/main.rs
crates/kem1536-cli/Cargo.toml
crates/kem1536-cli/src/main.rs
crates/kem1536-cli/tests/commands.rs
docs/PROTOCOLE_M08_IMPORTS.md
fuzz/fixtures/cases.bin
profiles/kem1536-p0.toml
references/manifest.json
research/m08-acceptance.json
research/m08-fuzz-plan.json
research/m08-import-consumer/Cargo.lock
research/m08-import-consumer/Cargo.toml
research/m08-import-consumer/README.md
research/m08-import-consumer/src/main.rs
research/m08-memory-probe/Cargo.lock
research/m08-memory-probe/Cargo.toml
research/m08-memory-probe/README.md
research/m08-memory-probe/src/main.rs
research/run_m07.py
research/run_m08.py
rust-toolchain.toml
vectors/nist-acvp/ML-KEM-encapDecap-FIPS203/expectedResults.json
vectors/nist-acvp/ML-KEM-encapDecap-FIPS203/prompt.json
vectors/nist-acvp/ML-KEM-encapDecap-FIPS203-tr1/expectedResults.json
vectors/nist-acvp/ML-KEM-encapDecap-FIPS203-tr1/prompt.json
vectors/nist-acvp/ML-KEM-keyGen-FIPS203/expectedResults.json
vectors/nist-acvp/ML-KEM-keyGen-FIPS203/prompt.json""".splitlines())
FIXTURE = dict(encoding_bytes_printed=False,
    kind="deterministic synthetic structural encodings; not a generated KEM key pair",
    private_sha3_256="d9fa8ca0a1ecf13ce7f168fdc9dc5dcbe4120f0de38eea9f1678527509fcf465",
    public_sha3_256="bd26b3e8db2f105b3881b9f1d6319f53b43ad4b98893e31a7e0a67680ee8ab16")


def file_names(folder):
    require(folder.is_dir(), "evidence directory missing: " + str(folder))
    require(not folder.is_symlink() and not getattr(folder.lstat(), "st_file_attributes", 0) & 0x400,
            "evidence directory is a link")
    result = set()
    for parent, directories, files in os.walk(folder, followlinks=False):
        for name in directories + files:
            path = Path(parent) / name
            require(not path.is_symlink() and not getattr(path.lstat(), "st_file_attributes", 0) & 0x400,
                    "evidence inventory traverses a link")
        for name in files:
            require(stat.S_ISREG((Path(parent) / name).lstat().st_mode), "evidence member is not a regular file")
        result.update((Path(parent) / name).relative_to(folder).as_posix() for name in files)
    return result


def parsed(raw):
    require(raw and raw.strip(), "empty observation stream")
    return [json.loads(line, parse_constant=lambda x: (_ for _ in ()).throw(InvalidData("nonfinite JSON")))
            for line in raw.splitlines()]


def moment(value):
    result = datetime.fromisoformat(value)
    require(result.tzinfo is not None and result.utcoffset() is not None, "timestamp lacks timezone")
    return result


def runtime_stderr(errors, host):
    if not errors:
        return
    known = b"wsl: Failed to start the systemd user session for 'majid'. See journalctl for more details.\n"
    require(host == "linux" and errors in (known, known.replace(b"\n", b"\r\n")),
            "unclassified runtime stderr; raw diagnostic must be reviewed")


def exact_fields(value, expected, message):
    require(isinstance(value, dict) and set(value) == set(expected), message)
    def equal(a, b):
        if type(a) is not type(b):
            return False
        if isinstance(b, dict):
            return set(a) == set(b) and all(equal(a[k], v) for k, v in b.items())
        if isinstance(b, list):
            return len(a) == len(b) and all(equal(x, y) for x, y in zip(a, b, strict=True))
        return a == b
    require(equal(value, expected), message)


def status_for(operation):
    return 0 if operation in ("public_valid", "private_valid") else (
        1 if operation in ("public_short", "private_short") else 3 if operation == "private_hash_invalid" else 2)


def matched_sources(maps, manifests):
    require(set(maps["baseline"]) == set(maps["candidate"]) == SOURCE_NAMES,
            "matched source surface is not the exact 46 inputs")
    for name, checksum in CORE.items():
        require(maps["baseline"][name] == checksum, "baseline core is not M07")
    require(maps["baseline"]["crates/kem1536/src/secret_box.rs"] ==
            "08d6ba7accadb46dc66b780a396dc418950641b29a91d365e12537001c40d28e", "baseline secret owner differs")
    allowed = {"crates/kem1536/src/dev_kem.rs", "research/run_m08.py"}
    for name in SOURCE_NAMES - allowed:
        require(maps["baseline"][name] == maps["candidate"][name], "matched compiled/preregistered input changed: " + name)
    require(maps["baseline"]["crates/kem1536/src/dev_kem.rs"] != maps["candidate"]["crates/kem1536/src/dev_kem.rs"],
            "production candidate unchanged")
    require(manifests["baseline"].get("measurement_control_change") is None
            and manifests["candidate"].get("measurement_control_change") == CONTROL_CHANGE,
            "acquisition control change lacks the declared scope")


def check_sources(out):
    acceptance, decision = read(out / "m08-acceptance.json"), read(out / "decision-commit.json")
    exact_fields(acceptance, EXPECTED_ACCEPTANCE, "preregistered acceptance values/types differ")
    require(sha(out / "m08-acceptance.json") == decision["acceptance_sha256"] == ACCEPTANCE_SHA
            and sha(out / "m08-fuzz-plan.json") == decision["fuzz_plan_sha256"] == PLAN_SHA
            and decision["commit"] == PREREG_COMMIT, "preregistration hash/commit binding differs")
    helper = read(out / "helper-bindings.json")
    exact_fields(helper, dict(prereg_commit=PREREG_COMMIT, helper="research/capture_m07_timing.py",
                 sha256=AFFINITY_SHA, matches_preregistered_git_blob=True, os_affinity_attestation=False),
                 "affinity helper declaration differs")
    maps, manifests, contracts = {}, {}, {}
    for label in LABELS:
        data = read(out / (label + "-source.json"))
        require(data["profile"] == PROFILE and re.fullmatch(r"[0-9a-f]{40}", data["head_commit"]), "source identity differs")
        require(data["preregistered_acceptance_sha256"] == ACCEPTANCE_SHA and data["fuzz_plan_sha256"] == PLAN_SHA,
                "source preregistration binding differs")
        folder = out / (label + "-source")
        require(file_names(folder) == set(data["source_sha256"]) == SOURCE_NAMES, "source file inventory differs")
        check_hashes(folder, data["source_sha256"])
        maps[label], manifests[label] = data["source_sha256"], data
        contracts[label] = verify_static_contract((folder / "crates/kem1536/src/dev_kem.rs").read_text(encoding="utf-8"))
        require(data["source_sha256"]["research/m08-acceptance.json"] == ACCEPTANCE_SHA
                and data["source_sha256"]["research/m08-fuzz-plan.json"] == PLAN_SHA, "captured criteria/plan differ")
    matched_sources(maps, manifests)
    require(contracts["baseline"] == dict(realization="M07-destination-owned-NTT-streamed-1", reviewed_source_anchors=35,
            formal_program_verification=False) and contracts["candidate"] == dict(realization="M08-direct-encoding-NTT-streamed-1",
            reviewed_source_anchors=36, formal_program_verification=False), "reviewed source realization differs")
    require(manifests["baseline"]["head_commit"] == PREREG_COMMIT
            and moment(manifests["baseline"]["captured_utc"]) <= moment(manifests["candidate"]["captured_utc"]),
            "baseline/candidate source chronology differs")
    return acceptance, maps, manifests, contracts


def recipe(command, label, host, kind):
    require(isinstance(command, list) and all(type(x) is str and x for x in command), "invalid build command")
    cmd = [part.replace("\\", "/") for part in command]
    require(cmd.count("build") == 1, "one Cargo build required")
    index = cmd.index("build")
    expected_cargo = "/.tools/cargo/bin/cargo.exe" if host == "windows" else "/.tools/linux-cargo/bin/cargo"
    require(cmd[index - 1].endswith(expected_cargo), "unexpected compiler driver")
    historic_root = cmd[index - 1][:-len(expected_cargo)]
    selection = {"latency": ["-p", "kem1536-bench", "--bin", "m07-measure"],
        "research": ["-p", "kem1536-cli", "--bin", "kem1536", "--features", "research-vectors"],
        "delivered": ["-p", "kem1536-cli", "--bin", "kem1536"],
        "timing": ["-p", "kem1536-bench", "--bin", "kem1536-bench"]}
    if kind in ("probe", "consumer"):
        workspace = "m08-memory-probe" if kind == "probe" else "m08-import-consumer"
        tail = ["--manifest-path", historic_root + f"/artifacts/generated/m08-001/{label}-source/research/{workspace}/Cargo.toml"]
    else:
        tail = selection[kind]
    require(cmd[index:] == ["build", "--release", "--locked", "--offline", *tail], "build selection/features differ")
    if host == "windows":
        require(index == 1, "Windows compiler wrapper differs")
    else:
        require(cmd[:6] == ["wsl", "-d", "Ubuntu-22.04", "--", "env", "-i"], "Linux clean environment wrapper differs")
        expected = {"CARGO_HOME": historic_root + "/.tools/linux-cargo", "RUSTUP_HOME": historic_root + "/.tools/linux-rustup",
            "RUSTUP_TOOLCHAIN": "1.91.1-x86_64-unknown-linux-gnu", "RUSTUP_AUTO_INSTALL": "0", "CARGO_BUILD_JOBS": "2",
            "CARGO_TARGET_DIR": historic_root + f"/target/m08-001/{label}/linux",
            "PATH": historic_root + "/.tools/linux-cargo/bin:/usr/local/bin:/usr/bin:/bin"}
        if kind == "probe":
            expected.update(RUSTC_BOOTSTRAP="1", RUSTFLAGS="-Zemit-stack-sizes")
        assignments = cmd[6:index - 1]
        require(all("=" in item for item in assignments), "invalid Linux environment assignment")
        actual = dict(item.split("=", 1) for item in assignments)
        require(len(actual) == len(assignments) and actual == expected, "Linux build environment/target differs")


def check_builds(out, label, sources, manifest):
    result, built = {}, {}
    for host in HOSTS:
        folder = out / label / host
        data = read(folder / "build.json")
        require(data["profile"] == PROFILE and data["host"] == host
                and data["source_manifest_sha256"] == sha(out / (label + "-source.json"))
                and data["controller_sha256"] == sources["research/run_m08.py"]
                and data["shared_dependency_target_within_label_and_host"] is True, "build recipe/source chain differs")
        require(set(data["binaries"]) == set(KINDS), "six binary kinds required")
        suffix = ".exe" if host == "windows" else ""
        require(file_names(folder / "bin") == {kind + suffix for kind in KINDS}, "binary file inventory differs")
        target = "x86_64-pc-windows-gnu" if host == "windows" else "x86_64-unknown-linux-gnu"
        for kind, row in data["binaries"].items():
            require(row["path"] == f"{label}/{host}/bin/{kind}{suffix}", "binary path differs")
            require(sha(member(out, row["path"])) == row["sha256"], "binary hash differs")
            require(type(row["rustc"]) is str and "release: 1.91.1\n" in row["rustc"]
                    and f"host: {target}\n" in row["rustc"], "compiler identity differs")
            require(row["emit_stack_metadata"] is (host == "linux" and kind == "probe"), "stack metadata flags differ")
            require((folder / (kind + "-build.log")).is_file(), "build log absent")
            recipe(row["command"], label, host, kind)
        built[host] = moment(data["built_utc"])
        require(moment(manifest["captured_utc"]) <= built[host], "build predates source capture")
        result[host] = data["binaries"]
    return result, built


def execution(command, host, binary_path, arguments, cpu=None):
    require(isinstance(command, list) and all(type(x) is str and x for x in command), "invalid execution command")
    prefix = [] if host == "windows" else ["wsl", "-d", "Ubuntu-22.04", "--"]
    if host == "linux" and cpu is not None:
        prefix += ["taskset", "-c", str(cpu)]
    require(command[:len(prefix)] == prefix and len(command) == len(prefix) + 1 + len(arguments), "execution wrapper differs")
    path = command[len(prefix)].replace("\\", "/")
    require(path.endswith("/" + binary_path) and command[len(prefix) + 1:] == list(map(str, arguments)),
            "execution binary/arguments differ")


def check_memory(out, label, host, binary, built, repetitions=20):
    folder = out / label / host
    raw, errors = (folder / "memory.jsonl").read_bytes(), (folder / "memory.stderr").read_bytes()
    data = read(folder / "memory-run.json")
    runtime_stderr(errors, host)
    require(type(data["exit_code"]) is int and data["exit_code"] == 0
            and data["binary_sha256"] == binary["sha256"] and data["raw_sha256"] == hashlib.sha256(raw).hexdigest()
            and data["stderr_sha256"] == hashlib.sha256(errors).hexdigest(), "memory stream/run binding differs")
    execution(data["command"], host, binary["path"], [repetitions])
    require(moment(data["executed_utc"]) >= built, "memory acquisition predates build")
    rows = parsed(raw)
    computed = validate_memory(rows, repetitions)
    checked_summary(read(folder / "memory-summary.json"), computed, "M08 memory")
    return computed, rows


def check_consumer(out, label, host, binary, built):
    folder = out / label / host / "validation"
    modes = ("smoke", "fixture-digests", "exhaustive")
    require(file_names(folder) == {mode + suffix for mode in modes for suffix in (".stdout", ".stderr", ".json")},
            "consumer validation file inventory differs")
    results = {}
    for mode in modes:
        raw, errors = (folder / (mode + ".stdout")).read_bytes(), (folder / (mode + ".stderr")).read_bytes()
        data = read(folder / (mode + ".json"))
        runtime_stderr(errors, host)
        require(type(data["exit_code"]) is int and data["exit_code"] == 0
                and data["binary_sha256"] == binary["sha256"] and data["stdout_sha256"] == hashlib.sha256(raw).hexdigest()
                and data["stderr_sha256"] == hashlib.sha256(errors).hexdigest(), "consumer output/run binding differs")
        execution(data["command"], host, binary["path"], [mode])
        require(moment(data["executed_utc"]) >= built, "consumer validation predates build")
        require(len(parsed(raw)) == 1 and parsed(raw)[0] == data["data"], "consumer retained JSON differs from stdout")
        results[mode] = data["data"]
    exact_fields(results["fixture-digests"], FIXTURE, "synthetic fixture digests differ")
    smoke, exhaustive = results["smoke"], results["exhaustive"]
    expected_smoke = dict(schema=1, profile=PROFILE, host=host, architecture="x86_64",
        research_vectors_feature_requested=False, fixtures=FIXTURE,
        fresh_imported_key_round_trips=1, fresh_rejections=1, repeat_rejection_equal=True,
        fresh_private_with_fixed_z_imported=True, fixed_z_import_is_syntax_not_entropy_validation=True, secrets_printed=False)
    exact_fields({k: v for k, v in smoke.items() if k != "cases"}, expected_smoke, "consumer smoke scope differs")
    expected_ops = IMPORT_OPERATIONS + ("public_short", "private_short")
    require(len(smoke["cases"]) == len(expected_ops), "consumer smoke case count differs")
    for operation, case in zip(expected_ops, smoke["cases"], strict=True):
        exact_fields(case, dict(operation=operation, status=status_for(operation), expected=status_for(operation)),
                     "consumer smoke statuses/order differ")
    exact_fields(exhaustive, dict(schema=1, profile=PROFILE, mode="exhaustive single-coefficient probes",
        fixture=FIXTURE, single_coefficient_value_alignment_cases=65536, boundary_position_cases=23040,
        total_cases=88576, complete_vector_space_exhausted=False,
        all_expected_statuses_and_accepted_encodings_match=True, formal_program_verification=False, secrets_printed=False),
        "consumer exhaustive coverage/status scope differs")
    return dict(binary_sha256=binary["sha256"], exhaustive_cases=88576, fixture=FIXTURE,
                fresh_imported_key_round_trips=1, fresh_rejections=1, fixed_z_import_is_syntax_not_entropy_validation=True)


def check_latency(folder, builds, built, host, kind, controller_sha, samples=1000, warmup=100, series=5, cpu=10):
    operations = CORE_OPERATIONS if kind == "latency" else IMPORT_OPERATIONS
    identities = [(label, number) for number in range(series) for label in (LABELS if number % 2 == 0 else LABELS[::-1])]
    expected_files = {f"{label}-{number}{suffix}" for label, number in identities
                      for suffix in (".stdout.gz", ".stderr", ".attempt.json")}
    require(file_names(folder) == expected_files | {"schedule.json", "statistics.json", "observations.jsonl.gz"},
            "paired panel file inventory differs")
    schedule = read(folder / "schedule.json")
    expected_scope = dict(samples=samples, warmup=warmup, series=series, CPU=cpu, operations=list(operations),
        frequency_fixed=False, host_wide_isolation_proved=False, drop_and_validation_outside_timing=True)
    exact_fields({k: v for k, v in schedule.items() if k != "schedule"}, expected_scope, "paired panel scope differs")
    require(len(schedule["schedule"]) == len(identities), "paired schedule incomplete")
    rows, previous_end = [], None
    for item, (label, number) in zip(schedule["schedule"], identities, strict=True):
        require(item["version"] == label and type(item["series"]) is int and item["series"] == number,
                "paired AB/BA series schedule differs")
        raw = gzip.decompress((folder / f"{label}-{number}.stdout.gz").read_bytes())
        errors = (folder / f"{label}-{number}.stderr").read_bytes()
        runtime_stderr(errors, host)
        require(type(item["exit_code"]) is int and item["exit_code"] == 0
                and item["stdout_sha256"] == hashlib.sha256(raw).hexdigest()
                and item["stderr_sha256"] == hashlib.sha256(errors).hexdigest(), "paired raw stream/run binding differs")
        binary = builds[label][host][kind]
        arguments = [number, samples, warmup] if kind == "latency" else ["latency", number, samples, warmup]
        execution(item["command"], host, binary["path"], arguments, cpu if host == "linux" else None)
        start, end = moment(item["started_utc"]), moment(item["finished_utc"])
        require(built[label][host] <= start <= end and (previous_end is None or previous_end <= start),
                "paired acquisitions overlap, reverse or predate builds")
        previous_end = end
        attempt = read(folder / f"{label}-{number}.attempt.json")
        require(set(attempt) == {"version", "series", "command", "binary_sha256", "started_utc", "finished_utc",
                "exit_code", "stdout_sha256", "stderr_sha256", "controller_sha256"}, "paired attempt schema differs")
        for key in ("version", "series", "command", "started_utc", "exit_code", "stdout_sha256", "stderr_sha256"):
            require(type(attempt[key]) is type(item[key]) and attempt[key] == item[key], "attempt/schedule metadata differs")
        require(attempt["binary_sha256"] == binary["sha256"] and attempt["controller_sha256"] == controller_sha
                and start <= moment(attempt["finished_utc"]) <= end, "attempt executable/controller/time binding differs")
        data = parsed(raw)
        schema = {"operation", "series", "iteration", "nanoseconds"}
        if kind == "consumer":
            schema |= {"schema", "profile", "status", "expected_status", "validation_and_drop_outside_timer", "secrets_printed"}
        for row in data:
            require(set(row) == schema and type(row["series"]) is int and row["series"] == number,
                    "paired stdout schema/series differs")
            if kind == "consumer":
                require(type(row["schema"]) is int and row["schema"] == 1 and row["profile"] == PROFILE
                        and type(row["status"]) is int and type(row["expected_status"]) is int
                        and row["status"] == row["expected_status"] == status_for(row["operation"])
                        and row["validation_and_drop_outside_timer"] is True and row["secrets_printed"] is False,
                        "paired import status/profile/flags differ")
            rows.append(dict(version=label, **row))
    retained = parsed(gzip.decompress((folder / "observations.jsonl.gz").read_bytes()))
    require(retained == rows, "enriched observations differ from actual paired stdout")
    computed = summarize(rows, operations, LABELS, samples, series)
    checked_summary(read(folder / "statistics.json"), computed, "M08 paired " + kind)
    return computed


def compare_memory(summaries, raw, budgets):
    checks = []
    for host in HOSTS:
        for op in MEMORY_OPERATIONS:
            if op.startswith("calibration_"):
                continue
            b, c = (summaries[label][host][op] for label in LABELS)
            checks.append(dict(host=host, operation=op, metric="touched_stack_maximum",
                baseline=b["touched_stack_bytes"]["maximum"], candidate=c["touched_stack_bytes"]["maximum"],
                limit=b["touched_stack_bytes"]["maximum"] + budgets["memory_stack_max_growth_bytes"],
                pass_=c["touched_stack_bytes"]["maximum"] <= b["touched_stack_bytes"]["maximum"] + budgets["memory_stack_max_growth_bytes"]))
            for metric in ("total_requested_bytes", "peak_live_requested_bytes"):
                value, limit = c["requested_allocation_ranges"][metric][1], b["requested_allocation_ranges"][metric][1]
                checks.append(dict(host=host, operation=op, metric=metric, candidate=value, limit=limit, pass_=value <= limit))
            counts = {label: max(sum(row[k] for k in ("alloc_calls", "alloc_zeroed_calls", "realloc_calls"))
                                for row in raw[label][host] if row["operation"] == op) for label in LABELS}
            checks.append(dict(host=host, operation=op, metric="allocation_attempts", candidate=counts["candidate"],
                               limit=counts["baseline"], pass_=counts["candidate"] <= counts["baseline"]))
            retained = {label: sorted({row["retained_requested_bytes_at_api_return"] for row in raw[label][host]
                                     if row["operation"] == op}) for label in LABELS}
            checks.append(dict(host=host, operation=op, metric="retained_requested_bytes_at_api_return",
                baseline=retained["baseline"], candidate=retained["candidate"], pass_=retained["baseline"] == retained["candidate"]))
    return [dict(("pass" if k == "pass_" else k, v) for k, v in row.items()) for row in checks]


def compare_latency(panels, operations, budgets, kind):
    checks = []
    for host, stats in panels.items():
        for op in operations:
            for metric, budget in (("median_ns", "median_ratio_max"), ("p95_ns", "p95_ratio_max")):
                b, c = (stats[label + "/" + op][metric] for label in LABELS)
                checks.append({"host": host, "panel": kind, "operation": op, "metric": metric,
                    "baseline": b, "candidate": c, "ratio": c / b, "limit": budgets[budget], "pass": c <= b * budgets[budget]})
    return checks


def analyze(out):
    out = Path(out).resolve()
    try:
        budgets, sources, manifests, contracts = check_sources(out)
        builds, built = {}, {}
        for label in LABELS:
            builds[label], built[label] = check_builds(out, label, sources[label], manifests[label])
        summaries, raw, consumers = ({label: {} for label in LABELS} for _ in range(3))
        for label in LABELS:
            for host in HOSTS:
                summaries[label][host], raw[label][host] = check_memory(out, label, host, builds[label][host]["probe"], built[label][host])
                consumers[label][host] = check_consumer(out, label, host, builds[label][host]["consumer"], built[label][host])
        core, imports = {}, {}
        for host in HOSTS:
            for name, kind, result in (("paired-latency", "latency", core), ("paired-imports", "consumer", imports)):
                result[host] = check_latency(out / name / host, builds, built, host, kind,
                                             sources["candidate"]["research/run_m08.py"])
        regression_data = read(out / "regression/summary.json")
        require(file_names(out / "regression/sources") == set(regression_data["source_sha256"]), "regression source inventory differs")
        regression = check_regression(out, builds, sources["candidate"])
        checks = (compare_memory(summaries, raw, budgets) + compare_latency(core, CORE_OPERATIONS, budgets, "core")
                  + compare_latency(imports, IMPORT_OPERATIONS, budgets, "imports"))
        stderr_paths = [(f"{label}/{host}/memory.stderr", host) for label in LABELS for host in HOSTS]
        stderr_paths += [(f"{label}/{host}/validation/{mode}.stderr", host) for label in LABELS for host in HOSTS
                         for mode in ("smoke", "fixture-digests", "exhaustive")]
        stderr_paths += [(f"{panel}/{host}/{label}-{number}.stderr", host) for panel in ("paired-latency", "paired-imports")
                         for host in HOSTS for label in LABELS for number in range(5)]
        diagnostics = []
        for name, host in stderr_paths:
            errors = member(out, name).read_bytes()
            runtime_stderr(errors, host)
            if errors:
                diagnostics.append(dict(path=name, sha256=hashlib.sha256(errors).hexdigest(),
                    classification="retained WSL launcher systemd-user-session warning; engine exited 0 with complete validated output"))
        return dict(schema="m08-measurement-evaluation-v1", profile=PROFILE, data_valid=True,
            candidate_within_budgets=all(row["pass"] for row in checks), acceptance_sha256=ACCEPTANCE_SHA,
            preregistered_commit=PREREG_COMMIT, source_contracts=contracts,
            source_manifest_sha256={label: sha(out / (label + "-source.json")) for label in LABELS},
            build_receipt_sha256={label + "/" + host: sha(out / label / host / "build.json") for label in LABELS for host in HOSTS},
            memory=summaries, paired_core=core, paired_imports=imports, consumer_validation=consumers,
            regression=regression, budget_checks=checks, runtime_stderr_diagnostics=diagnostics,
            scope="Finite API-return observations, consumer checks and archived full regressions. Touched-stack is not a stack bound; requested Rust heap is not RSS. CPU10/affinity recipes are recorded, without OS attestation. No new execution, binary review, full CT/erasure or global cryptographic-security proof is implied.")
    except InvalidData:
        raise
    except (OSError, LookupError, TypeError, ValueError, ArithmeticError, AttributeError) as error:
        raise InvalidData("invalid M08 evidence: " + str(error)) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("analyze", "verify"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    try:
        report = analyze(args.output)
        if args.action == "analyze" and args.report:
            with args.report.open("x", encoding="utf-8", newline="\n") as stream:
                json.dump(report, stream, indent=2, allow_nan=False)
                stream.write("\n")
        if args.action == "verify" and args.report:
            checked_summary(read(args.report), report, "M08 measurements")
        print(json.dumps(report, indent=2, allow_nan=False))
        return 2 if args.action == "verify" and not report["candidate_within_budgets"] else 0
    except InvalidData as error:
        print(json.dumps(dict(data_valid=False, error=str(error))))
        return 1


if __name__ == "__main__":
    sys.exit(main())
