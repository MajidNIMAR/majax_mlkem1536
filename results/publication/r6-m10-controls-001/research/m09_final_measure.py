"""Full M09 KEM comparison, distinct from the isolated NTT campaign.

Criteria are fixed in PROTOCOLE_M09_QUALIFICATION before these acquisitions.
The verifier recomputes every grid/statistic and memory budget from raw data.
"""
import argparse
from collections import defaultdict
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import shutil
import statistics
import subprocess

from run_m07 import linux, linux_prefix, read, require, save, sha, utc, windows_environment
from capture_m07_timing import affinity
from validate_hardening_m02 import command
from run_m08 import validate_memory, MEMORY_OPERATIONS

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts/generated/m09-final-001"
BASE = ROOT / "artifacts/generated/m09-poly-001"
OPS = ("keygen", "encaps", "decaps_valid", "decaps_rejected")
ALLOC = ("alloc_calls", "alloc_zeroed_calls", "realloc_calls", "dealloc_calls", "total_requested_bytes",
         "retained_requested_bytes_at_api_return", "peak_live_requested_bytes")
M08_CORE = {
    "crates/kem1536/src/dev_kem.rs": "b39c2fdfcdd7c22634162a2c451213a6c4309b27524a82069f37903653e12334",
    "crates/kem1536/src/engine_poly.rs": "ffe7b50dfebfe8d9998296672bd1973a8376a02cb06f2338418e27f23a392ac2",
    "crates/kem1536/src/secret_box.rs": "08d6ba7accadb46dc66b780a396dc418950641b29a91d365e12537001c40d28e",
}
HELPERS = ("run_m07.py", "capture_m07_timing.py", "validate_hardening_m02.py", "run_m08.py",
           "build_m06_validation.py", "analyze_delivery_timing.py")


def checked_source(folder, manifest):
    expected = read(manifest)["source_sha256"]
    actual = {p.relative_to(folder).as_posix(): sha(p) for p in sorted(folder.rglob("*")) if p.is_file()}
    require(actual == expected, "source closure differs")


def reference_build(out=OUT, baseline=BASE):
    OUT, BASE = Path(out).resolve(), Path(baseline).resolve()
    checked_source(BASE / "baseline-source", BASE / "baseline-source.json")
    dest = OUT / "reference-latency"
    dest.mkdir()
    for host in ("windows", "linux"):
        target = ROOT / "target" / (OUT.name+"-reference-latency") / host
        require(not target.exists(), "new reference target required")
        folder = dest / host
        folder.mkdir()
        args = ["build", "--release", "--locked", "--offline", "-p", "kem1536-bench", "--bin", "m07-measure"]
        if host == "windows":
            env, cargo, rustc, _ = windows_environment(target)
            cmd = [cargo, *args]
            version = subprocess.check_output([rustc, "-Vv"], env=env, text=True)
        else:
            env = None
            prefix = linux_prefix(target)
            cmd = [*prefix, linux(ROOT / ".tools/linux-cargo/bin/cargo"), *args]
            version = subprocess.check_output([*prefix, linux(ROOT / ".tools/linux-cargo/bin/rustc"), "-Vv"], text=True)
        with (folder / "build.log").open("xb") as log:
            result = subprocess.run(cmd, cwd=BASE / "baseline-source", env=env, stdout=log, stderr=subprocess.STDOUT)
        require(result.returncode == 0 and "release: 1.91.1" in version, "reference build failed")
        name = "latency.exe" if host == "windows" else "latency"
        shutil.copyfile(target / "release" / ("m07-measure.exe" if host == "windows" else "m07-measure"), folder / name)
        save(folder / "build.json", {"binary": name, "sha256": sha(folder / name), "command": cmd,
             "rustc": version, "emit_stack_metadata": False, "exit_code": result.returncode,
             "source_manifest_sha256": sha(BASE / "baseline-source.json")})
    checked_source(BASE / "baseline-source", BASE / "baseline-source.json")


def inventory(folder):
    return {p.relative_to(folder).as_posix(): sha(p) for p in sorted(folder.rglob("*")) if p.is_file()}


def prepare_context(out, baseline, reference_root):
    """Copy already built baseline images/data; never claim fresh acquisitions."""
    target = out / "reference-latency"
    reference_root = Path(reference_root).resolve() if reference_root is not None else target
    require(reference_root.is_dir(), "explicit reference-latency images are required")
    source_inventory = inventory(reference_root)
    if reference_root != target.resolve():
        require(not target.exists(), "reference destination already exists")
        shutil.copytree(reference_root, target)
    require(inventory(target) == source_inventory, "copied reference images/context differ")
    dest = out / "measurements"
    shutil.copytree(baseline / "baseline-source", dest / "baseline-source")
    shutil.copyfile(baseline / "baseline-source.json", dest / "baseline-source.json")
    shutil.copytree(baseline / "baseline-memory", dest / "baseline-memory")
    shutil.copyfile(ROOT / "research/m09_poly_memory_baseline.py", dest / "baseline-memory-controller.py")
    save(dest / "reference-origin.json", {"original_reference_root": str(reference_root),
        "reference_inventory": source_inventory, "new_reference_builds_performed": 0,
        "baseline_memory_origin": str(baseline / "baseline-memory"),
        "baseline_memory_inventory": inventory(dest / "baseline-memory"),
        "baseline_memory_reused_observations": 216, "new_baseline_memory_acquisitions": 0,
        "historical_campaign_credit_seconds": 0})


def image_bindings(out, cpu):
    result = {}
    for host in ("windows", "linux"):
        rb = out / "reference-latency" / host / "build.json"
        base = read(rb)
        cb = out / host / "build.json"
        candidate = read(cb)
        result[host] = {}
        for label, image, receipt, checksum in (
                ("baseline", rb.parent/base["binary"], rb, base["sha256"]),
                ("candidate", out/candidate["binaries"]["latency"]["path"], cb,
                 candidate["binaries"]["latency"]["sha256"])):
            require(image.resolve().is_relative_to(out.resolve()) and sha(image) == checksum, "latency image differs")
            prefix = command(image, []) if host == "windows" else ["wsl", "-d", "Ubuntu-22.04", "--",
                        "taskset", "-c", str(cpu), linux(image)]
            result[host][label] = {"path": image.relative_to(out).as_posix(), "sha256": checksum,
                "build_receipt": receipt.relative_to(out).as_posix(), "build_receipt_sha256": sha(receipt),
                "command_prefix": prefix}
    return result


def acquire(cpu, out=OUT, baseline=BASE, reference_root=None):
    OUT, BASE = Path(out).resolve(), Path(baseline).resolve()
    require(type(cpu) is int and cpu == 10, "the predefined CPU is 10")
    checked_source(OUT / "source", OUT / "source.json")
    checked_source(BASE / "baseline-source", BASE / "baseline-source.json")
    require(read(OUT / "qualification-adapter/validate-001/after.json")["status"] == "PASS",
            "complete successful candidate validation before measurements")
    dest = OUT / "measurements"
    dest.mkdir()
    prepare_context(OUT, BASE, reference_root)
    protocol = OUT / "source/docs/PROTOCOLE_M09_QUALIFICATION.md"
    shutil.copyfile(protocol, dest / "protocol.md")
    shutil.copyfile(Path(__file__), dest / "controller.py")
    helpers = {}
    for name in HELPERS:
        expected = read(OUT / "source.json")["source_sha256"]["research/"+name]
        require(sha(ROOT / "research" / name) == expected, "live acquisition helper differs: "+name)
        target = dest / "controls" / name
        target.parent.mkdir(exist_ok=True)
        shutil.copyfile(ROOT / "research" / name, target)
        helpers[name] = expected
    save(dest / "plan.json", {"created_utc": utc(), "source_manifest_sha256": sha(OUT / "source.json"),
        "baseline_manifest_sha256": sha(BASE / "baseline-source.json"), "protocol_sha256": sha(protocol),
        "controller_sha256": sha(Path(__file__)), "series": 5, "samples": 500, "warmup": 100,
        "CPU": cpu, "median_ratio_max": 1.05, "p95_ratio_max": 1.20, "minimum_gain_each_OS": .05,
        "stack_max_additional_bytes": 1024, "no_exclusions": True, "global_host_isolation_proved": False,
        "reference_origin_sha256": sha(dest / "reference-origin.json"), "helpers": helpers,
        "baseline_memory_controller_sha256": sha(dest / "baseline-memory-controller.py"),
        "images": image_bindings(OUT, cpu),
        "candidate_memory_validation_after_sha256": sha(OUT / "qualification-adapter/validate-001/after.json")})
    # Refuse bad source/image/memory provenance before starting a benchmark.
    verify_context(load_raws(OUT))
    runs = []
    for host in ("windows", "linux"):
        rb = OUT / "reference-latency" / host / "build.json"
        base_receipt = read(rb)
        baseline = rb.parent / base_receipt["binary"]
        source_receipt = read(OUT / host / "build.json")
        candidate = OUT / source_receipt["binaries"]["latency"]["path"]
        require(sha(baseline) == base_receipt["sha256"], "reference image differs")
        require(sha(candidate) == source_receipt["binaries"]["latency"]["sha256"], "candidate image differs")
        for series in range(5):
            for label in (("baseline", "candidate") if series % 2 == 0 else ("candidate", "baseline")):
                image = baseline if label == "baseline" else candidate
                args = [str(series), "500", "100"]
                cmd = command(image, args)
                if host == "linux":
                    cmd = ["wsl", "-d", "Ubuntu-22.04", "--", "taskset", "-c", str(cpu), linux(image), *args]
                stem = f"{host}-{series}-{label}"
                started = utc()
                with affinity(cpu), (dest / (stem + ".jsonl")).open("xb") as log, (dest / (stem + ".stderr")).open("xb") as errors:
                    result = subprocess.run(cmd, stdout=log, stderr=errors)
                record = {"host": host, "series": series, "label": label, "binary_sha256": sha(image),
                    "command": cmd, "exit_code": result.returncode, "started_utc": started, "finished_utc": utc(),
                    "raw": stem + ".jsonl", "raw_sha256": sha(dest / (stem + ".jsonl")),
                    "stderr_sha256": sha(dest / (stem + ".stderr"))}
                save(dest / (stem + ".receipt.json"), record)
                require(result.returncode == 0, "KEM latency acquisition failed")
                runs.append(record)
        print("M09 final latency " + host + " complete", flush=True)
    save(dest / "runs.json", runs)
    checked_source(OUT / "source", OUT / "source.json")
    require(sha(Path(__file__)) == read(dest / "plan.json")["controller_sha256"]
            and all(sha(ROOT / "research" / name) == checksum for name, checksum in helpers.items()),
            "measurement controller/helper changed during acquisition")
    report = evaluate(OUT)
    save(dest / "evaluation.json", report)
    print(json.dumps(report), flush=True)


class Evidence:
    """Bounded archive callers can supply bytes directly; no extraction/execution."""
    def __init__(self, raws):
        self.raws = raws
        for name in raws:
            path = PurePosixPath(name)
            require(type(name) is str and name and str(path) == name and not path.is_absolute()
                    and "\\" not in name and all(part not in ("", ".", "..") and ":" not in part
                                                for part in name.split("/")), "unsafe measurement path")

    def bytes(self, name):
        require(name in self.raws, "measurement evidence missing: "+name)
        return self.raws[name]

    def json(self, name):
        return json.loads(self.bytes(name))

    def sha(self, name):
        return hashlib.sha256(self.bytes(name)).hexdigest()

    def inventory(self, prefix):
        prefix += "/"
        return {name[len(prefix):]: hashlib.sha256(raw).hexdigest()
                for name, raw in self.raws.items() if name.startswith(prefix)}


def load_raws(out):
    return {p.relative_to(out).as_posix(): p.read_bytes() for p in sorted(out.rglob("*")) if p.is_file()}


def execution_time(value):
    require(type(value) is str, "execution timestamp must be a string")
    parsed = datetime.fromisoformat(value)
    require(parsed.tzinfo is not None and parsed.utcoffset().total_seconds() == 0, "UTC timestamp required")
    return parsed


def verify_context(raws):
    data = Evidence(raws)
    plan = data.json("measurements/plan.json")
    candidate = data.json("source.json")
    baseline = data.json("measurements/baseline-source.json")
    require(data.inventory("source") == candidate["source_sha256"], "candidate source closure differs")
    require(data.inventory("measurements/baseline-source") == baseline["source_sha256"], "baseline source closure differs")
    require(all(baseline["source_sha256"][name] == checksum for name, checksum in M08_CORE.items()),
            "reference is not the captured M08 core")
    require(plan["source_manifest_sha256"] == data.sha("source.json")
            and plan["baseline_manifest_sha256"] == data.sha("measurements/baseline-source.json"), "plan/source binding differs")
    require(all(type(plan[name]) is int and plan[name] == expected for name, expected in
                (("series", 5), ("samples", 500), ("warmup", 100), ("CPU", 10), ("stack_max_additional_bytes", 1024)))
            and plan["median_ratio_max"] == 1.05 and plan["p95_ratio_max"] == 1.20
            and plan["minimum_gain_each_OS"] == .05 and plan["no_exclusions"] is True,
            "predefined measurement budget differs")
    require(data.sha("measurements/controller.py") == plan["controller_sha256"]
            and data.sha("measurements/protocol.md") == plan["protocol_sha256"]
            == candidate["source_sha256"]["docs/PROTOCOLE_M09_QUALIFICATION.md"], "controller/protocol binding differs")
    require(set(plan["helpers"]) == set(HELPERS), "measurement helper closure differs")
    for name, checksum in plan["helpers"].items():
        require(data.sha("measurements/controls/"+name) == checksum
                == candidate["source_sha256"]["research/"+name], "acquisition helper/source differs")
    origin = data.json("measurements/reference-origin.json")
    require(data.sha("measurements/reference-origin.json") == plan["reference_origin_sha256"]
            and data.inventory("reference-latency") == origin["reference_inventory"]
            and data.inventory("measurements/baseline-memory") == origin["baseline_memory_inventory"],
            "reused reference inventory differs")
    require(all(type(origin[name]) is int and origin[name] == 0 for name in
                ("new_reference_builds_performed", "new_baseline_memory_acquisitions", "historical_campaign_credit_seconds"))
            and origin["baseline_memory_reused_observations"] == 216, "reference reuse credit differs")
    after_path = "qualification-adapter/validate-001/after.json"
    after = data.json(after_path)
    require(data.sha(after_path) == plan["candidate_memory_validation_after_sha256"] and after["status"] == "PASS"
            and type(after["child_exit_code"]) is int and after["child_exit_code"] == 0 and after["exit_code_known"] is True
            and after["after"]["binding"]["source_manifest_sha256"] == data.sha("source.json"),
            "candidate validation acquisition binding differs")
    require(data.sha("measurements/baseline-memory-controller.py") == plan["baseline_memory_controller_sha256"],
            "baseline memory controller differs")
    memory = {}
    require(set(plan["images"]) == {"windows", "linux"}, "image host grid differs")
    for host in ("windows", "linux"):
        builds = {"baseline": data.json("reference-latency/"+host+"/build.json"),
                  "candidate": data.json(host+"/build.json")}
        require(set(plan["images"][host]) == {"baseline", "candidate"}, "image label grid differs")
        for label in ("baseline", "candidate"):
            image = plan["images"][host][label]
            expected_receipt = "reference-latency/"+host+"/build.json" if label == "baseline" else host+"/build.json"
            require(image["build_receipt"] == expected_receipt
                    and data.sha(expected_receipt) == image["build_receipt_sha256"], "latency build receipt differs")
            build = builds[label]
            source_hash = data.sha("measurements/baseline-source.json") if label == "baseline" else data.sha("source.json")
            require(build["source_manifest_sha256"] == source_hash, "latency build/source binding differs")
            row = build if label == "baseline" else build["binaries"]["latency"]
            expected_path = "reference-latency/"+host+"/"+row["binary"] if label == "baseline" else row["path"]
            require(image["path"] == expected_path and data.sha(expected_path) == row["sha256"] == image["sha256"]
                    and type(row["exit_code"]) is int and row["exit_code"] == 0 and row["emit_stack_metadata"] is False
                    and "release: 1.91.1" in row["rustc"], "latency image/build binding differs")
            prefix = image["command_prefix"]
            require(isinstance(prefix, list) and prefix and all(type(value) is str for value in prefix)
                    and prefix[-1].replace("\\", "/").endswith("/"+expected_path), "executed latency path differs")
            require((host == "windows" and len(prefix) == 1) or
                    (host == "linux" and len(prefix) == 8 and prefix[:7] == ["wsl", "-d", "Ubuntu-22.04", "--", "taskset", "-c", "10"]),
                    "latency CPU/launcher differs")
        memory[host] = {}
        folder = "measurements/baseline-memory/"+host+"/"
        build, run = data.json(folder+"build.json"), data.json(folder+"run.json")
        probe = folder+("probe.exe" if host == "windows" else "probe")
        require(build["source_manifest_sha256"] == data.sha("measurements/baseline-source.json")
                and build["controller_sha256"] == plan["baseline_memory_controller_sha256"]
                and data.sha(probe) == build["binary_sha256"] == run["binary_sha256"]
                and type(build["exit_code"]) is type(run["exit_code"]) is type(run["repetitions"]) is int
                and build["exit_code"] == run["exit_code"] == 0 and run["repetitions"] == 3
                and build["emit_stack_metadata"] is (host == "linux")
                and "release: 1.91.1" in build["rustc"] and data.sha(folder+"build.log") == build["build_log_sha256"]
                and data.sha(folder+"memory.jsonl") == run["raw_sha256"]
                and data.sha(folder+"memory.stderr") == run["stderr_sha256"]
                and run["command"][-1] == "3", "baseline memory image/source/raw binding differs")
        memory[host]["baseline"] = validate_memory([json.loads(line) for line in data.bytes(folder+"memory.jsonl").splitlines()], 3)
        require(memory[host]["baseline"] == data.json(folder+"summary.json"), "baseline memory summary differs")
        folder = "validation/"+host+"/"
        run = data.json(folder+"memory.receipt.json")
        probe = builds["candidate"]["binaries"]["probe"]
        require(data.sha(probe["path"]) == probe["sha256"] == run["binary_sha256"]
                and type(probe["exit_code"]) is type(run["exit_code"]) is type(run["expected_exit_code"]) is int
                and probe["exit_code"] == run["exit_code"] == run["expected_exit_code"] == 0
                and run["command"][-1] == "3" and probe["emit_stack_metadata"] is (host == "linux"),
                "candidate memory image/source binding differs")
        for name in ("memory.stdout", "memory.stderr", "memory.receipt.json"):
            require(data.sha(folder+name) == after["output_sha256"][host+"/"+name], "candidate memory raw/receipt binding differs")
        memory[host]["candidate"] = validate_memory([json.loads(line) for line in data.bytes(folder+"memory.stdout").splitlines()], 3)
    return data, plan, memory


def evaluate_raws(raws):
    data, plan, memory = verify_context(raws)
    runs = data.json("measurements/runs.json")
    order = [(host, series, label) for host in ("windows", "linux") for series in range(5)
             for label in (("baseline", "candidate") if series % 2 == 0 else ("candidate", "baseline"))]
    require(len(runs) == 20, "full 20-run grid required")
    groups, results, last_finish = defaultdict(list), {}, execution_time(plan["created_utc"])
    for run, expected_identity in zip(runs, order, strict=True):
        require(type(run["series"]) is int and (run["host"], run["series"], run["label"]) == expected_identity,
                "predefined AB/BA run order differs")
        host, series, label = expected_identity
        stem = f"{host}-{series}-{label}"
        require(data.json("measurements/"+stem+".receipt.json") == run, "individual run receipt differs")
        require(run["raw"] == stem+".jsonl" and run["raw_sha256"] == data.sha("measurements/"+stem+".jsonl")
                and run["stderr_sha256"] == data.sha("measurements/"+stem+".stderr")
                and type(run["exit_code"]) is int and run["exit_code"] == 0, "latency bytes/execution differs")
        image = plan["images"][host][label]
        require(run["binary_sha256"] == image["sha256"]
                and run["command"] == image["command_prefix"]+[str(series), "500", "100"], "run/image/arguments binding differs")
        started, finished = execution_time(run["started_utc"]), execution_time(run["finished_utc"])
        require(last_finish <= started <= finished, "sequential acquisition timestamps differ")
        last_finish = finished
        rows = [json.loads(line) for line in data.bytes("measurements/"+stem+".jsonl").splitlines()]
        require(len(rows) == 2000, "full latency observation count required")
        seen = set()
        for row in rows:
            require(set(row) == {"operation", "series", "iteration", "nanoseconds"}
                    and type(row["series"]) is type(row["iteration"]) is type(row["nanoseconds"]) is int
                    and row["series"] == series and row["nanoseconds"] > 0, "invalid latency sample")
            identity = (row["operation"], row["iteration"])
            require(identity not in seen and row["operation"] in OPS and 0 <= row["iteration"] < 500,
                    "unknown or duplicate latency observation")
            seen.add(identity)
            groups[host, label, row["operation"]].append(row["nanoseconds"])
        require(seen == {(op, i) for op in OPS for i in range(500)}, "latency observation grid differs")
    for host in ("windows", "linux"):
        panels = {}
        for op in OPS:
            stats = {}
            for label in ("baseline", "candidate"):
                values = sorted(groups[host, label, op])
                require(len(values) == 2500, "pooled sample count differs")
                stats[label] = {"count": len(values), "median_ns": statistics.median(values),
                    "p95_ns": values[math.ceil(.95*len(values))-1]}
            med = stats["candidate"]["median_ns"]/stats["baseline"]["median_ns"]
            p95 = stats["candidate"]["p95_ns"]/stats["baseline"]["p95_ns"]
            panels[op] = {**stats, "median_ratio": med, "p95_ratio": p95, "passed": med <= 1.05 and p95 <= 1.20}
        budgets = {}
        for op in MEMORY_OPERATIONS[4:]:
            base, cand = memory[host]["baseline"][op], memory[host]["candidate"][op]
            bmax, cmax = base["touched_stack_bytes"]["maximum"], cand["touched_stack_bytes"]["maximum"]
            allocations = {key: cand["requested_allocation_ranges"][key][1] <= base["requested_allocation_ranges"][key][1] for key in ALLOC}
            budgets[op] = {"baseline_stack_max": bmax, "candidate_stack_max": cmax,
                "stack_passed": cmax <= bmax+1024, "allocation_budgets": allocations,
                "passed": cmax <= bmax+1024 and all(allocations.values())}
        gain = any(panel["median_ratio"] <= .95 for panel in panels.values())
        results[host] = {"latency": panels, "memory": budgets, "minimum_gain_passed": gain,
            "all_budgets_passed": gain and all(panel["passed"] for panel in panels.values()) and all(row["passed"] for row in budgets.values())}
    return {"latency_observations": 40000, "memory_observations_baseline_plus_candidate": 432,
        "baseline_memory_reused_observations": 216, "candidate_memory_validation_observations": 216,
        "new_reference_builds_during_this_acquisition": 0, "historical_campaign_credit_seconds": 0,
        "hosts": results, "all_budgets_passed": all(row["all_budgets_passed"] for row in results.values()),
        "isolated_microbenchmark_failure_overridden": False, "constant_time_proved": False}


def evaluate(out):
    return evaluate_raws(load_raws(Path(out)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build-reference", "acquire", "verify"))
    parser.add_argument("--cpu", type=int, default=10)
    parser.add_argument("--output", type=Path, default=OUT)
    parser.add_argument("--baseline", type=Path, default=BASE,
                        help="M09 pre-mutation capture containing baseline-source and baseline-memory")
    parser.add_argument("--reference-root", type=Path,
                        help="existing reference-latency directory; copied exactly, no new build credit")
    args = parser.parse_args()
    out, baseline = args.output.resolve(), args.baseline.resolve()
    require(out.parent == ROOT / "artifacts/generated" and baseline.parent == ROOT / "artifacts/generated",
            "new direct generated output and baseline required")
    if args.action == "build-reference":
        require(args.reference_root is None, "reference-root is for acquire; build-reference builds new images")
        reference_build(out, baseline)
    elif args.action == "acquire":
        acquire(args.cpu, out, baseline, args.reference_root)
    else:
        result = evaluate(out)
        require(result == read(out / "measurements/evaluation.json"), "evaluation differs")
        print(json.dumps(result))


if __name__ == "__main__":
    main()
