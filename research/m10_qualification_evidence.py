"""Data-only M10 finite-qualification replay; no engine, build or acquisition."""
import gzip
import io
import itertools
import json
from archive_m09 import parsed,digest,safe_name
from run_m07 import ROOT,require
from m09_chunks import sha
from verify_r1_certificate_bridge import verify_static_contract
from run_m08 import validate_memory
from analyze_delivery_timing import analyze as timing_analysis
from validate_hardening_m02 import mutations,oracle


def qualification_scope(raws):
    source = parsed(raws, "source.json")
    actual = {name.removeprefix("source/"): digest(raw) for name, raw in raws.items() if name.startswith("source/")}
    require(actual == source["source_sha256"], "M10 full source closure changed")
    contract = verify_static_contract(raws["source/crates/kem1536/src/dev_kem.rs"].decode("utf-8"))
    require(contract["realization"] == "M10-borrowed-XOF-copied-output-3"
            and contract["reviewed_source_anchors"] == 78, "M10 bridge realization differs")
    validation = parsed(raws, "validation.json")
    require(validation["source_manifest_sha256"] == digest(raws["source.json"])
            and validation["historical_campaign_credit"] == 0
            and validation["fresh_fuzzing_credit_seconds"] == 0, "qualification credit/source differs")
    counts, timing = {}, {}
    for host in ("windows", "linux"):
        build = parsed(raws, host + "/build.json")
        require(build["source_manifest_sha256"] == digest(raws["source.json"]), "build/source binding changed")
        require(set(build["binaries"]) == {"delivered", "research", "consumer", "latency", "timing", "probe"},
                "six image kinds required")
        for row in build["binaries"].values():
            require(row["exit_code"] == 0 and digest(raws[safe_name(row["path"])]) == row["sha256"]
                    and "release: 1.91.1" in row["rustc"], "original compiled image differs")
        result = validation["hosts"][host]
        require(result["regression"]["compared_to_frozen_M01"] == {"dev-vectors": 1000, "dev-rejection-vectors": 10000}
                and result["mutation"]["cases"] == 10000 and result["formats"]["inputs"] == 20000,
                "full finite qualification counts missing")
        require(result["CLI"]["fresh_round_trips"] == result["CLI"]["implicit_rejections_checked"] == 16,
                "CLI native smoke missing")
        for kind, count in (("dev-vectors", 1000), ("dev-rejection-vectors", 10000), ("dev-mutations", 10000)):
            with gzip.GzipFile(fileobj=io.BytesIO(raws[f"validation/{host}/{kind}.jsonl.gz"])) as stream:
                require(sum(1 for _ in stream) == count, "captured regression stream count differs")
        for operation, historical in (("dev-vectors", "r1-001/vectors.jsonl.gz"),
                                       ("dev-rejection-vectors", "r1-rejections-001/rejections.jsonl.gz")):
            saved = raws["execution/validate/inputs/results/engine/" + historical]
            require(digest(saved) == sha(ROOT / "results/engine" / historical), "historical input differs")
            with gzip.GzipFile(fileobj=io.BytesIO(raws[f"validation/{host}/{operation}.jsonl.gz"])) as current:
                with gzip.GzipFile(fileobj=io.BytesIO(saved)) as expected:
                    for left, right in itertools.zip_longest(current, expected):
                        require(left is not None and right is not None and json.loads(left) == json.loads(right),
                                "full historical R1 byte comparison differs")
        memory = [json.loads(line) for line in raws[f"validation/{host}/memory.stdout"].splitlines()]
        require(validate_memory(memory, 3) == result["memory"], "M10 memory summary differs")
        measurements = [json.loads(line) for line in raws[f"timing/{host}/observations.jsonl"].splitlines()]
        timing[host] = timing_analysis(measurements)
        require(timing[host] == parsed(raws, f"timing/{host}/analysis.json"), "timing summary differs")
        counts[host] = {"vectors": 1000, "rejections": 10000, "mutations": 10000, "formats": 20000,
                        "timing_observations": len(measurements), "memory_observations": len(memory)}
    for action in ("build", "validate", "timing"):
        before = parsed(raws, f"execution/{action}/before.json")
        after = parsed(raws, f"execution/{action}/after.json")
        require(after["status"] == "PASS" and after["failure"] is None
                and after["sources_and_controls_and_inputs_unchanged"] is True
                and before["source_manifest_sha256"] == after["source_manifest_sha256"] == digest(raws["source.json"]),
                "M10 execution did not complete with unchanged inputs")
        for name, checksum in before["controls_sha256"].items():
            require(digest(raws[f"execution/{action}/controls/"+name]) == checksum == after["controls_sha256"][name],
                    "M10 frozen execution controller differs")
    with gzip.GzipFile(fileobj=io.BytesIO(raws["validation/windows/dev-mutations.jsonl.gz"])) as stream:
        require(mutations(stream, oracle()) == validation["hosts"]["windows"]["mutation"],
                "independent mutation oracle differs")
    with gzip.GzipFile(fileobj=io.BytesIO(raws["validation/windows/dev-mutations.jsonl.gz"])) as windows:
        with gzip.GzipFile(fileobj=io.BytesIO(raws["validation/linux/dev-mutations.jsonl.gz"])) as linux:
            for left, right in itertools.zip_longest(windows, linux):
                require(left is not None and right is not None and json.loads(left) == json.loads(right),
                        "cross-OS mutation bytes differ")
    from m10_measure import evaluate_raws
    measures = evaluate_raws({n.removeprefix("measurements/"): v for n,v in raws.items() if n.startswith("measurements/")})
    require(measures == parsed(raws, "measurements/evaluation.json") and measures["all_budgets_passed"] is True,
            "full KEM performance/memory acceptance differs")
    return {"contract": contract, "counts": counts,
            "performance_memory_budgets_passed": measures["all_budgets_passed"],
            "timing_threshold_crossings": {host: result["threshold_crossings"] for host, result in timing.items()}}

