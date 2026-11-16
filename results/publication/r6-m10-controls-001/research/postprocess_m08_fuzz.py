"""Collect M08 LLVM branch/source coverage and independent corpus replay.

The long campaign has rebuilt std; cargo-fuzz 0.13.1 explicitly forbids
--build-std in coverage mode. Coverage therefore uses separate ASan objects
with the distributed std, instrument-coverage and -Zcoverage-options=branch.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode = True

from run_m08_fuzz import ROOT, TARGETS, environment, inventory, owned, read, require, save, sha, utc, verify as verify_campaign
from replay_m08_fuzz_corpus import verify as verify_replay


def json_export(path):
    with gzip.open(path, "rt", encoding="utf-8") as stream:
        return json.load(stream)


def save_export(path, raw):
    with path.open("xb") as output, gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0) as compressed:
        compressed.write(raw)


def core_summary(exported):
    require(exported["type"] == "llvm.coverage.json.export", "real LLVM export required")
    files = [row for item in exported["data"] for row in item["files"]
             if "/crates/kem1536/src/" in row["filename"]]
    require(files and len({row["filename"] for row in files}) == len(files), "unique core source mappings required")
    for row in files:
        for kind in ("lines", "functions", "regions", "branches"):
            counts = row["summary"][kind]
            require(type(counts["covered"]) is int and type(counts["count"]) is int
                    and 0 <= counts["covered"] <= counts["count"], "invalid LLVM coverage counts")
    functions = [row for item in exported["data"] for row in item["functions"]
                 if any("/crates/kem1536/src/" in name for name in row["filenames"])]
    require(functions, "full function coverage mapping required, including zero counts")
    zero_functions = [{"LLVM_name": row["name"], "count": row["count"], "filenames": row["filenames"]}
                      for row in functions if row["count"] == 0]
    uncovered = []
    for row in files:
        zero_regions = [segment for segment in row.get("segments", [])
                        if len(segment) >= 6 and segment[2] == 0 and segment[3] and segment[4] and not segment[5]]
        branches = row.get("branches", [])
        # LLVM branch tuples: start line/column, end line/column, true/false
        # counts, file/expanded-file identifiers and region kind. Keep tuples
        # verbatim so the measured field is never confused with an inferred CFG.
        zero_sides = [{"mapping": branch, "zero_true": branch[4] == 0, "zero_false": branch[5] == 0}
                      for branch in branches if len(branch) >= 6 and (branch[4] == 0 or branch[5] == 0)]
        uncovered.append({"filename": row["filename"], "zero_count_region_entries": zero_regions,
                          "branch_sides_not_observed": zero_sides})
    return {"files": [{"filename": row["filename"], "summary": row["summary"]} for row in files],
            "function_mappings": len(functions), "zero_count_functions": zero_functions,
            "uncovered_source_mappings": uncovered,
            "counts_are_not_constant_time_or_complete_path_proof": True}


def require_union_superset(union, panels):
    by_name = {row["filename"]: row for row in union["files"]}
    for panel in panels.values():
        for row in panel["files"]:
            require(row["filename"] in by_name, "source absent from LLVM union")
            combined = by_name[row["filename"]]["summary"]
            for kind in ("lines", "functions", "regions", "branches"):
                require(combined[kind]["count"] >= row["summary"][kind]["count"]
                        and combined[kind]["covered"] >= row["summary"][kind]["covered"],
                        "LLVM union is not a superset of a per-target panel")


def copy_source(out, destination):
    expected = read(out / "config.json")["source_sha256"]
    require(inventory(out / "source") == expected, "accepted source changed")
    shutil.copytree(out / "source", destination)
    require(inventory(destination) == expected, "coverage source copy changed")
    return expected


def check_request(request, config):
    require(request["schema"] == "m08-coverage-request-v1"
            and request["source_sha256"] == config["source_sha256"]
            and request["candidate_source_manifest_sha256"] == config["candidate_source_manifest_sha256"]
            and request["standard_library_rebuilt_for_coverage"] is False
            and request["rustflags_extra"] == "-Zcoverage-options=branch"
            and type(request["native_CPU"]) is int and request["native_CPU"] >= 0,
            "coverage source, CPU or instrumentation scope differs")
    require(request["controllers_sha256"] == {name: config["controller_sha256"][name]
            for name in ("postprocess_m08_fuzz.py", "replay_m08_fuzz_corpus.py")},
            "coverage request controllers differ from frozen launch closure")
    require(request["rustc"] == config["versions"]["rustc"]
            and request["compiler_binary_sha256"] == config["versions"]["compiler_binary_sha256"]
            and request["cargo_fuzz_binary_sha256"] == config["versions"]["cargo_fuzz_binary_sha256"]
            and request["ASAN_OPTIONS"] == config["ASAN_OPTIONS"] + ":detect_odr_violation=0",
            "coverage compiler/driver/ASan differs from frozen launch")
    match = re.search(r"LLVM version: ([^\s]+)", config["versions"]["rustc"])
    require(match is not None and all("LLVM version " + match.group(1) in request[name]
                                     for name in ("llvm_cov", "llvm_profdata")), "LLVM tool versions differ from compiler")


def check_coverage_command(receipt, name, request):
    command = receipt["coverage_command"]
    require(command[:3] == ["taskset", "-c", str(request["native_CPU"])]
            and command[4:7] == ["fuzz", "coverage", name]
            and PurePosixPath(command[7]).parts[-2:] == ("harvested-corpus", name)
            and "--build-std" not in command
            and receipt["standard_library_rebuilt"] is False
            and receipt["LLVM_source_and_branch_coverage"] is True
            and receipt["libFuzzer_edges_are_not_source_coverage"] is True,
            "coverage command CPU/corpus or source-coverage scope differs")
    export = receipt["export_command"]
    require(PurePosixPath(export[0]).name == "llvm-cov" and export[1] == "export"
            and "-summary-only" not in export, "full LLVM export including zero functions required")


def postprocess(out, target, replay_target, cpu):
    require(sys.platform == "linux" and cpu in os.sched_getaffinity(0), "native Linux CPU required")
    verify_campaign(out)
    target, replay_target = owned(target, ROOT / "target"), owned(replay_target, ROOT / "target")
    require(not target.exists() and not replay_target.exists() and target != replay_target,
            "new separate coverage and replay compiler targets required")
    config = read(out / "config.json")
    for name in ("postprocess_m08_fuzz.py", "replay_m08_fuzz_corpus.py"):
        require(sha(ROOT / "research" / name) == config["controller_sha256"][name],
                "postprocessing controller differs from frozen launch closure")
    folder = out / "postprocessing"
    require(not folder.exists(), "never overwrite a postprocessing attempt")
    folder.mkdir()
    try:
        source = folder / "source"
        frozen = copy_source(out, source)
        (folder / "tmp").mkdir()
        env = environment(target)
        env["RUSTFLAGS"] = "-Zcoverage-options=branch"
        env["ASAN_OPTIONS"] += ":detect_odr_violation=0"
        env["TMPDIR"] = str(folder / "tmp")
        cargo, rustc = (str(ROOT / ".tools/linux-cargo/bin" / name) for name in ("cargo", "rustc"))
        sysroot = Path(subprocess.check_output([rustc, "--print", "sysroot"], env=env, text=True).strip())
        llvm = sysroot / "lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov"
        profdata = llvm.parent / "llvm-profdata"
        require(llvm.is_file() and profdata.is_file(), "pinned LLVM tools required")
        recipe = ROOT / ".tools/linux-cargo/registry/src/index.crates.io-1949cf8c6b5b557f/cargo-fuzz-0.13.1/src/options/coverage.rs"
        request = {"schema": "m08-coverage-request-v1", "started_utc": utc(),
                   "candidate_source_manifest_sha256": config["candidate_source_manifest_sha256"],
                   "source_sha256": frozen, "native_CPU": cpu,
                   "cargo_fuzz_coverage_recipe_sha256": sha(recipe),
                   "rustflags_extra": env["RUSTFLAGS"], "standard_library_rebuilt_for_coverage": False,
                   "reason": "cargo-fuzz0.13.1 rejects --build-std in coverage mode; separate objects/profiles",
                   "rustc": subprocess.check_output([rustc, "-Vv"], env=env, text=True),
                   "llvm_cov": subprocess.check_output([str(llvm), "--version"], env=env, text=True),
                   "llvm_profdata": subprocess.check_output([str(profdata), "--version"], env=env, text=True),
                   "llvm_cov_binary_sha256": sha(llvm), "llvm_profdata_binary_sha256": sha(profdata),
                   "compiler_binary_sha256": sha(sysroot / "bin/rustc"), "ASAN_OPTIONS": env["ASAN_OPTIONS"],
                   "cargo_fuzz_binary_sha256": sha(ROOT / ".tools/linux-cargo/bin/cargo-fuzz"),
                   "temporary_directory": str(folder / "tmp"),
                   "controllers_sha256": {name: config["controller_sha256"][name]
                                          for name in ("postprocess_m08_fuzz.py", "replay_m08_fuzz_corpus.py")}}
        require("release: 1.91.1" in request["rustc"], "unexpected coverage compiler")
        check_request(request, config)
        save(folder / "request.json", request)
        (folder / "bin").mkdir()
        panels, receipts = {}, {}
        for name in TARGETS:
            corpus = out / "harvested-corpus" / name
            inputs = inventory(corpus)
            command = ["taskset", "-c", str(cpu), cargo, "fuzz", "coverage", name, str(corpus),
                       "--fuzz-dir", str(source / "fuzz"), "--target-dir", str(target), "--",
                       "-timeout=60", "-rss_limit_mb=2048"]
            with (folder / (name + "-coverage.log")).open("xb") as log:
                subprocess.run(command, cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
            binary = folder / "bin" / name
            shutil.copyfile(target / "x86_64-unknown-linux-gnu/release" / name, binary)
            profile = source / "fuzz/coverage" / name / "coverage.profdata"
            retained_profile = folder / (name + ".profdata")
            shutil.copyfile(profile, retained_profile)
            export_command = [str(llvm), "export", str(binary), "-instr-profile=" + str(retained_profile)]
            raw = subprocess.check_output(export_command, env=env)
            export = folder / (name + "-full.json.gz")
            save_export(export, raw)
            panels[name] = core_summary(json.loads(raw))
            require(inputs == inventory(corpus), "harvested corpus changed during coverage replay")
            receipts[name] = {"coverage_command": command, "export_command": export_command,
                              "binary_sha256": sha(binary), "profdata_sha256": sha(retained_profile),
                              "compressed_export_sha256": sha(export), "uncompressed_export_sha256": hashlib.sha256(raw).hexdigest(),
                              "corpus_sha256": inputs, "standard_library_rebuilt": False,
                              "LLVM_source_and_branch_coverage": True, "libFuzzer_edges_are_not_source_coverage": True}
            save(folder / (name + "-receipt.json"), receipts[name])
        # Merge profiles and export all four objects. Never add four overlapping
        # numerators or denominators to invent an aggregate coverage fraction.
        union_profile = folder / "union.profdata"
        merge_command = [str(profdata), "merge", "-sparse", *[str(folder / (n + ".profdata")) for n in TARGETS],
                         "-o", str(union_profile)]
        with (folder / "union.log").open("xb") as log:
            subprocess.run(merge_command, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
        export_command = [str(llvm), "export", str(folder / "bin" / TARGETS[0]),
                          *["-object=" + str(folder / "bin" / n) for n in TARGETS[1:]],
                          "-instr-profile=" + str(union_profile)]
        raw = subprocess.check_output(export_command, env=env)
        save_export(folder / "union-full.json.gz", raw)
        union = core_summary(json.loads(raw))
        require_union_superset(union, panels)
        require(any(row["summary"]["branches"]["count"] > 0 for row in union["files"]),
                "requested branch coverage produced no core branch mappings")
        save(folder / "coverage-summary.json", {"per_target": panels, "LLVM_union": union,
             "merge_command": merge_command, "export_command": export_command,
             "union_profile_sha256": sha(union_profile), "union_export_sha256": sha(folder / "union-full.json.gz"),
             "uncompressed_union_export_sha256": hashlib.sha256(raw).hexdigest(),
             "overlapping_per_target_counts_summed": False, "standard_library_rebuilt": False})
        # All measured inputs are fixed. Preserve the separate coverage worktree
        # with its profiles, and verify that the original source never changed.
        require(inventory(out / "source") == frozen, "coverage modified the accepted campaign source")
        actual_static = inventory(source)
        require({name: value for name, value in actual_static.items() if not name.startswith("fuzz/coverage/")} == frozen,
                "coverage build changed static inputs")
        save(folder / "coverage-worktree.json", {"static_sha256": frozen,
             "coverage_generated_sha256": {name: value for name, value in actual_static.items() if name.startswith("fuzz/coverage/")}})
        # Deterministic replay uses the same production+fixture sources, with
        # ordinary release flags and no research-vectors feature.
        replay_env = environment(replay_target)
        replay_env.pop("RUSTC_BOOTSTRAP", None)
        replay_env.pop("ASAN_OPTIONS", None)
        replay_command = ["taskset", "-c", str(cpu), cargo, "build", "--locked", "--offline", "--release",
                          "-p", "kem1536-bench", "--bin", "m06-replay"]
        with (out / "replay-build.log").open("xb") as log:
            subprocess.run(replay_command, cwd=out / "source", env=replay_env,
                           stdout=log, stderr=subprocess.STDOUT, check=True)
        replay_binary = out / "bin/m08-replay"
        shutil.copyfile(replay_target / "release/m06-replay", replay_binary)
        replay_binary.chmod(0o700)
        save(out / "replay-build.json", {"binary_sha256": sha(replay_binary), "command": replay_command,
             "source_sha256": frozen, "research_vectors_feature_enabled": False,
             "replay_harness_sha256": frozen["crates/kem1536-bench/src/bin/m06-replay.rs"]})
        windows = lambda path: subprocess.check_output(["wslpath", "-w", str(path)], text=True).strip()
        oracle_command = [str(ROOT / ".tools/research-venv/Scripts/python.exe"), "-B",
                          windows(out / "controls/replay_m08_fuzz_corpus.py"), "run", "--campaign", windows(out),
                          "--linux-binary", str(replay_binary)]
        with (out / "oracle-replay.log").open("xb") as log:
            subprocess.run(oracle_command, stdout=log, stderr=subprocess.STDOUT, check=True)
        save(folder / "postprocess.json", {"finished_utc": utc(), "source_coverage_exported": True,
             "independent_python_replay_passed": True, "oracle_command": oracle_command,
             "oracle_receipt_sha256": sha(out / "oracle-replay.json"),
             "original_campaign_source_unchanged": inventory(out / "source") == frozen,
             "new_security_constant_time_or_erasure_proof": False})
        return verify(out)
    except BaseException as error:
        save(folder / "failure.json", {"at_utc": utc(), "type": type(error).__name__,
             "error": str(error), "evidence_preserved": True})
        raise


def verify(out):
    campaign = verify_campaign(out)
    folder = out / "postprocessing"
    request, saved = read(folder / "request.json"), read(folder / "coverage-summary.json")
    config = read(out / "config.json")
    check_request(request, config)
    panels = {}
    for name in TARGETS:
        receipt = read(folder / (name + "-receipt.json"))
        check_coverage_command(receipt, name, request)
        export = folder / (name + "-full.json.gz")
        require(receipt["binary_sha256"] == sha(folder / "bin" / name)
                and receipt["profdata_sha256"] == sha(folder / (name + ".profdata"))
                and receipt["compressed_export_sha256"] == sha(export)
                and receipt["corpus_sha256"] == inventory(out / "harvested-corpus" / name)
                and receipt["standard_library_rebuilt"] is False,
                "coverage binary/profile/export/corpus binding differs")
        with gzip.open(export, "rb") as stream:
            raw = stream.read()
        require(hashlib.sha256(raw).hexdigest() == receipt["uncompressed_export_sha256"], "full LLVM export changed")
        panels[name] = core_summary(json.loads(raw))
    require(panels == saved["per_target"] and saved["overlapping_per_target_counts_summed"] is False
            and saved["standard_library_rebuilt"] is False,
            "per-target source coverage does not replay")
    union_path = folder / "union-full.json.gz"
    with gzip.open(union_path, "rb") as stream:
        raw = stream.read()
    union = core_summary(json.loads(raw))
    require(union == saved["LLVM_union"] and sha(union_path) == saved["union_export_sha256"]
            and hashlib.sha256(raw).hexdigest() == saved["uncompressed_union_export_sha256"]
            and sha(folder / "union.profdata") == saved["union_profile_sha256"], "full LLVM union differs")
    require_union_superset(union, panels)
    worktree = read(folder / "coverage-worktree.json")
    require(worktree["static_sha256"] == config["source_sha256"]
            and inventory(folder / "source") == {**worktree["static_sha256"], **worktree["coverage_generated_sha256"]},
            "coverage worktree changed")
    replay_build = read(out / "replay-build.json")
    require(replay_build["source_sha256"] == config["source_sha256"]
            and replay_build["research_vectors_feature_enabled"] is False
            and sha(out / "bin/m08-replay") == replay_build["binary_sha256"], "replay build source/binary differs")
    replay = verify_replay(out)
    final = read(folder / "postprocess.json")
    require(final["source_coverage_exported"] is True and final["independent_python_replay_passed"] is True
            and final["oracle_receipt_sha256"] == sha(out / "oracle-replay.json")
            and final["original_campaign_source_unchanged"] is True
            and final["new_security_constant_time_or_erasure_proof"] is False, "postprocessing scope differs")
    return {**campaign, "main_campaign_source_line_coverage_measured": False,
            "source_line_coverage_measured": True, "source_branch_coverage_measured": True,
            "coverage_standard_library_rebuilt": False, "new_coverage_execution_by_verifier": False,
            **replay, "independent_oracle_replayed": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "verify"))
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/generated/m08-fuzz-001")
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target/m08-coverage-001")
    parser.add_argument("--replay-target-dir", type=Path, default=ROOT / "target/m08-replay-001")
    parser.add_argument("--cpu", type=int, default=8)
    args = parser.parse_args()
    result = postprocess(owned(args.output, ROOT / "artifacts/generated"), args.target_dir, args.replay_target_dir, args.cpu) \
        if args.action == "run" else verify(args.output.resolve())
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
