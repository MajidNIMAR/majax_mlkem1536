"""M10 original CLI packages and same-host repeat builds, never deployment.

All compiled inputs come from the selected m10-final-003/source capture.
The distribution receipt alone is not a full qualification or external audit.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from confirm_m06_builds import comparison_bytes
from package_m08 import check_windows_imports, validate_executable, windows_path, verify_archive, zip_package
from run_m07 import inventory, linux, linux_prefix, utc, windows_environment
from verify_m04_distribution import cargo_lock, compiled_inventory, deterministic_tar, license_inventory, native_dependencies

ROOT = Path(__file__).resolve().parents[1]
FINAL = ROOT / "artifacts/generated/m10-final-003"
OUT = ROOT / "artifacts/generated/m10-distribution-001"
TARGET_ROOT = ROOT / "target/m10-repeat-001"
TARGETS = {"windows": "x86_64-pc-windows-gnu", "linux": "x86_64-unknown-linux-gnu"}
PROFILE = "KEM1536-DEV-Q7681-R1"
DOCUMENTS = ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", "SECURITY.md",
             "docs/SPECIFICATION_DEV_Q7681_R1.md", "docs/MOTEUR_KEM_R1.md",
             "docs/PROTOCOLE_M10.md", "docs/REVUE_CYCLE_SECRET_M10.md",
             "docs/DECISION_PARAMETRES_M10.md", "docs/SECURITE_M10.md")


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def save(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def source_binding():
    manifest = read(FINAL / "source.json")
    require(inventory(FINAL / "source") == manifest["source_sha256"], "M10 captured source changed")
    return manifest


def compare(first, repeated, host):
    a, a_meta = comparison_bytes(first, host)
    b, b_meta = comparison_bytes(repeated, host)
    require(a == b, "repeat differs outside permitted PE header metadata")
    return {"raw_byte_identical": first == repeated,
            "comparison_sha256": hashlib.sha256(a).hexdigest(),
            "original_metadata": a_meta, "repeat_metadata": b_meta,
            "comparison_scope": "Linux raw identical; Windows only COFF timestamp and PE checksum masked temporarily",
            "raw_binaries_modified": False}


def setup(resume=False):
    measured = source_binding()
    source = OUT / "source"
    if OUT.exists():
        require(resume and not (OUT / "source-manifest.json").exists()
                and not (OUT / "source.tar.gz").exists() and not (source / "BUILD_M10.md").exists(),
                "only an unfinished source-document setup may be resumed")
        existing = inventory(source)
        require(all(existing.get(n) == h for n, h in measured["source_sha256"].items()), "partial setup captured source differs")
        require(set(existing) <= set(measured["source_sha256"]) | set(DOCUMENTS), "unexpected partial setup file")
        require(sha(OUT / "measured-source.json") == sha(FINAL / "source.json"), "partial setup manifest differs")
        save(OUT / "setup-recovery.json", {"reason": "Preserve captured pre-results addendum after document collision; resume missing source/package preparation only",
             "preserved_source_sha256": existing, "original_controller_sha256": sha(OUT / "repeat-controller.py"),
             "new_controller_sha256": sha(Path(__file__)), "measured_source_sha256": sha(FINAL / "source.json")})
        shutil.copyfile(Path(__file__), OUT / "setup-recovery-controller.py")
    else:
        require(not resume, "setup resume requires existing partial preparation")
        OUT.mkdir()
        shutil.copyfile(Path(__file__), OUT / "repeat-controller.py")
        shutil.copyfile(FINAL / "source.json", OUT / "measured-source.json")
        shutil.copytree(FINAL / "source", source)
    added = {}
    captured_document_differences = {}
    for name in DOCUMENTS:
        original = ROOT / name
        require(original.is_file(), "missing distribution document: " + name)
        destination = source / name
        if destination.exists():
            if name in measured["source_sha256"]:
                require(sha(destination) == measured["source_sha256"][name], "captured document changed")
                if sha(destination) != sha(original):
                    captured_document_differences[name] = {"captured": sha(destination), "current_report": sha(original),
                                                           "decision": "preserve captured source document"}
            else:
                require(sha(destination) == sha(original), "previously added document changed during resume")
                added[name] = sha(destination)
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original, destination)
            added[name] = sha(destination)
    (source / "BUILD_M10.md").write_text(
        "# MAJAX R6 M10 â€” compact sources\n\n"
        "Rust 1.91.1, native C linker and the platform Rust target are required.\n"
        "Dependencies are locked, not vendored; a new computer needs registry access or matching Cargo caches.\n\n"
        "```sh\ncargo +1.91.1 build --release --locked -p kem1536-cli --bin kem1536\n"
        "./target/release/kem1536 dev-self-test\n```\n\n"
        "Windows uses kem1536.exe and x86_64-pc-windows-gnu with the provided .cargo/config.toml.\n"
        "The compact archive contains the captured compilation closure plus selected documents;\n"
        "it does not contain all historical research evidence or a vendored toolchain.\n",
        encoding="utf-8")
    save(OUT / "source-manifest.json", {"profile": PROFILE,
         "measured_manifest_sha256": sha(FINAL / "source.json"), "files": inventory(source),
         "compiled_source_sha256": read(FINAL / "source.json")["source_sha256"],
         "added_documents_sha256": added, "current_report_differs_from_captured_document": captured_document_differences})
    deterministic_tar(source, OUT / "source.tar.gz", 0)
    verify_archive(OUT / "source.tar.gz", inventory(source))


def environment(host, target):
    if host == "windows":
        env, cargo, rustc, llvm = windows_environment(target)
        prefix = []
    else:
        env, llvm = None, None
        prefix = linux_prefix(target)
        cargo = linux(ROOT / ".tools/linux-cargo/bin/cargo")
        rustc = linux(ROOT / ".tools/linux-cargo/bin/rustc")
    version = subprocess.check_output([*prefix, rustc, "-Vv"], env=env, text=True)
    sysroot = subprocess.check_output([*prefix, rustc, "--print", "sysroot"], env=env, text=True).strip()
    return env, prefix, cargo, llvm, version, sysroot


def translated_metadata(metadata, host):
    translated = copy.deepcopy(metadata)
    if host == "linux":
        for row in translated["packages"]:
            row["manifest_path"] = str(windows_path(row["manifest_path"]))
            if row.get("license_file", "") and row["license_file"].startswith("/mnt/"):
                row["license_file"] = str(windows_path(row["license_file"]))
    return translated


def toolchain_licenses(folder, sysroot):
    notices = windows_path(sysroot) / "share/doc/rust"
    folder.mkdir(parents=True)
    for name in ("COPYRIGHT-library.html", "COPYRIGHT.html"):
        shutil.copyfile(notices / name, folder / name)
    shutil.copytree(notices / "licenses", folder / "texts")


def repeat(host):
    source_binding()
    folder = OUT / host
    folder.mkdir(exist_ok=False)
    shutil.copyfile(Path(__file__), folder / "repeat-execution-controller.py")
    target = TARGET_ROOT / host
    require(not target.exists(), "new repeat target required")
    original_receipt = read(FINAL / host / "build.json")
    require(original_receipt["source_manifest_sha256"] == sha(FINAL / "source.json"), "original source binding differs")
    original_item = original_receipt["binaries"]["delivered"]
    original = FINAL / original_item["path"]
    require(sha(original) == original_item["sha256"], "original CLI changed")
    env, prefix, cargo, llvm, version, sysroot = environment(host, target)
    require(version == original_item["rustc"], "repeat toolchain differs")
    arguments = ["build", "--release", "--locked", "--offline", "-p", "kem1536-cli", "--bin", "kem1536",
                 "--message-format=json-render-diagnostics"]
    command = [*prefix, cargo, *arguments]
    with (folder / "repeat-artifacts.jsonl").open("xb") as output, (folder / "repeat-build.log").open("xb") as errors:
        process = subprocess.run(command, cwd=FINAL / "source", env=env, stdout=output, stderr=errors)
    require(process.returncode == 0, "repeat CLI build failed; logs preserved")
    suffix = ".exe" if host == "windows" else ""
    repeated = folder / ("repeat" + suffix)
    shutil.copyfile(target / "release" / ("kem1536" + suffix), repeated)
    comparison = compare(original.read_bytes(), repeated.read_bytes(), host)
    save(folder / "comparison.json", comparison)
    metadata_command = [*prefix, cargo, "metadata", "--format-version", "1", "--locked", "--offline", "--filter-platform", TARGETS[host]]
    metadata = json.loads(subprocess.check_output(metadata_command, cwd=FINAL / "source", env=env))
    save(folder / "metadata.json", metadata)
    records = compiled_inventory(metadata, (folder / "repeat-artifacts.jsonl").read_text(), cargo_lock(FINAL / "source/Cargo.lock"))
    if host == "windows":
        native_command = [str(llvm / "llvm-readobj.exe"), "--coff-imports", str(original)]
    else:
        native_command = ["wsl", "-d", "Ubuntu-22.04", "--", "readelf", "-d", "--version-info", linux(original)]
    native_raw = subprocess.check_output(native_command, env=env)
    (folder / "native-dependencies.txt").write_bytes(native_raw)
    native = check_windows_imports(native_raw.decode(), original.read_bytes()) if host == "windows" else native_dependencies(native_raw.decode(), host)
    package = folder / "package"
    (package / "bin").mkdir(parents=True)
    shipped = package / "bin" / ("kem1536" + suffix)
    shutil.copyfile(original, shipped)
    if host == "linux":
        subprocess.run(["wsl", "-d", "Ubuntu-22.04", "--", "chmod", "0755", linux(shipped), linux(repeated)], check=True)
    original_validation = validate_executable(shipped, host, folder, "original")
    repeated_validation = validate_executable(repeated, host, folder, "repeat")
    license_inventory(records, translated_metadata(metadata, host), package / "licenses/dependencies")
    toolchain_licenses(package / "licenses/toolchain", sysroot)
    save(package / "dependencies.json", {"packages": records, "native": native,
         "normal_dependency_graph_is_not_linker_symbol_attribution": True,
         "metadata_sha256": sha(folder / "metadata.json"), "build_messages_sha256": sha(folder / "repeat-artifacts.jsonl")})
    for name in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", "SECURITY.md"):
        shutil.copyfile(OUT / "source" / name, package / name)
    for name in ("source.tar.gz", "source-manifest.json"):
        shutil.copyfile(OUT / name, package / name)
    save(folder / "repeat-build.json", {"command": command, "exit_code": process.returncode,
         "binary_sha256": sha(repeated), "original_binary_sha256": sha(original),
         "original_build_receipt_sha256": sha(FINAL / host / "build.json"), "rustc": version,
         "sysroot": sysroot, "source_manifest_sha256": sha(FINAL / "source.json"),
         "metadata_command": metadata_command, "native_command": native_command,
         "execution_controller_sha256": sha(folder / "repeat-execution-controller.py"),
         "new_CLI_builds": 1, "shared_tools_cache_and_source_path": True,
         "third_party_reproduction_claimed": False})
    save(package / "provenance.json", {"profile": PROFILE, "milestone": "M10", "host": host,
         "target": TARGETS[host], "source_manifest_sha256": sha(FINAL / "source.json"),
         "binary_sha256": sha(shipped), "repeat_binary_sha256": sha(repeated), "comparison": comparison,
         "original_self_test": original_validation, "repeat_self_test": repeated_validation,
         "research_vectors_enabled": False, "new_CLI_builds_this_run": 1,
         "shared_tools_cache_and_source_path": True, "third_party_reproduction_claimed": False,
         "global_constant_time_or_erasure_proof_claimed": False, "external_audit_claimed": False,
         "qualification_scope": "distribution build/byte comparison and CLI smoke only; final M10 qualification is separate"})
    (package / "USAGE.md").write_text(
        "# MAJAX R6 M10\n\nRun bin/kem1536 dev-profile or bin/kem1536 dev-self-test (.exe on Windows).\n"
        "Self-test performs 16 fresh exchanges and 16 rejection checks without printing keys.\n"
        "Research commands are disabled. This package ships the original M10 CLI, not its repeat build.\n"
        "The same-host repeat shares tools, dependency caches and source path; it is not reproduction by a third party.\n"
        "See dependencies.json for resolved normal/build graphs and system prerequisites. These graphs do not attribute linker symbols.\n"
        "System DLLs/libc are prerequisites, not bundled libraries. Sources and license texts are included.\n"
        "The R1 rank-six KEM is experimental, outside the NIST ML-KEM parameter sets; no external audit or universal CT/erasure proof is claimed.\n",
        encoding="utf-8")
    source_binding()


def diagnostic_inventory(host):
    """Conservative resolved graphs, not statements about linked diagnostics."""
    source_binding()
    folder = OUT / host / "diagnostics"
    folder.mkdir()
    env, prefix, cargo, _, version, sysroot = environment(host, TARGET_ROOT / host)
    builds = read(FINAL / host / "build.json")
    configurations = {
        "research": (FINAL / "source/Cargo.toml", ["--features", "research-vectors"]),
        "timing-latency": (FINAL / "source/Cargo.toml", []),
        "consumer": (FINAL / "source/research/m08-import-consumer/Cargo.toml", []),
        "probe": (FINAL / "source/research/m08-memory-probe/Cargo.toml", []),
    }
    metadata_receipts, packages = {}, {}
    all_metadata = {"packages": []}
    for label, (manifest, features) in configurations.items():
        manifest_arg = str(manifest) if host == "windows" else linux(manifest)
        command = [*prefix, cargo, "metadata", "--manifest-path", manifest_arg, "--format-version", "1", "--locked", "--offline",
                   "--filter-platform", TARGETS[host], *features]
        metadata = json.loads(subprocess.check_output(command, cwd=FINAL / "source", env=env))
        save(folder / (label + "-metadata.json"), metadata)
        lock = cargo_lock(manifest.parent / "Cargo.lock")
        locks = {(p["name"], p["version"], p.get("source")): p for p in lock["package"]}
        nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
        for p in metadata["packages"]:
            identity = p["id"]
            key = (p["name"], p["version"], p.get("source"))
            require(key in locks, "diagnostic metadata package absent from lock")
            if identity not in packages:
                packages[identity] = {"name": p["name"], "version": p["version"],
                    "source": p.get("source") or "project source snapshot", "lock_checksum": locks[key].get("checksum"),
                    "license": p.get("license"), "metadata_id": identity, "features": set(), "graphs": [],
                    "category": "conservative_resolved_graph_not_compiled_or_symbol_attribution"}
                all_metadata["packages"].append(p)
            packages[identity]["features"].update(nodes[identity]["features"])
            packages[identity]["graphs"].append(label)
        metadata_receipts[label] = {"command": command, "sha256": sha(folder / (label + "-metadata.json"))}
    records = []
    for identity in sorted(packages):
        p = packages[identity]
        p["features"] = sorted(p["features"])
        records.append(p)
    # Package IDs for local crates differ by standalone graph. Their own files
    # have no registry license text; repeated third-party IDs are deduplicated.
    license_inventory(records, translated_metadata(all_metadata, host), folder / "licenses/dependencies")
    toolchain_licenses(folder / "licenses/toolchain", sysroot)
    for name in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"):
        shutil.copyfile(OUT / "source" / name, folder / name)
    shutil.copyfile(FINAL / host / "build.json", folder / "original-build.json")
    save(folder / "dependencies.json", {"scope": "conservative resolved workspace/standalone graph union, not a compiled package or linked symbol inventory",
         "packages": records, "graphs": metadata_receipts, "rustc": version,
         "source_manifest_sha256": sha(FINAL / "source.json"),
         "diagnostic_image_sha256": {k: v["sha256"] for k, v in builds["binaries"].items() if k != "delivered"}})


def safe_evidence_name(name):
    from pathlib import PurePosixPath
    path = PurePosixPath(name)
    require(not path.is_absolute() and str(path) == name and ".." not in path.parts
            and ":" not in name and "\\" not in name and bool(path.parts), "unsafe acceptance evidence path")
    return name


def check_promotion_acceptance(marker, manifest_hash, delivered_hashes):
    require(marker.get("profile") == PROFILE and marker.get("accepted") is True,
            "root internal acceptance required before qualified packaging")
    require(marker.get("source_manifest_sha256") == manifest_hash,
            "root acceptance source differs")
    require(marker.get("delivered_binary_sha256") == delivered_hashes,
            "root acceptance original images differ")
    require(marker.get("checks") == {"latency": True, "memory": True, "binary_review": True},
            "root latency, memory and binary-review gates must all pass")
    evidence = marker.get("evidence_sha256")
    require(type(evidence) is dict and len(evidence) >= 3, "three bound acceptance evidence files required")
    for name, digest in evidence.items():
        safe_evidence_name(name)
        require(type(digest) is str and len(digest) == 64 and all(c in "0123456789abcdef" for c in digest),
                "invalid acceptance evidence digest")


def finish(status="REJECTED_FOR_PROMOTION", acceptance=None):
    source_binding()
    require(status in ("REJECTED_FOR_PROMOTION", "QUALIFIED_INTERNAL"), "unknown promotion status")
    delivered_hashes = {host: read(OUT / host / "package/provenance.json")["binary_sha256"] for host in TARGETS}
    if status == "QUALIFIED_INTERNAL":
        require(acceptance is not None and acceptance.is_file(), "root acceptance file is required")
        marker = read(acceptance)
        check_promotion_acceptance(marker, sha(FINAL / "source.json"), delivered_hashes)
        for name, digest in marker["evidence_sha256"].items():
            original = ROOT / name
            require(original.is_file() and sha(original) == digest, "root acceptance evidence changed")
        shutil.copyfile(acceptance, OUT / "promotion-acceptance.json")
        for name in marker["evidence_sha256"]:
            destination = OUT / "acceptance-evidence" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
    result = {"profile": PROFILE, "milestone": "M10", "created_utc": utc(),
              "source_manifest_sha256": sha(FINAL / "source.json"), "source_archive_sha256": sha(OUT / "source.tar.gz"),
              "platforms": {}, "third_party_reproduction_claimed": False,
              "full_M10_qualification_implied_by_distribution": False,
              "promotion_status": status,
              "promotion_reason": "Root bounded internal qualification passed; external review remains open" if status == "QUALIFIED_INTERNAL" else
                                  "No root bounded acceptance for this M10 candidate; distribution is not promotable"}
    if status == "QUALIFIED_INTERNAL":
        result["root_acceptance_sha256"] = sha(OUT / "promotion-acceptance.json")
        result["acceptance_evidence_sha256"] = marker["evidence_sha256"]
    for host, triple in TARGETS.items():
        folder = OUT / host
        package = folder / "package"
        save(package / "PROMOTION_STATUS.json", {"status": result["promotion_status"], "reason": result["promotion_reason"],
             "canonical_binary_replaced": False, "scope": "bounded internally qualified distribution; external audit separate" if status == "QUALIFIED_INTERNAL" else
                                                            "negative distribution evidence, not an accepted release"})
        validation = package / "validation"
        validation.mkdir()
        for name in ("repeat-build.json", "comparison.json", "metadata.json", "native-dependencies.txt",
                     "repeat-artifacts.jsonl", "repeat-build.log", "original-validation.json", "repeat-validation.json",
                     "original-self-test.stdout", "original-self-test.stderr", "repeat-self-test.stdout", "repeat-self-test.stderr"):
            shutil.copyfile(folder / name, validation / name)
        if (folder / "repeat-execution-controller.py").is_file():
            shutil.copyfile(folder / "repeat-execution-controller.py", validation / "repeat-execution-controller.py")
        shutil.copyfile(FINAL / host / "build.json", validation / "original-build.json")
        shutil.copyfile(OUT / "measured-source.json", validation / "measured-source.json")
        shutil.copyfile(OUT / "repeat-controller.py", validation / "repeat-controller.py")
        if status == "QUALIFIED_INTERNAL":
            shutil.copyfile(OUT / "promotion-acceptance.json", validation / "promotion-acceptance.json")
        save(package / "SHA256SUMS.json", inventory(package))
        members = inventory(package)
        archive = OUT / ("majax-r6-m10-" + triple + (".zip" if host == "windows" else ".tar.gz"))
        zip_package(package, archive) if host == "windows" else deterministic_tar(package, archive, 0)
        verify_archive(archive, members)
        result["platforms"][host] = {"archive": archive.name, "archive_sha256": sha(archive), "package_sha256": members,
                                    "diagnostics_sha256": inventory(folder / "diagnostics")}
    save(OUT / "result.json", result)
    return verify(OUT)


def verify(out):
    """Read-only verification: no compiler, executable or external process."""
    result = read(out / "result.json")
    source = read(out / "source-manifest.json")
    measured = read(out / "measured-source.json")
    require(result["profile"] == source["profile"] == PROFILE, "distribution profile differs")
    require(result["third_party_reproduction_claimed"] is False and result["full_M10_qualification_implied_by_distribution"] is False, "distribution scope differs")
    require(result["promotion_status"] in ("REJECTED_FOR_PROMOTION", "QUALIFIED_INTERNAL"), "unknown distribution promotion status")
    if result["promotion_status"] == "QUALIFIED_INTERNAL":
        require(sha(out / "promotion-acceptance.json") == result["root_acceptance_sha256"], "root acceptance file changed")
        root_acceptance = read(out / "promotion-acceptance.json")
        delivered_hashes = {host: read(out / host / "package/provenance.json")["binary_sha256"] for host in TARGETS}
        check_promotion_acceptance(root_acceptance, result["source_manifest_sha256"], delivered_hashes)
        require(root_acceptance["evidence_sha256"] == result["acceptance_evidence_sha256"], "accepted evidence map differs")
        for name, digest in result["acceptance_evidence_sha256"].items():
            require(sha(out / "acceptance-evidence" / safe_evidence_name(name)) == digest, "accepted evidence file changed")
    require(sha(out / "measured-source.json") == result["source_manifest_sha256"] == source["measured_manifest_sha256"], "distribution source binding differs")
    require(measured["source_sha256"] == source["compiled_source_sha256"], "compiled source map differs")
    require(all(source["files"].get(n) == s for n, s in measured["source_sha256"].items()), "captured compilation input absent from source archive")
    require(inventory(out / "source") == source["files"], "compact source changed")
    require(sha(out / "source.tar.gz") == result["source_archive_sha256"], "source archive changed")
    verify_archive(out / "source.tar.gz", source["files"])
    require(set(result["platforms"]) == set(TARGETS), "two distribution hosts required")
    for host, row in result["platforms"].items():
        folder = out / host
        package = folder / "package"
        require(inventory(package) == row["package_sha256"], "package member changed")
        require(inventory(folder / "diagnostics") == row["diagnostics_sha256"], "diagnostic notice changed")
        diagnostics = read(folder / "diagnostics/dependencies.json")
        original_build = read(package / "validation/original-build.json")
        require(original_build["source_manifest_sha256"] == result["source_manifest_sha256"], "original build source differs")
        require(diagnostics["source_manifest_sha256"] == result["source_manifest_sha256"], "diagnostic notice source differs")
        require(diagnostics["diagnostic_image_sha256"] == {k: v["sha256"] for k, v in original_build["binaries"].items() if k != "delivered"}, "diagnostic image notice binding differs")
        require(sha(out / row["archive"]) == row["archive_sha256"], "package archive changed")
        verify_archive(out / row["archive"], row["package_sha256"])
        checksums = inventory(package)
        checksums.pop("SHA256SUMS.json")
        require(checksums == read(package / "SHA256SUMS.json"), "package checksum map differs")
        suffix = ".exe" if host == "windows" else ""
        original = package / "bin" / ("kem1536" + suffix)
        repeated = folder / ("repeat" + suffix)
        provenance = read(package / "provenance.json")
        repeated_build = read(folder / "repeat-build.json")
        if "execution_controller_sha256" in repeated_build:
            require(sha(folder / "repeat-execution-controller.py") == repeated_build["execution_controller_sha256"]
                    == sha(package / "validation/repeat-execution-controller.py"), "repeat execution control changed")
        promotion = read(package / "PROMOTION_STATUS.json")
        require(promotion["status"] == result["promotion_status"] and promotion["canonical_binary_replaced"] is False, "package rejection status differs")
        if result["promotion_status"] == "QUALIFIED_INTERNAL":
            require(sha(package / "validation/promotion-acceptance.json") == result["root_acceptance_sha256"], "packaged root acceptance differs")
        require(sha(original) == provenance["binary_sha256"] and sha(repeated) == provenance["repeat_binary_sha256"], "package image identity differs")
        require(sha(original) == original_build["binaries"]["delivered"]["sha256"], "package does not contain original delivered image")
        require(sha(package / "validation/measured-source.json") == result["source_manifest_sha256"], "packaged measured source differs")
        for name in ("repeat-build.json", "comparison.json", "metadata.json", "native-dependencies.txt",
                     "repeat-artifacts.jsonl", "repeat-build.log", "original-validation.json", "repeat-validation.json",
                     "original-self-test.stdout", "original-self-test.stderr", "repeat-self-test.stdout", "repeat-self-test.stderr"):
            require(sha(package / "validation" / name) == sha(folder / name), "packaged validation copy differs")
        require(compare(original.read_bytes(), repeated.read_bytes(), host) == provenance["comparison"], "repeat comparison differs")
        require(provenance["research_vectors_enabled"] is False and provenance["external_audit_claimed"] is False, "package assurance scope differs")
        for label in ("original", "repeat"):
            check = read(folder / (label + "-validation.json"))
            expected = provenance[label + "_self_test"]
            require(check == expected and check["self_test_exit_code"] == 0, "CLI validation differs")
            test = check["self_test"]
            require((test["fresh_round_trips"], test["implicit_rejections_checked"], test["secrets_printed"]) == (16, 16, False), "CLI smoke scope differs")
            require(len(check["research_commands_rejected"]) == 5 and all(c["exit_code"] == 1 for c in check["research_commands_rejected"]), "research command rejection differs")
        require(sha(package / "source.tar.gz") == result["source_archive_sha256"], "packaged source archive differs")
        for notices in (package, folder / "diagnostics"):
            dependencies = read(notices / "dependencies.json")
            for dependency in dependencies["packages"]:
                for license_file in dependency["license_files"]:
                    require(sha(notices / license_file["path"]) == license_file["sha256"], "dependency license text differs")
            for name in ("COPYRIGHT-library.html", "COPYRIGHT.html"):
                require((notices / "licenses/toolchain" / name).is_file(), "toolchain copyright missing")
    return {"verified": True, "hosts": sorted(result["platforms"]), "source_manifest_sha256": result["source_manifest_sha256"],
            "promotion_status": result["promotion_status"],
            "scope": "distribution only; external audit and full M10 qualification separate"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("setup", "repeat", "diagnostics", "finish", "verify"))
    parser.add_argument("--host", choices=tuple(TARGETS))
    parser.add_argument("--output", type=Path, default=OUT)
    parser.add_argument("--build-root", type=Path, default=FINAL)
    parser.add_argument("--target-root", type=Path, default=TARGET_ROOT)
    parser.add_argument("--promotion-status", choices=("REJECTED_FOR_PROMOTION", "QUALIFIED_INTERNAL"), default="REJECTED_FOR_PROMOTION")
    parser.add_argument("--acceptance", type=Path)
    parser.add_argument("--resume-setup", action="store_true")
    args = parser.parse_args()
    # These paths select new acquisition roots. Historical outputs are not
    # rewritten: setup/targets/archives use exclusive creation throughout.
    globals()["FINAL"] = args.build_root.resolve()
    globals()["OUT"] = args.output.resolve()
    globals()["TARGET_ROOT"] = args.target_root.resolve()
    require(FINAL.is_relative_to(ROOT / "artifacts/generated") and FINAL != ROOT / "artifacts/generated", "captured project build root required")
    require(OUT.is_relative_to(ROOT / "artifacts/generated") and OUT != ROOT / "artifacts/generated" if args.action != "verify" else True, "new project distribution root required")
    require(TARGET_ROOT.is_relative_to(ROOT / "target") and TARGET_ROOT != ROOT / "target", "project-local repeat target required")
    if args.action == "setup":
        setup(args.resume_setup)
    elif args.action == "repeat":
        repeat(args.host)
    elif args.action == "diagnostics":
        diagnostic_inventory(args.host)
    elif args.action == "finish":
        print(json.dumps(finish(args.promotion_status, args.acceptance)))
    else:
        print(json.dumps(verify(args.output)))


if __name__ == "__main__":
    main()
