"""Snapshot, inventory and verify the M04 distribution without global tools.

The snapshot is the Git source inventory plus nonignored new working files.
Build products, secrets ignored by Git and tool caches are never source inputs.
"""

import argparse
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile

from export_publication import EXCLUDED as PUBLIC_EXCLUDED


def stream_digest(handle):
    value = hashlib.sha256()
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        value.update(chunk)
    return value.hexdigest()


def digest(path):
    with Path(path).open("rb") as handle:
        return stream_digest(handle)


def cargo_lock(path):
    """Read the four scalar package fields emitted by Cargo (also on Python 3.10).

    This is deliberately not a TOML parser: Cargo generates double-quoted JSON-
    compatible scalar strings for these fields. Missing/duplicate fields fail.
    Dependency resolution itself comes from Cargo metadata and compiler messages.
    """
    data = Path(path).read_text(encoding="utf-8")
    packages = []
    for block in re.split(r"(?m)^\[\[package\]\]\s*$", data)[1:]:
        fields = {}
        for key, value in re.findall(r'(?m)^(name|version|source|checksum) = ("[^\n]*")\s*$', block):
            if key in fields:
                raise ValueError(f"duplicate Cargo.lock field: {key}")
            fields[key] = json.loads(value)
        if not {"name", "version"} <= fields.keys():
            raise ValueError("unrecognized Cargo.lock package block")
        packages.append(fields)
    if not packages:
        raise ValueError("Cargo.lock package inventory is empty")
    return {"package": packages}


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def safe_path(base, name):
    path = PurePosixPath(name.replace("\\", "/"))
    if path.is_absolute() or not path.parts or any(p in ("..", ".") for p in path.parts):
        raise ValueError(f"unsafe manifest path: {name}")
    result = (Path(base) / str(path)).resolve()
    if not result.is_relative_to(Path(base).resolve()):
        raise ValueError(f"path escapes its root: {name}")
    return result


def file_manifest(root):
    return {p.relative_to(root).as_posix(): digest(p)
            for p in sorted(Path(root).rglob("*")) if p.is_file()}


def check_files(root, expected):
    actual = file_manifest(Path(root))
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        added = sorted(set(actual) - set(expected))
        changed = sorted(k for k in set(actual) & set(expected) if actual[k] != expected[k])
        raise ValueError(f"file inventory mismatch: missing={missing[:5]}, added={added[:5]}, changed={changed[:5]}")


def deterministic_tar(folder, output, epoch):
    """No user names, absolute paths, wall timestamps or host file modes."""
    folder, output = Path(folder), Path(output)
    with output.open("wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=epoch) as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as archive:
            for path in sorted(folder.rglob("*")):
                if path.is_symlink():
                    raise ValueError("symbolic links are not accepted in a release archive")
                if not path.is_file():
                    continue
                name = path.relative_to(folder).as_posix()
                info = tarfile.TarInfo(name)
                info.size, info.mtime = path.stat().st_size, epoch
                info.mode = 0o755 if path.suffix == ".sh" or name.startswith("bin/") else 0o644
                with path.open("rb") as source:
                    archive.addfile(info, source)


def verify_source_archive(path, files):
    if set(files) & PUBLIC_EXCLUDED:
        raise ValueError("source archive contains files excluded from public distribution")
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        if len(members) != len(files) or {p.name for p in members} != set(files):
            raise ValueError("source archive inventory differs from source manifest")
        for item in members:
            if not item.isfile():
                raise ValueError("source archive contains a non-file entry")
            if stream_digest(archive.extractfile(item)) != files[item.name]:
                raise ValueError(f"source archive hash mismatch: {item.name}")


def git(root, *arguments):
    return subprocess.check_output(["git", "-C", str(root), *arguments])


def snapshot(root, output):
    root, output = Path(root).resolve(), Path(output).resolve()
    allowed = root / "artifacts/generated/m04-distribution"
    if not output.is_relative_to(allowed) or output == allowed:
        raise ValueError("a new named output below artifacts/generated/m04-distribution is required")
    if output.exists():
        raise ValueError("snapshot output already exists; select a new run ID")
    raw_names = git(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z")
    names = sorted(set(n.decode("utf-8") for n in raw_names.split(b"\0") if n))
    selected = []
    for name in names:
        if name in PUBLIC_EXCLUDED:
            continue
        if name.startswith((".git/", ".tools/", "target/", "artifacts/generated/", "fuzz/target/")):
            raise ValueError(f"forbidden source root in Git inventory: {name}")
        path = safe_path(root, name)
        if path.is_symlink():
            raise ValueError(f"source link is not supported: {name}")
        if path.is_file():
            selected.append((name, path, digest(path)))
    output.mkdir(parents=True)
    source = output / "source"
    source.mkdir()
    for name, path, expected in selected:
        destination = safe_path(source, name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
        if digest(destination) != expected:
            raise ValueError(f"source changed during copying: {name}")
    for name, path, expected in selected:
        if digest(path) != expected:
            raise ValueError(f"working source changed during snapshot: {name}")
    head = git(root, "rev-parse", "HEAD").decode().strip()
    epoch = int(git(root, "show", "-s", "--format=%ct", "HEAD").decode().strip())
    manifest = dict(schema="m04-source-v1", git_head=head,
                    source_kind="tracked working files plus nonignored new files; not necessarily HEAD",
                    source_date_epoch=epoch,
                    git_status=git(root, "status", "--porcelain=v1").decode("utf-8"),
                    excluded_paths=sorted(PUBLIC_EXCLUDED),
                    files={name: expected for name, _, expected in selected})
    check_files(source, manifest["files"])
    write_json(output / "source-manifest.json", manifest)
    deterministic_tar(source, output / "source.tar.gz", epoch)
    verify_source_archive(output / "source.tar.gz", manifest["files"])
    print(json.dumps(dict(source_files=len(selected), git_head=head,
                          archive_sha256=digest(output / "source.tar.gz"))))


def copy_source(snapshot_dir, destination):
    snapshot_dir, destination = Path(snapshot_dir), Path(destination)
    manifest = read_json(snapshot_dir / "source-manifest.json")
    if set(manifest["files"]) & PUBLIC_EXCLUDED:
        raise ValueError("snapshot contains files excluded from the public distribution")
    verify_source_archive(snapshot_dir / "source.tar.gz", manifest["files"])
    check_files(snapshot_dir / "source", manifest["files"])
    if destination.exists():
        raise ValueError("build source directory already exists")
    shutil.copytree(snapshot_dir / "source", destination)
    check_files(destination, manifest["files"])


def compiled_inventory(metadata, messages, lock):
    packages = {p["id"]: p for p in metadata["packages"]}
    compiled = {}
    for line in messages.splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if item.get("reason") == "compiler-artifact":
            compiled.setdefault(item["package_id"], set()).update(item.get("features", []))
    roots = [p["id"] for p in packages.values() if p["name"] == "kem1536-cli"]
    if len(roots) != 1 or roots[0] not in compiled:
        raise ValueError("kem1536-cli build artifact not found")
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    runtime, pending = set(), roots[:]
    while pending:
        identity = pending.pop()
        if identity in runtime or identity not in compiled:
            continue
        package = packages[identity]
        if any("proc-macro" in t["kind"] for t in package["targets"]):
            continue
        runtime.add(identity)
        for dep in nodes[identity]["deps"]:
            if any(kind["kind"] is None for kind in dep["dep_kinds"]):
                pending.append(dep["pkg"])
    lock_map = {(p["name"], p["version"], p.get("source")): p for p in lock["package"]}
    result = []
    for identity in sorted(compiled, key=lambda x: (packages[x]["name"], packages[x]["version"])):
        p = packages[identity]
        if p["name"] in ("kem1536", "kem1536-cli") and "research-vectors" in compiled[identity]:
            raise ValueError("research-vectors must be disabled in the shipped binary")
        source = p.get("source")
        locked = lock_map.get((p["name"], p["version"], source))
        if locked is None:
            raise ValueError(f"compiled package absent from Cargo.lock: {p['name']} {p['version']}")
        result.append(dict(name=p["name"], version=p["version"], source=source or "project source snapshot",
                           lock_checksum=locked.get("checksum"), license=p.get("license"),
                           features=sorted(compiled[identity]),
                           category="normal_dependency_graph" if identity in runtime else "compile_time_only",
                           metadata_id=identity))
    return result


def license_inventory(records, metadata, folder):
    folder = Path(folder)
    by_id = {p["id"]: p for p in metadata["packages"]}
    for record in records:
        package = by_id[record.pop("metadata_id")]
        if not package.get("source"):
            record["license_files"] = []
            continue
        package_root = Path(package["manifest_path"]).parent
        files = [p for p in package_root.iterdir() if p.is_file()
                 and p.name.upper().startswith(("LICENSE", "COPYING", "NOTICE", "UNLICENSE"))]
        if package.get("license_file"):
            extra = Path(package["license_file"])
            extra = extra if extra.is_absolute() else package_root / extra
            if extra.is_file():
                files.append(extra)
        if not files:
            raise ValueError(f"no license text found for compiled dependency {record['name']}")
        name = f"{record['name']}-{record['version']}"
        target = folder / name
        target.mkdir(parents=True)
        record["license_files"] = []
        for path in sorted(set(files)):
            shutil.copyfile(path, target / path.name)
            record["license_files"].append(dict(path=f"licenses/dependencies/{name}/{path.name}", sha256=digest(path)))


def native_dependencies(text, platform):
    if platform == "windows":
        values = sorted(set(re.findall(r"DLL Name:\s*(\S+)", text)), key=str.lower)
        if not values:
            raise ValueError("PE import inventory is empty")
        return dict(kind="PE import table; system DLLs are not bundled", libraries=values)
    values = sorted(set(re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", text)))
    if not values:
        raise ValueError("ELF NEEDED inventory is empty")
    versions = sorted(set(re.findall(r"GLIBC_([0-9.]+)", text)), key=lambda s: tuple(map(int, s.split("."))))
    return dict(kind="ELF NEEDED and symbol versions; system libraries are not bundled", libraries=values,
                glibc_versions=versions, highest_glibc_version=versions[-1] if versions else None)


def compiled_input_names(files):
    """Conservative superset of CLI compilation inputs, also covering workspace src.

    Integration tests are intentionally excluded: Cargo release --bin does not
    compile them. Explicit includes outside src are included as well.
    """
    fixed = {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "build.rs",
             "references/manifest.json", "fuzz/fixtures/cases.bin"}
    return {name for name in files if name in fixed or name.startswith((".cargo/", "profiles/", "vectors/"))
            or (name.startswith("crates/") and ("/src/" in name or name.endswith(("/Cargo.toml", "/build.rs"))))}


def compare_compiled_inputs(reference, current):
    old = {name: reference[name] for name in compiled_input_names(reference)}
    new = {name: current[name] for name in compiled_input_names(current)}
    if old != new:
        changed = sorted(name for name in set(old) | set(new) if old.get(name) != new.get(name))
        raise ValueError(f"compiled inputs changed; binary reuse forbidden: {changed}")
    return old


def check_literal_includes(source, manifest, compiled):
    """Every literal include in the selected Rust src must fall inside the superset."""
    source = Path(source).resolve()
    for name in compiled:
        if not name.endswith(".rs"):
            continue
        file = safe_path(source, name)
        for included in re.findall(r'include_(?:str|bytes)!\s*\(\s*"([^"]+)"', file.read_text(encoding="utf-8")):
            target = (file.parent / included).resolve()
            if not target.is_relative_to(source):
                raise ValueError(f"compile-time include escapes the source: {name}: {included}")
            relative = target.relative_to(source).as_posix()
            if relative not in manifest or relative not in compiled:
                raise ValueError(f"compile-time include missing from reuse proof: {relative}")


def repackage(snapshot_dir, reference_dir, validations):
    """Reuse proven binaries only after exact equality of all production inputs."""
    snapshot_dir, reference_dir = Path(snapshot_dir).resolve(), Path(reference_dir).resolve()
    if snapshot_dir == reference_dir or snapshot_dir.parent != reference_dir.parent:
        raise ValueError("distinct sibling snapshots below m04-distribution are required")
    verify(reference_dir)
    old = read_json(reference_dir / "source-manifest.json")
    new = read_json(snapshot_dir / "source-manifest.json")
    check_files(snapshot_dir / "source", new["files"])
    verify_source_archive(snapshot_dir / "source.tar.gz", new["files"])
    inputs = compare_compiled_inputs(old["files"], new["files"])
    check_literal_includes(reference_dir / "source", old["files"], inputs)
    check_literal_includes(snapshot_dir / "source", new["files"], inputs)
    differences = {name: dict(before=old["files"].get(name), after=new["files"].get(name))
                   for name in sorted(set(old["files"]) | set(new["files"]))
                   if old["files"].get(name) != new["files"].get(name)}
    proof = dict(schema="m04-compiled-input-equality-v1", reference_run=reference_dir.name,
                 current_run=snapshot_dir.name, compiled_input_count=len(inputs),
                 compiled_input_sha256=inputs,
                 reference_source_manifest_sha256=digest(reference_dir / "source-manifest.json"),
                 current_source_manifest_sha256=digest(snapshot_dir / "source-manifest.json"),
                 noncompiled_changes=differences, all_compiled_inputs_exactly_identical=True,
                 new_compilations_in_current_run=0,
                 scope="Cargo/toolchain/config, all workspace src/manifests/build scripts, profiles, vectors, and literal includes; integration tests and documentation excluded")
    proof_path = snapshot_dir / "compiled-input-equality.json"
    write_json(proof_path, proof)
    for platform in ("windows", "linux"):
        reference_result = read_json(reference_dir / platform / "result.json")
        previous = reference_result["provenance"]
        if previous.get("two_isolated_builds_identical") is not True:
            raise ValueError("reference run must contain actual successful double builds")
        build = snapshot_dir / platform
        if build.exists():
            raise ValueError("repackaged target already exists")
        package = build / "package"
        shutil.copytree(reference_dir / platform / "package", package)
        extension = ".exe" if platform == "windows" else ""
        binary = package / "bin" / f"kem1536{extension}"
        if digest(binary) != previous["binary_sha256"]:
            raise ValueError("copied reference binary hash mismatch")
        for name in ("LICENSE", "NOTICE", "SECURITY.md", "THIRD_PARTY_NOTICES.md"):
            shutil.copyfile(snapshot_dir / "source" / name, package / name)
        shutil.copyfile(snapshot_dir / "source.tar.gz", package / "source.tar.gz")
        shutil.copyfile(snapshot_dir / "source-manifest.json", package / "source-manifest.json")
        shutil.copyfile(proof_path, package / "validation/compiled-input-equality.json")
        shutil.copyfile(reference_dir / "source-manifest.json", package / f"validation/{reference_dir.name}-source-manifest.json")
        shutil.copyfile(reference_dir / platform / "package/provenance.json", package / f"validation/{reference_dir.name}-build-provenance.json")
        validation_hashes = {}
        for path in validations:
            path = Path(path)
            if not path.is_file():
                raise ValueError(f"validation evidence missing: {path}")
            shutil.copyfile(path, package / "validation" / path.name)
            validation_hashes[path.name] = digest(path)
        provenance = dict(schema="m04-distribution-repackage-v1", platform=platform,
                          profile=previous["profile"], binary_sha256=previous["binary_sha256"],
                          source_git_head=new["git_head"], source_kind=new["source_kind"],
                          source_manifest_sha256=digest(snapshot_dir / "source-manifest.json"),
                          source_archive_sha256=digest(snapshot_dir / "source.tar.gz"),
                          new_compilations_in_this_run=0, binary_reused_from_reference_run=True,
                          reference_double_build_run=reference_dir.name,
                          two_isolated_builds_identical_in_reference_run=True,
                          reference_result_sha256=digest(reference_dir / platform / "result.json"),
                          reference_source_manifest_sha256=digest(reference_dir / "source-manifest.json"),
                          reference_archive_sha256=reference_result["archive_sha256"],
                          compiled_input_equality_sha256=digest(proof_path),
                          corrected_validation_logs=validation_hashes,
                          environment_of_reference_build=previous["environment"],
                          research_vectors_enabled=False, certification=False,
                          scope="Current public sources; production inputs exactly equal to reference double builds. No new compilation performed.")
        write_json(package / "provenance.json", provenance)
        with (package / "USAGE.md").open("a", encoding="utf-8") as handle:
            handle.write(f"\nThis package reuses the two-build evidence from {reference_dir.name}; no new build was run.\n"
                         "All production compilation inputs are byte-identical; see validation/compiled-input-equality.json.\n"
                         "Sources include subsequent integration-test, report and review-tool corrections.\n")
        check = file_manifest(package)
        check.pop("SHA256SUMS.json", None)
        write_json(package / "SHA256SUMS.json", check)
        environment = previous["environment"]
        archive = build / f"kem1536-r1-{environment['target']}.tar.gz"
        deterministic_tar(package, archive, new["source_date_epoch"])
        result = dict(provenance=provenance, archive=archive.name, archive_sha256=digest(archive),
                      package_files=len(check), compiled_packages=reference_result["compiled_packages"],
                      native_dependencies=reference_result["native_dependencies"])
        write_json(build / "result.json", result)
        print(json.dumps(dict(platform=platform, archive_sha256=result["archive_sha256"],
                              binary_sha256=previous["binary_sha256"], compiled_inputs_identical=len(inputs),
                              new_compilations=0)))
    verify(snapshot_dir)


def seal(snapshot_dir, platform, rust_root):
    snapshot_dir, rust_root = Path(snapshot_dir), Path(rust_root)
    build = snapshot_dir / platform
    manifest = read_json(snapshot_dir / "source-manifest.json")
    verify_source_archive(snapshot_dir / "source.tar.gz", manifest["files"])
    extension = ".exe" if platform == "windows" else ""
    binaries = [build / f"build-{letter}/target" / read_json(build / "environment.json")["target"]
                / "release" / f"kem1536{extension}" for letter in ("a", "b")]
    hashes = [digest(path) for path in binaries]
    if hashes[0] != hashes[1]:
        raise ValueError(f"isolated binaries are not identical: {hashes}")
    for letter in ("a", "b"):
        # Cargo.lock and all source inputs must remain unchanged by --locked builds.
        check_files(build / f"build-{letter}/source", manifest["files"])
        test = read_json(build / f"build-{letter}/self-test.json")
        if (test.get("profile") != "KEM1536-DEV-Q7681-R1"
                or test.get("fresh_round_trips") != 16
                or test.get("implicit_rejections_checked") != 16
                or test.get("secrets_printed") is not False):
            raise ValueError("shipped executable self-test report is incomplete")
    metadata = read_json(build / "metadata-a.json")
    second_metadata = read_json(build / "metadata-b.json")
    lock = cargo_lock(snapshot_dir / "source/Cargo.lock")
    records = compiled_inventory(metadata, (build / "build-a/cargo.jsonl").read_text(encoding="utf-8-sig"), lock)
    second = compiled_inventory(second_metadata, (build / "build-b/cargo.jsonl").read_text(encoding="utf-8-sig"), lock)
    comparison = lambda rows: [{k: v for k, v in row.items() if k != "metadata_id"} for row in rows]
    if comparison(records) != comparison(second):
        raise ValueError("two builds did not compile the same package/features inventory")
    package = build / "package"
    if package.exists():
        raise ValueError("sealed package already exists")
    (package / "bin").mkdir(parents=True)
    shutil.copyfile(binaries[0], package / "bin" / binaries[0].name)
    for name in ("LICENSE", "NOTICE", "SECURITY.md", "THIRD_PARTY_NOTICES.md"):
        shutil.copyfile(snapshot_dir / "source" / name, package / name)
    shutil.copyfile(snapshot_dir / "source.tar.gz", package / "source.tar.gz")
    shutil.copyfile(snapshot_dir / "source-manifest.json", package / "source-manifest.json")
    (package / "validation").mkdir()
    for letter in ("a", "b"):
        shutil.copyfile(build / f"build-{letter}/self-test.json", package / f"validation/self-test-{letter}.json")
    license_inventory(records, metadata, package / "licenses/dependencies")
    tool_license = rust_root / "share/doc/rust"
    (package / "licenses/toolchain").mkdir(parents=True)
    for name in ("COPYRIGHT-library.html", "COPYRIGHT.html"):
        shutil.copyfile(tool_license / name, package / "licenses/toolchain" / name)
    shutil.copytree(tool_license / "licenses", package / "licenses/toolchain/texts")
    native = native_dependencies((build / "native-dependencies.txt").read_text(encoding="utf-8-sig"), platform)
    write_json(package / "dependencies.json", dict(schema="m04-dependencies-v1", packages=records, native=native,
               normal_graph_is_not_linker_symbol_attribution=True,
               lock_packages_total=len(lock["package"]), actually_compiled_packages=len(records)))
    environment = read_json(build / "environment.json")
    provenance = dict(schema="m04-distribution-v1", profile="KEM1536-DEV-Q7681-R1", platform=platform,
                      source_manifest_sha256=digest(snapshot_dir / "source-manifest.json"),
                      source_archive_sha256=digest(snapshot_dir / "source.tar.gz"),
                      source_git_head=manifest["git_head"], source_kind=manifest["source_kind"],
                      environment=environment, binary_sha256=hashes[0],
                      two_isolated_builds_identical=True, research_vectors_enabled=False,
                      isolation="same host and dependency cache; distinct source and target directories; no containers",
                      certification=False)
    write_json(package / "provenance.json", provenance)
    usage = """# Experimental R1 release\n\nThis package is a research distribution, without production-security or certification claims.\n\nRun `bin/kem1536 dev-profile` and `bin/kem1536 dev-self-test` (add `.exe` on Windows).\nThe self-test uses fresh OS randomness and prints no secret keys. `research-vectors` is disabled.\n\nExtract source.tar.gz to use the Rust library through `crates/kem1536`, with Rust 1.91.1.\nCargo.lock pins crate versions; dependencies are not vendored. A fresh computer needs Cargo\nregistry access and the native target/toolchain described in provenance.json. Read README.md\nand docs/DISTRIBUTION_M04.md in the sources. The CLI is a diagnostics interface; library\nconsumers call keygen, encapsulate and decapsulate through the Rust API.\n\nThe system libraries listed in dependencies.json remain prerequisites and are not included.\nNormal Rust dependency graph membership does not prove every dependency symbol survives\nlinker garbage collection. Compile-time-only crates and toolchain notices are listed separately.\n"""
    (package / "USAGE.md").write_text(usage, encoding="utf-8")
    check = file_manifest(package)
    write_json(package / "SHA256SUMS.json", check)
    archive = build / f"kem1536-r1-{environment['target']}.tar.gz"
    deterministic_tar(package, archive, manifest["source_date_epoch"])
    summary = dict(provenance=provenance, archive=archive.name, archive_sha256=digest(archive),
                   package_files=len(check), compiled_packages=len(records), native_dependencies=native)
    write_json(build / "result.json", summary)
    print(json.dumps(summary, indent=2))


def verify(snapshot_dir):
    snapshot_dir = Path(snapshot_dir)
    manifest = read_json(snapshot_dir / "source-manifest.json")
    check_files(snapshot_dir / "source", manifest["files"])
    verify_source_archive(snapshot_dir / "source.tar.gz", manifest["files"])
    verified = []
    for platform in ("windows", "linux"):
        result_path = snapshot_dir / platform / "result.json"
        if not result_path.is_file():
            continue
        result = read_json(result_path)
        archive = snapshot_dir / platform / result["archive"]
        if digest(archive) != result["archive_sha256"]:
            raise ValueError(f"distribution archive changed: {platform}")
        package = snapshot_dir / platform / "package"
        provenance = read_json(package / "provenance.json")
        extension = ".exe" if platform == "windows" else ""
        if digest(package / "bin" / f"kem1536{extension}") != provenance["binary_sha256"]:
            raise ValueError("packaged executable differs from its provenance")
        if provenance.get("schema") == "m04-distribution-repackage-v1":
            proof_path = package / "validation/compiled-input-equality.json"
            proof = read_json(proof_path)
            if (digest(proof_path) != provenance["compiled_input_equality_sha256"]
                    or proof["current_source_manifest_sha256"] != digest(snapshot_dir / "source-manifest.json")
                    or provenance.get("new_compilations_in_this_run") != 0):
                raise ValueError("binary reuse proof disagrees with current source provenance")
            old_manifest_path = safe_path(package, f"validation/{proof['reference_run']}-source-manifest.json")
            old_build_path = safe_path(package, f"validation/{proof['reference_run']}-build-provenance.json")
            old_manifest, old_build = read_json(old_manifest_path), read_json(old_build_path)
            if (digest(old_manifest_path) != proof["reference_source_manifest_sha256"]
                    or old_build.get("two_isolated_builds_identical") is not True
                    or old_build["binary_sha256"] != provenance["binary_sha256"]
                    or old_build["environment"] != provenance["environment_of_reference_build"]):
                raise ValueError("binary reuse does not match original double-build evidence")
            compared = compare_compiled_inputs(old_manifest["files"], manifest["files"])
            if compared != proof["compiled_input_sha256"] or len(compared) != proof["compiled_input_count"]:
                raise ValueError("compiled input equality proof is incomplete")
        expected = read_json(package / "SHA256SUMS.json")
        actual = file_manifest(package)
        actual.pop("SHA256SUMS.json")
        if actual != expected:
            raise ValueError(f"package content changed: {platform}")
        with tarfile.open(archive, "r:gz") as tar:
            members = {item.name: item for item in tar.getmembers()}
            if set(members) != set(actual) | {"SHA256SUMS.json"}:
                raise ValueError("package archive inventory differs from package directory")
            for name, item in members.items():
                safe_path(package, name)
                if not item.isfile():
                    raise ValueError("release archive contains a non-file entry")
                stream = tar.extractfile(item)
                if stream_digest(stream) != digest(package / name):
                    raise ValueError(f"archive bytes mismatch: {name}")
        verified.append(platform)
    print(json.dumps(dict(source_files=len(manifest["files"]), verified_release_targets=verified)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    command = sub.add_parser("snapshot")
    command.add_argument("--root", type=Path, required=True)
    command.add_argument("--output", type=Path, required=True)
    command = sub.add_parser("copy-source")
    command.add_argument("--snapshot", type=Path, required=True)
    command.add_argument("--destination", type=Path, required=True)
    command = sub.add_parser("seal")
    command.add_argument("--snapshot", type=Path, required=True)
    command.add_argument("--platform", choices=("windows", "linux"), required=True)
    command.add_argument("--rust-root", type=Path, required=True)
    command = sub.add_parser("verify")
    command.add_argument("--snapshot", type=Path, required=True)
    command = sub.add_parser("repackage")
    command.add_argument("--snapshot", type=Path, required=True)
    command.add_argument("--reference", type=Path, required=True)
    command.add_argument("--validation-file", type=Path, action="append", default=[])
    args = parser.parse_args()
    if args.action == "snapshot":
        snapshot(args.root, args.output)
    elif args.action == "copy-source":
        copy_source(args.snapshot, args.destination)
    elif args.action == "seal":
        seal(args.snapshot, args.platform, args.rust_root)
    elif args.action == "repackage":
        repackage(args.snapshot, args.reference, args.validation_file)
    else:
        verify(args.snapshot)


if __name__ == "__main__":
    main()
