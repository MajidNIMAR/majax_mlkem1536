"""Repeat the M08 CLI once per host and package the original inventoried images.

Windows coordinator, with Linux builds/execution through the same WSL recipe
as run_m08. Real execution requires both root acceptance markers. No previous
artifact, source snapshot, compiler target or control is replaced.
The import review concerns default-feature API consumers; it does not prove
erasure of the delivered CLI's PKE. The CLI inventories identify their own
original images and disassembly, with no global erasure or CT claim.
"""
import ast
import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import zipfile

sys.dont_write_bytecode = True

from confirm_m06_builds import comparison_bytes
from run_m08_fuzz import TARGETS as FUZZ_TARGETS, inventory, ordinary, original_campaign_root, owned, safe_name
from verify_m04_distribution import cargo_lock, compiled_inventory, license_inventory, deterministic_tar, native_dependencies
from review_m08_imports import check_consumer_command

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "KEM1536-DEV-Q7681-R1"
TARGETS = {"windows": "x86_64-pc-windows-gnu", "linux": "x86_64-unknown-linux-gnu"}
EXTRA_SOURCE = ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", "SECURITY.md",
                "docs/SPECIFICATION_DEV_Q7681_R1.md", "docs/MOTEUR_KEM_R1.md", "docs/M08_IMPORTS_ET_VALIDATION.md")
CONTROL_FILES = ("package_m08.py", "confirm_m06_builds.py", "verify_m04_distribution.py", "run_m08_fuzz.py")
HOST_VALIDATION_FILES = ("comparison.json", "native-dependencies.txt", "original-validation.json", "repeat-validation.json",
                         "metadata.json", "repeat-artifacts.jsonl", "repeat-build.log", "original-self-test.stdout",
                         "original-self-test.stderr", "repeat-self-test.stdout", "repeat-self-test.stderr")
RESEARCH_COMMANDS = (("dev-vectors", "1"), ("dev-rejection-vectors",), ("dev-hardening",),
                     ("dev-mutations",), ("dev-timing",))
SYSTEM_DLLS = {"kernel32.dll", "kernelbase.dll", "ntdll.dll", "msvcrt.dll", "ucrtbase.dll",
              "bcrypt.dll", "bcryptprimitives.dll", "advapi32.dll", "userenv.dll", "ws2_32.dll",
              "api-ms-win-core-synch-l1-2-0.dll", "crypt32.dll", "secur32.dll", "ole32.dll",
              "oleaut32.dll", "user32.dll", "shell32.dll", "gdi32.dll", "version.dll", "rpcrt4.dll"}
PROOF_SCOPE = {"import_review_scope": "four default-feature API consumer images, not the delivered CLI PKE",
               "CLI_inventory_scope": "identified research/delivered CLI images and full inventories, not a PKE erasure proof",
               "import_review_applies_to_shipped_CLI": False, "CLI_PKE_erasure_proved": False}


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def save(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def checked_collection(receipt, collection, schema, collection_schema):
    data = read(receipt)
    require(data.get("schema") == schema
            and type(data.get("files_sha256")) is dict, "invalid sealed binary review receipt")
    collection = receipt.parent / "collection.json" if collection is None else collection
    ordinary(collection)
    require(sha(collection) == data["files_sha256"].get("collection.json"), "review collection hash differs")
    value = read(collection)
    require(value.get("schema") == collection_schema and value.get("profile") == PROFILE, "wrong collection schema/profile")
    return value, collection


def checked_import_collection(receipt, manifest, memory_hash, collection=None):
    """Bind the separate import-consumer review, never reclassify it as CLI erasure."""
    value, collection = checked_collection(receipt, collection, "m08-import-review-receipt-v1",
                                           "m08-import-review-collection-v1")
    require(value["source_manifest_sha256"]["candidate"] == sha(manifest)
            and value["memory_acceptance_sha256"] == memory_hash,
            "import review source/acceptance binding differs")
    require(set(value["binaries"]) == {label + "-" + host for label in ("baseline", "candidate") for host in TARGETS},
            "four baseline/candidate consumer identities required")
    return value, collection


def checked_cli_collection(receipt, manifest, memory_hash, collection=None):
    value, collection = checked_collection(receipt, collection, "m08-cli-inventory-receipt-v1",
                                           "m08-cli-inventory-collection-v1")
    require(value["source_manifest_sha256"] == sha(manifest) and value["memory_acceptance_sha256"] == memory_hash,
            "CLI inventory source/acceptance binding differs")
    require(set(value["binaries"]) == {host + "-" + kind for host in TARGETS for kind in ("research", "delivered")}
            and set(value["build_receipt_sha256"]) == set(TARGETS), "four exact candidate CLI identities required")
    return value, collection


def check_original_receipt(host, receipt_path, manifest, delivery, imports, cli):
    receipt = read(receipt_path)
    require(receipt["profile"] == PROFILE and receipt["host"] == host
            and receipt["source_manifest_sha256"] == sha(manifest), "wrong original source/host profile")
    require(imports["build_receipt_sha256"]["candidate-" + host] == sha(receipt_path)
            and imports["binaries"]["candidate-" + host] == receipt["binaries"]["consumer"],
            "consumer import-review identity is not bound to original candidate build")
    check_consumer_command(receipt["binaries"]["consumer"], host)
    require(cli["build_receipt_sha256"][host] == sha(receipt_path), "CLI inventory original build hash differs")
    for kind in ("research", "delivered"):
        item = receipt["binaries"][kind]
        expected_name = f"candidate/{host}/bin/" + kind + (".exe" if host == "windows" else "")
        require(item["path"] == expected_name and item["emit_stack_metadata"] is False
                and cli["binaries"][host + "-" + kind] == item and "release: 1.91.1" in item["rustc"],
                "original CLI inventory/source/compiler identity differs")
    item = receipt["binaries"]["delivered"]
    command = item["command"]
    require("build" in command and command[command.index("build"):] ==
            ["build", "--release", "--locked", "--offline", "-p", "kem1536-cli", "--bin", "kem1536"],
            "original default CLI build selection differs")
    require(item["sha256"] == delivery["delivered_binary_sha256"][host], "accepted original CLI hash differs")
    return receipt


def bindings(measurements, review, cli_inventory, timing):
    measurements = owned(measurements, ROOT / "artifacts/generated")
    ordinary(measurements, directory=True)
    marker_paths = {"memory": measurements / "MEMORY_AND_LATENCY_ACCEPTED.json",
                    "delivery": measurements / "DELIVERY_ACCEPTED.json"}
    for name, path in marker_paths.items():
        require(path.is_file(), f"wait for {path.name} before repeat builds or packaging")
        ordinary(path)
    manifest_path = measurements / "candidate-source.json"
    ordinary(manifest_path)
    manifest = read(manifest_path)
    require(manifest["profile"] == PROFILE and len(manifest["source_sha256"]) == 46, "wrong candidate profile/46-input closure")
    for name in manifest["source_sha256"]:
        safe_name(name)
    require(inventory(measurements / "candidate-source") == manifest["source_sha256"], "candidate sources changed")
    markers = {name: read(path) for name, path in marker_paths.items()}
    for marker in markers.values():
        require(marker.get("profile") == PROFILE and marker.get("accepted") is True
                and marker.get("candidate_source_manifest_sha256") == sha(manifest_path), "unaccepted or differently bound candidate")
    review, cli_inventory, timing = (Path(os.path.abspath(path)) for path in (review, cli_inventory, timing))
    for path in (review, cli_inventory, timing):
        require(path.is_relative_to(ROOT / "artifacts/generated"), "local generated review/timing evidence required")
        current = ROOT
        for part in path.relative_to(ROOT).parts[:-1]:
            current /= part
            ordinary(current, directory=True)
        ordinary(path)
    delivery = markers["delivery"]
    require(sha(review) == delivery["import_review_receipt_sha256"]
            and sha(cli_inventory) == delivery["cli_inventory_receipt_sha256"]
            and sha(timing) == delivery["timing_capture_sha256"], "review or timing receipt differs")
    review_data, review_collection = checked_import_collection(review, manifest_path, sha(marker_paths["memory"]))
    cli_data, cli_collection = checked_cli_collection(cli_inventory, manifest_path, sha(marker_paths["memory"]))
    originals, receipts = {}, {}
    for host in TARGETS:
        receipt_path = measurements / "candidate" / host / "build.json"
        receipt = check_original_receipt(host, receipt_path, manifest_path, delivery, review_data, cli_data)
        item = receipt["binaries"]["delivered"]
        expected_name = f"candidate/{host}/bin/delivered" + (".exe" if host == "windows" else "")
        original = measurements / expected_name
        ordinary(original)
        require(sha(original) == item["sha256"], "inventoried original binary changed")
        originals[host], receipts[host] = original, receipt
    require(set(delivery["delivered_binary_sha256"]) == set(TARGETS), "two delivered hosts required")
    return {"measurements": measurements, "source": measurements / "candidate-source",
            "manifest": manifest_path, "manifest_data": manifest, "markers": marker_paths,
            "marker_hashes": {name: sha(path) for name, path in marker_paths.items()},
            "review": review, "review_collection": review_collection, "cli_inventory": cli_inventory,
            "cli_collection": cli_collection, "timing": timing, "originals": originals, "receipts": receipts}


def compare(raw_first, raw_repeat, host):
    first, first_meta = comparison_bytes(raw_first, host)
    second, second_meta = comparison_bytes(raw_repeat, host)
    require(first == second, f"repeat program differs outside allowed PE metadata: {host}")
    return {"raw_byte_identical": raw_first == raw_repeat,
            "comparison_sha256": hashlib.sha256(first).hexdigest(),
            "original_metadata": first_meta, "repeat_metadata": second_meta,
            "raw_binaries_modified": False,
            "scope": "Linux exact bytes; Windows only COFF timestamp/PE checksum masked in temporary copies"}


def check_windows_imports(text, raw=None):
    if raw is not None:
        comparison_bytes(raw, "windows")  # Validates the x86-64 PE32+ header.
        pe = struct.unpack_from("<I", raw, 60)[0]
        require(len(raw) >= pe + 136, "truncated PE data-directory header")
        count = struct.unpack_from("<I", raw, pe + 132)[0]
        if count > 13:
            require(len(raw) >= pe + 248, "truncated PE delay-import directory")
            require(struct.unpack_from("<II", raw, pe + 240) == (0, 0),
                    "unexpected PE delay imports require separate inspection before delivery")
    names = sorted(set(re.findall(r"(?m)^[ \t]*Name:[ \t]?([^\r\n]*)\r?$", text)), key=str.casefold)
    require(names, "PE imports are absent")
    unknown = [name for name in names if name.casefold() not in SYSTEM_DLLS]
    require(not unknown, "non-system Windows DLL is not supplied/licensed: " + ", ".join(unknown))
    return {"kind": "PE import table; delay-import directory must be absent", "libraries": names,
            "non_system_libraries": [], "system_libraries_bundled": False,
            "policy": "explicit reviewed system-DLL allowlist; unknown DLLs fail closed"}


def recipe(bound):
    path = bound["source"] / "research/run_m08.py"
    checksum = sha(path)
    require(all(row["controller_sha256"] == checksum for row in bound["receipts"].values()), "build recipe differs from captured run_m08")
    require(sha(ROOT / "research/run_m07.py") == bound["manifest_data"]["source_sha256"]["research/run_m07.py"],
            "shared build-environment helper differs from measured closure")
    spec = importlib.util.spec_from_file_location("m08_archived_delivery_recipe", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = ROOT  # Reuse the original existing tool/cache root, never a new source path.
    return module


def execute_binary(binary, host, arguments):
    command = [str(binary), *arguments] if host == "windows" else ["wsl", "-d", "Ubuntu-22.04", "--",
        "/mnt/" + binary.drive[0].lower() + str(binary)[2:].replace("\\", "/"), *arguments]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    return result, command


def validate_executable(binary, host, folder, label):
    before = sha(binary)
    process, command = execute_binary(binary, host, ["dev-self-test"])
    (folder / f"{label}-self-test.stdout").write_bytes(process.stdout)
    (folder / f"{label}-self-test.stderr").write_bytes(process.stderr)
    require(process.returncode == 0, "delivered self-test failed")
    data = json.loads(process.stdout)
    require((data.get("profile"), data.get("fresh_round_trips"), data.get("implicit_rejections_checked"), data.get("secrets_printed"))
            == (PROFILE, 16, 16, False), "delivered self-test scope differs")
    disabled = []
    for arguments in RESEARCH_COMMANDS:
        probe, invocation = execute_binary(binary, host, list(arguments))
        require(probe.returncode == 1 and probe.stdout == b"", "research-only command did not reject normally")
        disabled.append({"command": invocation, "exit_code": probe.returncode,
                         "stdout_sha256": hashlib.sha256(probe.stdout).hexdigest(),
                         "stderr_sha256": hashlib.sha256(probe.stderr).hexdigest()})
    require(sha(binary) == before, "executable changed during validation")
    receipt = {"binary_sha256": before, "self_test_command": command, "self_test_exit_code": process.returncode, "self_test": data,
               "research_commands_rejected": disabled}
    save(folder / f"{label}-validation.json", receipt)
    return receipt


def windows_path(path):
    if path.startswith("/mnt/") and len(path) > 7 and path[6] == "/":
        return Path(path[5].upper() + ":/" + path[7:])
    return Path(path)


def licenses(package, records, metadata, bound, host, rustc_version, sysroot):
    old_root = ROOT / "results/engine/m04-001/distribution"
    old_package = old_root / host / "package"
    old_manifest = read(old_root / "source-manifest.json")
    old = read(old_package / "dependencies.json")
    old_env = read(old_root / host / "environment.json")
    stripped = lambda rows: [{key: value for key, value in row.items() if key not in {"metadata_id", "license_files"}}
                             for row in rows]
    reusable = (sha(bound["source"] / "Cargo.lock") == old_manifest["files"]["Cargo.lock"]
                and rustc_version.splitlines() == old_env["rustc"].splitlines()
                and stripped(records) == stripped(old["packages"]))
    if reusable:
        expected = {name: checksum for name, checksum in read(old_package / "SHA256SUMS.json").items() if name.startswith("licenses/")}
        require({"licenses/" + name: checksum for name, checksum in inventory(old_package / "licenses").items()} == expected,
                "frozen M04 license hashes differ")
        shutil.copytree(old_package / "licenses", package / "licenses")
        by_key = {(row["name"], row["version"], row["source"]): row for row in old["packages"]}
        for row in records:
            row.pop("metadata_id")
            row["license_files"] = by_key[(row["name"], row["version"], row["source"])]["license_files"]
        return {"mode": "license texts reused from immutable M04 distribution, not its binaries",
                "old_dependencies_sha256": sha(old_package / "dependencies.json"),
                "old_environment_sha256": sha(old_root / host / "environment.json"),
                "same_Cargo_lock": True, "same_rustc": True, "same_compiled_packages_features": True}
    translated = json.loads(json.dumps(metadata))
    if host == "linux":
        for row in translated["packages"]:
            row["manifest_path"] = str(windows_path(row["manifest_path"]))
            if row.get("license_file") and row["license_file"].startswith("/mnt/"):
                row["license_file"] = str(windows_path(row["license_file"]))
    license_inventory(records, translated, package / "licenses/dependencies")
    notices = windows_path(sysroot) / "share/doc/rust"
    (package / "licenses/toolchain").mkdir(parents=True)
    for name in ("COPYRIGHT-library.html", "COPYRIGHT.html"):
        shutil.copyfile(notices / name, package / "licenses/toolchain" / name)
    shutil.copytree(notices / "licenses", package / "licenses/toolchain/texts")
    return {"mode": "license texts collected from resolved metadata and pinned toolchain cache",
            "same_Cargo_lock_as_M04": sha(bound["source"] / "Cargo.lock") == old_manifest["files"]["Cargo.lock"]}


def compact_source(out, bound):
    source = out / "source"
    shutil.copytree(bound["source"], source)
    additions = {}
    for name in EXTRA_SOURCE:
        ordinary(ROOT / name)
        destination = source / name
        if destination.exists():
            require(sha(destination) == sha(ROOT / name), "documentation collides with compiled source snapshot")
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        additions[name] = sha(destination)
    build = """# MAJAX R6 M08 compact source\n\nUse Rust 1.91.1 and an appropriate native C linker. From this root:\n\n```sh\ncargo +1.91.1 build --locked --release -p kem1536-cli --bin kem1536\n./target/release/kem1536 dev-self-test\n```\n\nOn Windows use kem1536.exe. Cargo.lock pins dependencies; they are not vendored.\nA new machine needs registry access or matching Cargo caches. The Windows GNU\ntarget uses the included .cargo/config.toml and Rust self-contained linking.\nThe source contains the measured compilation closure and selected API/specification\nguides, not all historical research archives or local tools. Research-only\ncommands are disabled in this default CLI. See the accompanying provenance\nfor the exact original delivered executable and same-host repeat build.\n"""
    (source / "BUILD_M08.md").write_text(build, encoding="utf-8")
    files = inventory(source)
    require(all(files[name] == checksum for name, checksum in bound["manifest_data"]["source_sha256"].items()), "compact source lost measured compilation inputs")
    save(out / "source-manifest.json", {"profile": PROFILE, "measured_manifest_sha256": sha(bound["manifest"]),
         "compiled_source_sha256": bound["manifest_data"]["source_sha256"], "added_documents_sha256": additions,
         "files": files, "scope": "compact compilable measured closure plus selected license/API/specification documents"})
    deterministic_tar(source, out / "source.tar.gz", 0)
    verify_archive(out / "source.tar.gz", files)


def verify_archive(path, expected):
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            require(archive.testzip() is None and len(archive.infolist()) == len(expected)
                    and set(archive.namelist()) == set(expected), "ZIP inventory differs")
            for name, checksum in expected.items():
                require(hashlib.sha256(archive.read(name)).hexdigest() == checksum, "ZIP member changed")
    else:
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            require(len(members) == len(expected) and {row.name for row in members} == set(expected)
                    and all(row.isfile() for row in members), "tar inventory differs")
            for row in members:
                digest = hashlib.sha256()
                with archive.extractfile(row) as stream:
                    while chunk := stream.read(1024 * 1024):
                        digest.update(chunk)
                require(digest.hexdigest() == expected[row.name], "tar member changed")


def zip_package(folder, output):
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in inventory(folder):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100755 if name.startswith("bin/") else 0o100644) << 16
            archive.writestr(info, (folder / name).read_bytes())


def check_comparison_binding(provenance, original, repeated, comparison):
    require(provenance["binary_sha256"] == original
            and provenance["repeat_binary_sha256"] == repeated
            and provenance["comparison"] == comparison, "packaged comparison provenance differs")


def check_proof_scope(provenance):
    require(all(key in provenance and provenance[key] == value and type(provenance[key]) is type(value)
                for key, value in PROOF_SCOPE.items()), "consumer import review may not become a CLI PKE erasure claim")


def check_validation_copies(out, host, package):
    expected = inventory(out / "validation")
    for name in HOST_VALIDATION_FILES:
        expected[name] = sha(out / host / name)
    require(inventory(package / "validation") == expected, "packaged validation copy differs")


def control_closure():
    todo, found = list(CONTROL_FILES), set()
    while todo:
        name = todo.pop()
        if name in found:
            continue
        found.add(name)
        for node in ast.walk(ast.parse((ROOT / "research" / name).read_text(encoding="utf-8-sig"))):
            modules = [node.module] if isinstance(node, ast.ImportFrom) else ([a.name for a in node.names] if isinstance(node, ast.Import) else [])
            todo.extend(module + ".py" for module in modules if module and (ROOT / "research" / (module + ".py")).is_file())
    return sorted(found)


def run(out, measurements, target, review, cli_inventory, timing):
    require(sys.platform == "win32", "use the Windows coordinator; Linux repeat build runs through WSL")
    out, target = owned(out, ROOT / "artifacts/generated"), owned(target, ROOT / "target")
    require(not out.exists() and not target.exists(), "new delivery and repeat target directories required")
    bound = bindings(measurements, review, cli_inventory, timing)  # No mutation/tool execution before both gates.
    controller = recipe(bound)
    out.mkdir()
    try:
        (out / "controls").mkdir()
        for name in control_closure():
            shutil.copyfile(ROOT / "research" / name, out / "controls" / name)
        control_hashes = inventory(out / "controls")
        (out / "validation").mkdir()
        for name, path in {"memory-accepted.json": bound["markers"]["memory"],
                           "delivery-accepted.json": bound["markers"]["delivery"],
                           "candidate-source.json": bound["manifest"], "import-review.json": bound["review"],
                           "import-review-collection.json": bound["review_collection"],
                           "cli-inventory.json": bound["cli_inventory"], "cli-inventory-collection.json": bound["cli_collection"],
                           "timing-capture.json": bound["timing"]}.items():
            shutil.copyfile(path, out / "validation" / name)
        for host in TARGETS:
            shutil.copyfile(bound["measurements"] / "candidate" / host / "build.json",
                            out / "validation" / (host + "-original-build.json"))
        require(all(sha(bound["markers"][name]) == checksum and
                    sha(out / "validation" / ("memory-accepted.json" if name == "memory" else "delivery-accepted.json")) == checksum
                    for name, checksum in bound["marker_hashes"].items()), "acceptance marker changed before build")
        require(sha(out / "validation/import-review.json") == read(out / "validation/delivery-accepted.json")["import_review_receipt_sha256"]
                and sha(out / "validation/cli-inventory.json") == read(out / "validation/delivery-accepted.json")["cli_inventory_receipt_sha256"]
                and sha(out / "validation/timing-capture.json") == read(out / "validation/delivery-accepted.json")["timing_capture_sha256"],
                "review/timing receipt changed before build")
        checked_import_collection(out / "validation/import-review.json", out / "validation/candidate-source.json",
                                  bound["marker_hashes"]["memory"], out / "validation/import-review-collection.json")
        checked_cli_collection(out / "validation/cli-inventory.json", out / "validation/candidate-source.json",
                               bound["marker_hashes"]["memory"], out / "validation/cli-inventory-collection.json")
        compact_source(out, bound)
        results = {}
        for host, triple in TARGETS.items():
            folder = out / host
            folder.mkdir()
            this_target = target / host / "delivered"
            args = ["build", "--release", "--locked", "--offline", "-p", "kem1536-cli", "--bin", "kem1536", "--message-format=json"]
            if host == "windows":
                env, cargo, rustc, llvm = controller.windows_environment(this_target, False)
                prefix, command = [], [cargo, *args]
                version = subprocess.check_output([rustc, "-Vv"], env=env, text=True)
                sysroot = subprocess.check_output([rustc, "--print", "sysroot"], env=env, text=True).strip()
                metadata_command = [cargo, "metadata", "--locked", "--offline", "--format-version", "1", "--filter-platform", triple]
            else:
                env, llvm = None, None
                prefix = controller.linux_prefix(this_target, False)
                cargo = controller.linux(ROOT / ".tools/linux-cargo/bin/cargo")
                rustc = controller.linux(ROOT / ".tools/linux-cargo/bin/rustc")
                command = [*prefix, cargo, *args]
                version = subprocess.check_output([*prefix, rustc, "-Vv"], text=True)
                sysroot = subprocess.check_output([*prefix, rustc, "--print", "sysroot"], text=True).strip()
                metadata_command = [*prefix, cargo, "metadata", "--locked", "--offline", "--format-version", "1", "--filter-platform", triple]
            require(version.splitlines() == bound["receipts"][host]["binaries"]["delivered"]["rustc"].splitlines(), "repeat compiler differs")
            with (folder / "repeat-artifacts.jsonl").open("xb") as stdout, (folder / "repeat-build.log").open("xb") as stderr:
                subprocess.run(command, cwd=bound["source"], env=env, stdout=stdout, stderr=stderr, check=True)
            metadata = json.loads(subprocess.check_output(metadata_command, cwd=bound["source"], env=env))
            save(folder / "metadata.json", metadata)
            suffix = ".exe" if host == "windows" else ""
            repeat = folder / ("repeat" + suffix)
            shutil.copyfile(this_target / "release" / ("kem1536" + suffix), repeat)
            original = bound["originals"][host]
            require(sha(original) == bound["receipts"][host]["binaries"]["delivered"]["sha256"], "original changed before packaging")
            comparison = compare(original.read_bytes(), repeat.read_bytes(), host)
            save(folder / "comparison.json", comparison)
            if host == "windows":
                native_command = [str(llvm / "llvm-readobj.exe"), "--coff-imports", str(original)]
            else:
                native_command = ["wsl", "-d", "Ubuntu-22.04", "--", "readelf", "-d", "--version-info", controller.linux(original)]
            raw = subprocess.check_output(native_command, env=env)
            (folder / "native-dependencies.txt").write_bytes(raw)
            native = check_windows_imports(raw.decode(), original.read_bytes()) if host == "windows" else native_dependencies(raw.decode(), host)
            package = folder / "package"
            (package / "bin").mkdir(parents=True)
            shipped = package / "bin" / ("kem1536" + suffix)
            shutil.copyfile(original, shipped)  # Ship the FIRST inventoried CLI, never the repeat.
            if host == "linux":
                # Windows chmod does not reliably set DrvFS Unix executable bits.
                subprocess.run(["wsl", "-d", "Ubuntu-22.04", "--", "chmod", "0755",
                                controller.linux(shipped), controller.linux(repeat)], check=True)
            require(sha(shipped) == sha(original), "package did not retain inventoried original bytes")
            original_validation = validate_executable(shipped, host, folder, "original")
            repeat_validation = validate_executable(repeat, host, folder, "repeat")
            records = compiled_inventory(metadata, (folder / "repeat-artifacts.jsonl").read_text(encoding="utf-8-sig"), cargo_lock(bound["source"] / "Cargo.lock"))
            licensing = licenses(package, records, metadata, bound, host, version, sysroot)
            for name in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", "SECURITY.md"):
                shutil.copyfile(out / "source" / name, package / name)
            for name in ("source.tar.gz", "source-manifest.json"):
                shutil.copyfile(out / name, package / name)
            (package / "validation").mkdir()
            for path in (out / "validation").iterdir():
                shutil.copyfile(path, package / "validation" / path.name)
            for name in HOST_VALIDATION_FILES:
                shutil.copyfile(folder / name, package / "validation" / name)
            save(package / "dependencies.json", {"packages": records, "native": native,
                 "native_inspection_command": native_command,
                 "native_report_sha256": sha(folder / "native-dependencies.txt"),
                 "normal_dependency_graph_is_not_linker_symbol_attribution": True, "license_collection": licensing})
            provenance = {"profile": PROFILE, "milestone": "M08", "host": host, "target": triple,
                "source_manifest_sha256": sha(bound["manifest"]), "original_build_receipt_sha256": sha(bound["measurements"] / "candidate" / host / "build.json"),
                "binary_sha256": sha(shipped), "repeat_binary_sha256": sha(repeat), "comparison": comparison,
                "original_self_test": original_validation, "repeat_self_test": repeat_validation,
                "memory_acceptance_sha256": bound["marker_hashes"]["memory"], "delivery_acceptance_sha256": bound["marker_hashes"]["delivery"],
                "import_review_receipt_sha256": sha(bound["review"]), "timing_capture_sha256": sha(bound["timing"]),
                "import_review_collection_sha256": sha(bound["review_collection"]),
                "cli_inventory_receipt_sha256": sha(bound["cli_inventory"]),
                "cli_inventory_collection_sha256": sha(bound["cli_collection"]),
                **PROOF_SCOPE,
                "new_cli_builds_this_run": 1, "research_vectors_enabled": False,
                "repeat_command": command, "metadata_only_extra_option": "--message-format=json",
                "rustc": version, "shared_dependency_and_toolchain_caches": True,
                "cargo_metadata_sha256": sha(folder / "metadata.json"),
                "cargo_build_messages_sha256": sha(folder / "repeat-artifacts.jsonl"),
                "repeat_build_log_sha256": sha(folder / "repeat-build.log"),
                "packaging_controls_sha256": control_hashes,
                "repeat_source_path": str(bound["source"]), "separate_repeat_target": str(this_target),
                "third_party_reproduction_claimed": False, "certification": False}
            save(package / "provenance.json", provenance)
            usage = "# MAJAX R6 M08\n\nRun bin/kem1536 dev-profile and bin/kem1536 dev-self-test (add .exe on Windows).\nThe self-test makes 16 fresh exchanges and checks 16 rejections without printing keys.\nResearch-only commands are disabled. This package contains the original inventoried delivered CLI;\nthe repeat is comparison evidence only. Memory, latency and timing diagnostics use their own\nidentified executables from the same candidate sources. The import review concerns separate\ndefault-feature API consumer images. It does not establish erasure of the delivered CLI PKE;\nthe separate CLI inventories identify their images and disassembly, without a global CT/erasure proof.\nSee provenance.json and dependencies.json for hashes, OS prerequisites, shared-cache repeat-build\nscope and Windows PE metadata limits. Extract source.tar.gz and follow BUILD_M08.md for the Rust\nAPI/CLI sources. Dependencies are not vendored; system libraries are prerequisites, not bundled components.\n"
            (package / "USAGE.md").write_text(usage, encoding="utf-8")
            members = inventory(package)
            save(package / "SHA256SUMS.json", members)
            members = inventory(package)
            archive = out / ("majax-r6-m08-" + triple + (".zip" if host == "windows" else ".tar.gz"))
            zip_package(package, archive) if host == "windows" else deterministic_tar(package, archive, 0)
            verify_archive(archive, members)
            results[host] = {"archive": archive.name, "archive_sha256": sha(archive), "package_sha256": members,
                             "original_binary_sha256": sha(original), "repeat_binary_sha256": sha(repeat), "comparison": comparison}
        require(inventory(bound["source"]) == bound["manifest_data"]["source_sha256"], "repeat build changed measured source")
        save(out / "result.json", {"created_utc": datetime.now(timezone.utc).isoformat(), "profile": PROFILE,
            "platforms": results, "source_archive_sha256": sha(out / "source.tar.gz"),
            "packaging_controls_sha256": control_hashes,
            "new_cli_builds_total": 2, "third_party_reproduction_claimed": False})
        return verify(out)
    except BaseException as error:
        save(out / "failure.json", {"error_type": type(error).__name__, "error": str(error), "evidence_preserved": True})
        raise


def verify(out):
    result = read(out / "result.json")
    source = read(out / "source-manifest.json")
    require(result["profile"] == source["profile"] == PROFILE and result["new_cli_builds_total"] == 2
            and result["third_party_reproduction_claimed"] is False, "delivery scope differs")
    require(inventory(out / "controls") == result["packaging_controls_sha256"], "packaging control changed")
    validation = out / "validation"
    manifest = read(validation / "candidate-source.json")
    memory, delivery = read(validation / "memory-accepted.json"), read(validation / "delivery-accepted.json")
    manifest_hash = sha(validation / "candidate-source.json")
    require(source["measured_manifest_sha256"] == manifest_hash and source["compiled_source_sha256"] == manifest["source_sha256"]
            and len(manifest["source_sha256"]) == 46,
            "compact source manifest is not the accepted compiled closure")
    require(all(source["files"][name] == checksum for name, checksum in manifest["source_sha256"].items()), "measured compilation member changed")
    for marker in (memory, delivery):
        require(marker["profile"] == PROFILE and marker["accepted"] is True
                and marker["candidate_source_manifest_sha256"] == manifest_hash, "acceptance marker changed")
    require(sha(validation / "import-review.json") == delivery["import_review_receipt_sha256"]
            and sha(validation / "cli-inventory.json") == delivery["cli_inventory_receipt_sha256"]
            and sha(validation / "timing-capture.json") == delivery["timing_capture_sha256"], "accepted review/timing receipt changed")
    collection, _ = checked_import_collection(validation / "import-review.json", validation / "candidate-source.json",
        sha(validation / "memory-accepted.json"), validation / "import-review-collection.json")
    cli, _ = checked_cli_collection(validation / "cli-inventory.json", validation / "candidate-source.json",
        sha(validation / "memory-accepted.json"), validation / "cli-inventory-collection.json")
    require(inventory(out / "source") == source["files"], "compact source changed")
    require(sha(out / "source.tar.gz") == result["source_archive_sha256"], "compact source archive changed")
    verify_archive(out / "source.tar.gz", source["files"])
    for host, row in result["platforms"].items():
        require(host in TARGETS and inventory(out / host / "package") == row["package_sha256"], "package member changed")
        archive = out / row["archive"]
        require(sha(archive) == row["archive_sha256"], "delivery archive changed")
        verify_archive(archive, row["package_sha256"])
        package = out / host / "package"
        suffix = ".exe" if host == "windows" else ""
        shipped, repeat = package / "bin" / ("kem1536" + suffix), out / host / ("repeat" + suffix)
        require(sha(shipped) == row["original_binary_sha256"] and sha(repeat) == row["repeat_binary_sha256"], "original/repeat binary changed")
        require(compare(shipped.read_bytes(), repeat.read_bytes(), host) == row["comparison"], "repeat comparison differs")
        provenance = read(package / "provenance.json")
        check_comparison_binding(provenance, sha(shipped), sha(repeat), row["comparison"])
        check_validation_copies(out, host, package)
        checksums = inventory(package)
        checksums.pop("SHA256SUMS.json")
        require(read(package / "SHA256SUMS.json") == checksums, "package checksum manifest differs")
        require(sha(package / "source.tar.gz") == result["source_archive_sha256"]
                and sha(package / "source-manifest.json") == sha(out / "source-manifest.json"), "packaged source differs")
        require(provenance["binary_sha256"] == sha(shipped) and provenance["new_cli_builds_this_run"] == 1
                and provenance["research_vectors_enabled"] is False and provenance["third_party_reproduction_claimed"] is False,
                "package provenance scope differs")
        original = check_original_receipt(host, validation / (host + "-original-build.json"),
            validation / "candidate-source.json", delivery, collection, cli)
        require(original["source_manifest_sha256"] == manifest_hash
                and original["binaries"]["delivered"]["sha256"] == sha(shipped) == delivery["delivered_binary_sha256"][host]
                and sha(validation / (host + "-original-build.json")) == provenance["original_build_receipt_sha256"]
                and provenance["import_review_collection_sha256"] == sha(validation / "import-review-collection.json")
                and provenance["cli_inventory_collection_sha256"] == sha(validation / "cli-inventory-collection.json"),
                "shipped binary is not the inventoried original")
        require(provenance["packaging_controls_sha256"] == result["packaging_controls_sha256"]
                and provenance["source_manifest_sha256"] == manifest_hash
                and provenance["memory_acceptance_sha256"] == sha(validation / "memory-accepted.json")
                and provenance["delivery_acceptance_sha256"] == sha(validation / "delivery-accepted.json")
                and provenance["import_review_receipt_sha256"] == sha(validation / "import-review.json")
                and provenance["cli_inventory_receipt_sha256"] == sha(validation / "cli-inventory.json")
                and provenance["timing_capture_sha256"] == sha(validation / "timing-capture.json"), "provenance binding differs")
        check_proof_scope(provenance)
        for label, expected_binary in (("original", sha(shipped)), ("repeat", sha(repeat))):
            receipt = read(out / host / (label + "-validation.json"))
            test = json.loads((out / host / (label + "-self-test.stdout")).read_bytes())
            require(receipt["binary_sha256"] == expected_binary and receipt["self_test_exit_code"] == 0 and receipt["self_test"] == test
                    and provenance[label + "_self_test"] == receipt
                    and (test.get("profile"), test.get("fresh_round_trips"), test.get("implicit_rejections_checked"), test.get("secrets_printed"))
                    == (PROFILE, 16, 16, False), "self-test receipt differs")
            require(len(receipt["research_commands_rejected"]) == len(RESEARCH_COMMANDS)
                    and all(record["exit_code"] == 1 and record["stdout_sha256"] == hashlib.sha256(b"").hexdigest()
                            and record["command"][-len(arguments):] == list(arguments)
                            for record, arguments in zip(receipt["research_commands_rejected"], RESEARCH_COMMANDS)),
                    "research command rejection differs")
        native_text = (out / host / "native-dependencies.txt").read_text(encoding="utf-8-sig")
        native = check_windows_imports(native_text, shipped.read_bytes()) if host == "windows" else native_dependencies(native_text, host)
        dependencies = read(package / "dependencies.json")
        require(dependencies["native"] == native and dependencies["native_report_sha256"] == sha(out / host / "native-dependencies.txt")
                and sha(package / "validation/native-dependencies.txt") == dependencies["native_report_sha256"], "native import inventory differs")
        require(sha(out / host / "metadata.json") == provenance["cargo_metadata_sha256"]
                and sha(out / host / "repeat-artifacts.jsonl") == provenance["cargo_build_messages_sha256"]
                and sha(out / host / "repeat-build.log") == provenance["repeat_build_log_sha256"], "compiler metadata or messages changed")
        actual_packages = compiled_inventory(read(out / host / "metadata.json"),
            (out / host / "repeat-artifacts.jsonl").read_text(encoding="utf-8-sig"), cargo_lock(out / "source/Cargo.lock"))
        stripped = lambda rows: [{key: value for key, value in record.items() if key not in {"metadata_id", "license_files"}} for record in rows]
        require(stripped(actual_packages) == stripped(dependencies["packages"]), "compiled dependency/features inventory differs")
        for record in dependencies["packages"]:
            for license_file in record["license_files"]:
                safe_name(license_file["path"])
                require(sha(package / license_file["path"]) == license_file["sha256"], "dependency license text differs")
    require(set(result["platforms"]) == set(TARGETS), "two delivery platforms required")
    return {"profile": PROFILE, "packages_verified": 2, "new_cli_builds_total": 2,
            "shipped_binaries_are_inventoried_originals": True, "third_party_reproduction_claimed": False,
            "consumer_import_review_is_not_CLI_PKE_erasure_proof": True}


def diagnostic_records(metadata, lock, root_package="kem1536-fuzz"):
    """Resolved diagnostic graph for notices; no linker-symbol claim is made."""
    packages = {row["id"]: row for row in metadata["packages"]}
    nodes = {row["id"]: row for row in metadata["resolve"]["nodes"]}
    roots = [identity for identity, row in packages.items() if row["name"] == root_package]
    require(len(roots) == 1, "one diagnostic package root required: " + root_package)
    pending, selected = roots[:], set()
    while pending:
        identity = pending.pop()
        if identity in selected:
            continue
        require(identity in nodes and identity in packages, "resolved diagnostic graph is incomplete")
        selected.add(identity)
        pending.extend(dep["pkg"] for dep in nodes[identity]["deps"])
    locked = {(row["name"], row["version"], row.get("source")): row for row in lock["package"]}
    records = []
    for identity in sorted(selected, key=lambda value: (packages[value]["name"], packages[value]["version"])):
        package = packages[identity]
        key = package["name"], package["version"], package.get("source")
        require(key in locked, "diagnostic metadata package differs from frozen Cargo.lock")
        features = sorted(nodes[identity]["features"])
        require(package["name"] != "kem1536" or "research-vectors" not in features,
                "diagnostic graph unexpectedly enables research-vectors")
        records.append({"name": package["name"], "version": package["version"],
            "source": package.get("source") or "project source snapshot", "lock_checksum": locked[key].get("checksum"),
            "license": package.get("license"), "features": features, "metadata_id": identity,
            "category": "resolved_target_diagnostic_graph_not_linker_attribution"})
    return records


DIAGNOSTIC_GROUPS = {"fuzz": {"root_package": "kem1536-fuzz", "manifest": "fuzz/Cargo.toml", "lock": "fuzz/Cargo.lock"},
                     "replay": {"root_package": "kem1536-bench", "manifest": "Cargo.toml", "lock": "Cargo.lock"}}


def diagnostic_union(graphs, metadatas):
    """One notice folder per exact package, preserving each resolved feature graph."""
    require(set(graphs) == set(metadatas) == set(DIAGNOSTIC_GROUPS), "fuzz and replay graphs required")
    union, packages = {}, {}
    for group in sorted(graphs):
        by_id = {row["id"]: row for row in metadatas[group]["packages"]}
        for record in graphs[group]:
            identity = record["metadata_id"]
            require(identity in by_id, "diagnostic metadata identity missing")
            if identity in packages:
                require(all(packages[identity].get(key) == by_id[identity].get(key)
                            for key in ("manifest_path", "license_file", "license", "source", "name", "version")),
                        "same diagnostic metadata identity has different source/license")
            packages[identity] = by_id[identity]
            key = record["name"], record["version"], record["source"]
            if key in union:
                current = union[key]
                require(current["lock_checksum"] == record["lock_checksum"] and current["license"] == record["license"],
                        "same diagnostic package/version has different checksum/license")
                current["features"] = sorted(set(current["features"]) | set(record["features"]))
                current["binary_groups"].append(group)
            else:
                union[key] = {**record, "features": list(record["features"]), "binary_groups": [group]}
    return [union[key] for key in sorted(union)], {"packages": [packages[key] for key in sorted(packages)]}


def check_diagnostic_metadata_command(command, config, manifest):
    origin = original_campaign_root(config)
    expected_manifest = str(origin / "source" / manifest)
    require(command[:6] == ["wsl", "-d", "Ubuntu-22.04", "--", "env", "-i"]
            and command.count("metadata") == 1, "diagnostic metadata coordinator/argv differs")
    index = command.index("metadata")
    require(index > 0 and command[index - 1] == config["build_command"][3]
            and command[index:] == ["metadata", "--locked", "--offline", "--format-version", "1",
                                   "--filter-platform", "x86_64-unknown-linux-gnu", "--manifest-path", expected_manifest],
            "diagnostic metadata must bind the exact frozen group manifest and locked target")


def check_diagnostic_group(out, group, recorded, config):
    spec = DIAGNOSTIC_GROUPS[group]
    require(all(recorded[key] == value for key, value in spec.items())
            and sha(out / ("metadata-" + group + ".json")) == recorded["metadata_sha256"]
            and sha(out / "inputs" / (group + "-Cargo.toml")) == recorded["manifest_sha256"] == config["source_sha256"][spec["manifest"]]
            and sha(out / "inputs" / (group + "-Cargo.lock")) == recorded["lock_sha256"] == config["source_sha256"][spec["lock"]],
            "diagnostic group manifest/lock/metadata differs")
    check_diagnostic_metadata_command(recorded["metadata_command"], config, spec["manifest"])
    metadata = read(out / ("metadata-" + group + ".json"))
    graph = diagnostic_records(metadata, cargo_lock(out / "inputs" / (group + "-Cargo.lock")), spec["root_package"])
    require(graph == recorded["resolved_packages"], "per-group diagnostic dependency/features differ")
    return graph, metadata


def diagnostic_notices(campaign, out):
    """Collect fresh texts from exact locked metadata/cache, never old binaries."""
    require(sys.platform == "win32", "use Windows metadata/cache coordinator")
    from postprocess_m08_fuzz import verify as verify_diagnostic_campaign
    verify_diagnostic_campaign(campaign)
    out = owned(out, ROOT / "artifacts/generated")
    require(not out.exists(), "new diagnostic-notice output required")
    config = read(campaign / "config.json")
    source = campaign / "source"
    to_linux = lambda path: "/mnt/" + path.drive[0].lower() + str(path)[2:].replace("\\", "/")
    prefix = ["wsl", "-d", "Ubuntu-22.04", "--", "env", "-i",
              "CARGO_HOME=" + to_linux(ROOT / ".tools/linux-cargo"),
              "RUSTUP_HOME=" + to_linux(ROOT / ".tools/linux-rustup"),
              "RUSTUP_TOOLCHAIN=1.91.1-x86_64-unknown-linux-gnu", "RUSTUP_AUTO_INSTALL=0", "CARGO_NET_OFFLINE=true",
              "PATH=" + to_linux(ROOT / ".tools/linux-cargo/bin") + ":/usr/bin:/bin"]
    cargo, rustc = (to_linux(ROOT / ".tools/linux-cargo/bin" / name) for name in ("cargo", "rustc"))
    version = subprocess.check_output([*prefix, rustc, "-Vv"], text=True)
    require(version.splitlines() == config["versions"]["rustc"].splitlines(), "diagnostic notice toolchain differs")
    sysroot = subprocess.check_output([*prefix, rustc, "--print", "sysroot"], text=True).strip()
    require(sha(windows_path(sysroot) / "bin/rustc") == config["versions"]["compiler_binary_sha256"],
            "diagnostic compiler binary differs")
    metadatas, graphs, commands = {}, {}, {}
    for group, spec in DIAGNOSTIC_GROUPS.items():
        commands[group] = [*prefix, cargo, "metadata", "--locked", "--offline", "--format-version", "1",
                           "--filter-platform", "x86_64-unknown-linux-gnu", "--manifest-path", to_linux(source / spec["manifest"])]
        check_diagnostic_metadata_command(commands[group], config, spec["manifest"])
        metadatas[group] = json.loads(subprocess.check_output(commands[group]))
        graphs[group] = diagnostic_records(metadatas[group], cargo_lock(source / spec["lock"]), spec["root_package"])
    records, combined = diagnostic_union(graphs, metadatas)
    out.mkdir()
    try:
        (out / "inputs").mkdir()
        shutil.copyfile(campaign / "config.json", out / "inputs/campaign-config.json")
        group_receipts = {}
        for group, spec in DIAGNOSTIC_GROUPS.items():
            save(out / ("metadata-" + group + ".json"), metadatas[group])
            shutil.copyfile(source / spec["manifest"], out / "inputs" / (group + "-Cargo.toml"))
            shutil.copyfile(source / spec["lock"], out / "inputs" / (group + "-Cargo.lock"))
            group_receipts[group] = {**spec, "metadata_command": commands[group],
                "metadata_sha256": sha(out / ("metadata-" + group + ".json")),
                "manifest_sha256": sha(out / "inputs" / (group + "-Cargo.toml")),
                "lock_sha256": sha(out / "inputs" / (group + "-Cargo.lock")), "resolved_packages": graphs[group]}
        translated = json.loads(json.dumps(combined))
        for row in translated["packages"]:
            row["manifest_path"] = str(windows_path(row["manifest_path"]))
            if row.get("license_file") and row["license_file"].startswith("/mnt/"):
                row["license_file"] = str(windows_path(row["license_file"]))
        license_inventory(records, translated, out / "licenses/dependencies")
        notices = windows_path(sysroot) / "share/doc/rust"
        (out / "licenses/toolchain").mkdir(parents=True)
        for name in ("COPYRIGHT-library.html", "COPYRIGHT.html"):
            shutil.copyfile(notices / name, out / "licenses/toolchain" / name)
        shutil.copytree(notices / "licenses", out / "licenses/toolchain/texts")
        (out / "licenses/project").mkdir()
        for name in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md"):
            shutil.copyfile(ROOT / name, out / "licenses/project" / name)
        binaries = {"fuzz/" + name: sha(campaign / "bin" / name) for name in read(campaign / "built.json")["binary_sha256"]}
        binaries.update({"coverage/" + name: sha(campaign / "postprocessing/bin" / name)
                         for name in read(campaign / "built.json")["binary_sha256"]})
        binaries["deterministic-replay"] = sha(campaign / "bin/m08-replay")
        save(out / "notices.json", {"schema": "m08-diagnostic-notices-v1", "profile": PROFILE,
            "mode": "fresh locked metadata/cache/toolchain text collection",
            "reused_M06_bundle": False, "new_compilation_performed": False,
            "rustc": version, "groups": group_receipts,
            "compiler_binary_sha256": config["versions"]["compiler_binary_sha256"],
            "source_sha256": config["source_sha256"], "diagnostic_binary_sha256": binaries,
            "binary_to_dependency_group": {name: "replay" if name == "deterministic-replay" else "fuzz" for name in binaries},
            "packages": records,
            "license_sha256": inventory(out / "licenses"),
            "feature_scope": "separate resolved target fuzz/replay graphs, with per-group features; union is not linker-symbol attribution",
            "libFuzzer_vendor_SPDX": "Apache-2.0 WITH LLVM-exception; corresponding toolchain texts retained"})
        save(out / "provenance.json", {"files_sha256": inventory(out), "copied_old_binaries": False})
        return verify_diagnostic_notices(out)
    except BaseException as error:
        save(out / "failure.json", {"type": type(error).__name__, "error": str(error), "evidence_preserved": True})
        raise


def verify_diagnostic_notices(out):
    provenance = read(out / "provenance.json")
    files = inventory(out)
    files.pop("provenance.json")
    require(files == provenance["files_sha256"] and provenance["copied_old_binaries"] is False,
            "diagnostic notices member inventory differs")
    receipt, config = read(out / "notices.json"), read(out / "inputs/campaign-config.json")
    require(receipt["schema"] == "m08-diagnostic-notices-v1" and receipt["profile"] == PROFILE
            and receipt["reused_M06_bundle"] is False
            and receipt["new_compilation_performed"] is False
            and receipt["source_sha256"] == config["source_sha256"]
            and receipt["rustc"].splitlines() == config["versions"]["rustc"].splitlines()
            and receipt["compiler_binary_sha256"] == config["versions"]["compiler_binary_sha256"]
            and inventory(out / "licenses") == receipt["license_sha256"], "diagnostic source/license scope differs")
    require(set(receipt["diagnostic_binary_sha256"]) == {"deterministic-replay"}
            | {kind + "/" + name for kind in ("fuzz", "coverage") for name in FUZZ_TARGETS},
            "four fuzz, four coverage and one replay diagnostic identity required")
    require(receipt["binary_to_dependency_group"] == {name: "replay" if name == "deterministic-replay" else "fuzz"
                                                     for name in receipt["diagnostic_binary_sha256"]},
            "diagnostic images are not bound to their dependency groups")
    require(set(receipt["groups"]) == set(DIAGNOSTIC_GROUPS), "separate fuzz and replay notice groups required")
    graphs, metadatas = {}, {}
    for group, spec in DIAGNOSTIC_GROUPS.items():
        graphs[group], metadatas[group] = check_diagnostic_group(out, group, receipt["groups"][group], config)
    expected, _ = diagnostic_union(graphs, metadatas)
    stripped = lambda rows: [{key: value for key, value in row.items() if key not in {"metadata_id", "license_files"}}
                             for row in rows]
    require(stripped(expected) == stripped(receipt["packages"]), "diagnostic resolved dependency/features differ")
    for row in receipt["packages"]:
        for license_file in row["license_files"]:
            safe_name(license_file["path"])
            require(sha(out / license_file["path"]) == license_file["sha256"], "diagnostic dependency notice changed")
    return {"diagnostic_notice_files": len(inventory(out / "licenses")),
            "diagnostic_binaries_identified": len(receipt["diagnostic_binary_sha256"]),
            "new_compilation_performed": False, "reused_M06_bundle": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "verify", "diagnostic-notices", "verify-notices"))
    parser.add_argument("--measurements", type=Path, default=ROOT / "artifacts/generated/m08-001")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/generated/m08-delivery-001")
    parser.add_argument("--target-dir", type=Path, default=ROOT / "target/m08-repeat-001")
    parser.add_argument("--import-review-receipt", type=Path)
    parser.add_argument("--cli-inventory-receipt", type=Path)
    parser.add_argument("--timing-capture", type=Path)
    parser.add_argument("--campaign", type=Path, default=ROOT / "artifacts/generated/m08-fuzz-001")
    parser.add_argument("--notices-output", type=Path, default=ROOT / "artifacts/generated/m08-diagnostic-notices-001")
    args = parser.parse_args()
    if args.action == "run":
        out = owned(args.output, ROOT / "artifacts/generated")
        require(args.import_review_receipt is not None and args.cli_inventory_receipt is not None
                and args.timing_capture is not None, "import-review/CLI-inventory/timing receipt paths required")
        result = run(out, args.measurements, args.target_dir, args.import_review_receipt,
                     args.cli_inventory_receipt, args.timing_capture)
    elif args.action == "verify":
        result = verify(args.output.resolve())
    elif args.action == "diagnostic-notices":
        result = diagnostic_notices(args.campaign.resolve(), args.notices_output)
    else:
        result = verify_diagnostic_notices(args.notices_output.resolve())
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
