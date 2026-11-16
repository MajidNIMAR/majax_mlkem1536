"""Freeze/replay M07 evidence in compact, byte-preserving stage archives.

Verification only unpacks data into a temporary directory and recomputes
receipts. It never runs compilers, delivered binaries, objdump or campaigns.
"""
import argparse
import ast
from contextlib import contextmanager
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import tempfile

from analyze_delivery_timing import analyze as analyze_timing
from package_m07 import verify as verify_delivery
from review_m07_binary import verify as verify_binary
from run_m07_fuzz import verify as verify_fuzz
from verify_m07 import analyze as analyze_measurements

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "KEM1536-DEV-Q7681-R1"
STAGES = {"measurements": "m07-001", "binary": "m07-binary-001",
          "fuzz": "m07-fuzz-001", "delivery": "m07-delivery-001"}
MAX_BYTES = 1024 * 1024 * 1024
METADATA_BYTES = 16 * 1024 * 1024
MAX_MEMBERS = 25000


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
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def safe_name(name):
    parts = name.split("/")
    require(name and not PurePosixPath(name).is_absolute() and "\\" not in name,
            "absolute or platform-specific archive name")
    for part in parts:
        stem = part.split(".", 1)[0].casefold()
        require(part not in ("", ".", "..") and part.rstrip(" .") == part
                and not any(ord(c) < 32 or c in ':<>"|?*' for c in part)
                and stem not in {"con", "prn", "aux", "nul"}
                and not (len(stem) == 4 and stem[:3] in {"com", "lpt"} and stem[3] in "123456789\u00b9\u00b2\u00b3"),
                "unsafe archive member name")
    return parts


def inventory(folder):
    files, directories, spellings = {}, [], set()
    for path in sorted(folder.rglob("*"), key=lambda item: item.relative_to(folder).as_posix()):
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
                "archive input contains a link")
        name = path.relative_to(folder).as_posix()
        safe_name(name)
        require(name.casefold() not in spellings, "case-aliasing archive input")
        spellings.add(name.casefold())
        if path.is_dir():
            directories.append(name)
        else:
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "archive input is not an ordinary file")
            files[name] = {"sha256": sha(path), "bytes": info.st_size}
    require(len(files) + len(directories) <= MAX_MEMBERS, "archive member count exceeds budget")
    require(sum(row["bytes"] for row in files.values()) <= MAX_BYTES, "archive stage exceeds byte budget")
    return {"files": files, "directories": directories}


def pack(folder, archive):
    before = inventory(folder)
    with archive.open("xb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for name in sorted([*before["directories"], *before["files"]]):
                info = tarfile.TarInfo(name)
                info.uid = info.gid = info.mtime = 0
                info.uname = info.gname = ""
                info.mode = 0o755 if name in before["directories"] else 0o644
                if name in before["directories"]:
                    info.type = tarfile.DIRTYPE
                    tar.addfile(info)
                else:
                    info.size = before["files"][name]["bytes"]
                    with (folder / name).open("rb") as stream:
                        tar.addfile(info, stream)
    require(inventory(folder) == before, "archive source changed while packing")
    return {"archive": archive.name, "archive_sha256": sha(archive), **before}


class BoundedReader:
    """Bound bytes consumed, including PAX/longname data parsed by tarfile."""
    def __init__(self, stream, limit):
        self.stream, self.remaining = stream, limit

    def read(self, size):
        require(type(size) is int and size >= 0, "bounded reads must have a size")
        data = self.stream.read(min(size, self.remaining + 1))
        self.remaining -= len(data)
        require(self.remaining >= 0, "decompressed tar stream exceeds budget")
        return data


def unpack(archive, record, destination):
    require(sha(archive) == record["archive_sha256"], "archive checksum differs")
    files, directories = record["files"], record["directories"]
    require(isinstance(files, dict) and isinstance(directories, list)
            and len(directories) == len(set(directories)), "invalid stage inventory")
    expected = set(files) | set(directories)
    require(len(expected) == len(files) + len(directories), "file/directory collision")
    require(len(expected) <= MAX_MEMBERS, "archive member count exceeds budget")
    spellings = set()
    for name in expected:
        safe_name(name)
        require(name.casefold() not in spellings, "case-aliasing archive member")
        spellings.add(name.casefold())
        require(all(parent.as_posix() in directories for parent in PurePosixPath(name).parents
                    if parent.as_posix() != "."), "missing parent directory in stage inventory")
    require(all(type(row["bytes"]) is int and row["bytes"] >= 0 for row in files.values())
            and sum(row["bytes"] for row in files.values()) <= MAX_BYTES, "invalid archive byte budget")
    destination.mkdir()
    seen = set()
    with gzip.open(archive, "rb") as compressed:
        reader = BoundedReader(compressed, sum(row["bytes"] for row in files.values()) + METADATA_BYTES)
        with tarfile.open(fileobj=reader, mode="r|") as tar:
            for info in tar:
                name = info.name
                safe_name(name)
                require(name in expected and name not in seen, "unlisted or duplicate tar member")
                seen.add(name)
                target = destination.joinpath(*safe_name(name))
                require(target.resolve().is_relative_to(destination.resolve()), "member escaped extraction directory")
                if name in directories:
                    require(info.isdir() and info.size == 0, "invalid directory tar member")
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    require(info.isfile() and info.size == files[name]["bytes"], "invalid regular tar member")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(info) as source, target.open("xb") as sink:
                        shutil.copyfileobj(source, sink, length=1024 * 1024)
                    require(sha(target) == files[name]["sha256"], "unpacked member checksum differs")
    require(seen == expected and inventory(destination) == {"files": files, "directories": sorted(directories)},
            "incomplete or changed extracted inventory")


def check_timing(measurements):
    folder = measurements / "timing"
    capture = read(folder / "capture.json")
    require(capture["source_manifest_sha256"] == sha(measurements / "candidate-source.json")
            and capture["controller_sha256"] == sha(folder / "controller.py")
            and capture["observations"] == 32000 and capture["constant_time_proved"] is False
            and set(capture["hosts"]) == {"windows", "linux"}, "timing scope/binding differs")
    results = {}
    for host, row in capture["hosts"].items():
        path = measurements.joinpath(*safe_name(row["binary"]))
        require(sha(path) == row["binary_sha256"] and sha(folder / host / "build.log") == row["build_log_sha256"]
                and sha(folder / host / "observations.jsonl") == row["raw_sha256"]
                and sha(folder / host / "analysis.json") == row["analysis_sha256"], "timing data changed")
        with (folder / host / "observations.jsonl").open(encoding="utf-8") as stream:
            computed = analyze_timing(json.loads(line) for line in stream)
        require(computed == read(folder / host / "analysis.json"), "timing statistics do not replay")
        require(computed["maximum_absolute_t"] == row["maximum_absolute_t"]
                and computed["threshold_crossings"] == row["threshold_crossings"], "timing capture summary differs")
        results[host] = {"observations": computed["observations"], "maximum_absolute_t": computed["maximum_absolute_t"],
                         "threshold_crossings": computed["threshold_crossings"], "constant_time_proved": False}
    return results


def check_links(stages):
    measurement, binary, fuzz, delivery = (stages[name] for name in STAGES)
    manifest = sha(measurement / "candidate-source.json")
    memory_path, delivery_path = (measurement / name for name in ("MEMORY_AND_LATENCY_ACCEPTED.json", "DELIVERY_ACCEPTED.json"))
    memory, accepted = read(memory_path), read(delivery_path)
    require(memory["profile"] == accepted["profile"] == PROFILE and memory["accepted"] is True and accepted["accepted"] is True
            and memory["candidate_source_manifest_sha256"] == accepted["candidate_source_manifest_sha256"] == manifest,
            "M07 acceptance manifest differs")
    for name, checksum in memory["evidence_sha256"].items():
        require(sha(measurement.joinpath(*safe_name(name))) == checksum, "memory acceptance evidence differs")
    require(memory["evaluation_sha256"] == sha(measurement / "measurements-evaluation.json")
            and memory["acceptance_sha256"] == sha(measurement / "acceptance.json")
            and memory["timing_capture_sha256"] == accepted["timing_capture_sha256"] == sha(measurement / "timing/capture.json"),
            "M07 acceptance receipt differs")
    require(accepted["binary_review_receipt_sha256"] == sha(binary / "provenance.json"), "delivery review binding differs")
    collection = read(binary / "collection.json")
    require(collection["marker_sha256"] == sha(memory_path) and collection["source_manifest_sha256"] == manifest
            and read(fuzz / "config.json")["candidate_source_manifest_sha256"] == manifest
            and sha(fuzz / "accepted-marker.json") == sha(memory_path)
            and sha(fuzz / "candidate-source.json") == manifest, "binary/fuzz source or acceptance differs")
    for name, source in (("candidate-source.json", measurement / "candidate-source.json"),
                         ("memory-accepted.json", memory_path), ("delivery-accepted.json", delivery_path),
                         ("binary-review.json", binary / "provenance.json"),
                         ("binary-review-collection.json", binary / "collection.json"),
                         ("timing-capture.json", measurement / "timing/capture.json")):
        require(sha(delivery / "validation" / name) == sha(source), "delivery cross-stage input differs: " + name)
    for host in ("windows", "linux"):
        build = read(measurement / "candidate" / host / "build.json")
        require(build["binaries"]["delivered"]["sha256"] == accepted["delivered_binary_sha256"][host], "delivery original hash differs")
        require(sha(delivery / "validation" / (host + "-original-build.json")) == sha(measurement / "candidate" / host / "build.json"),
                "delivery build provenance differs")


def replay(stages):
    measurements = analyze_measurements(stages["measurements"])
    require(measurements == read(stages["measurements"] / "measurements-evaluation.json")
            and measurements["candidate_within_budgets"], "saved measurements/budgets differ")
    check_links(stages)
    timing = check_timing(stages["measurements"])
    return {"profile": PROFILE, "measurements_valid": True,
            "budget_checks_passed": sum(row["pass"] for row in measurements["budget_checks"]),
            "budget_checks_total": len(measurements["budget_checks"]), "timing": timing,
            "binary": verify_binary(stages["binary"]), "fuzz": verify_fuzz(stages["fuzz"]),
            "delivery": verify_delivery(stages["delivery"]), "new_experiments_performed_by_replay": False,
            "global_security_constant_time_or_erasure_proved": False}


@contextmanager
def temporary_directory():
    parent = ROOT / "target/m07-archive-temp"
    require(parent.resolve().is_relative_to(ROOT.resolve()), "temporary parent escapes project")
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="evidence-", dir=parent) as temporary:
        path = Path(temporary)
        require(path.resolve().parent == parent.resolve(), "temporary directory escapes owned parent")
        yield path


@contextmanager
def extracted(output, provenance):
    with temporary_directory() as temporary:
        paths = {}
        for name, record in provenance["stages"].items():
            require(name in STAGES or name == "controls", "unknown M07 evidence stage")
            require(record["archive"] == name + ".tar.gz", "unexpected archive path")
            path = temporary / name
            unpack(output / record["archive"], record, path)
            paths[name] = path
        yield paths


def verify(output):
    provenance = read(output / "provenance.json")
    require(provenance["schema"] == "m07-compact-evidence-v1" and provenance["profile"] == PROFILE
            and set(provenance["stages"]) == set(STAGES) | {"controls"}, "invalid M07 snapshot schema")
    required = {"provenance.json", *provenance["sidecar_sha256"], *(name + ".tar.gz" for name in provenance["stages"])}
    require({path.name for path in output.iterdir()} == required, "snapshot file inventory differs")
    for name, checksum in provenance["sidecar_sha256"].items():
        require(len(safe_name(name)) == 1 and sha(output / name) == checksum, "snapshot sidecar changed")
    with extracted(output, provenance) as paths:
        result = replay(paths)
    require(result == read(output / "summary.json"), "M07 archived outcome does not replay")
    return {"stages_verified": len(STAGES), **result}


def control_closure():
    todo = [Path(__file__).name]
    found = set()
    while todo:
        name = todo.pop()
        if name in found:
            continue
        found.add(name)
        for node in ast.walk(ast.parse((ROOT / "research" / name).read_text(encoding="utf-8-sig"))):
            modules = [node.module] if isinstance(node, ast.ImportFrom) else ([a.name for a in node.names] if isinstance(node, ast.Import) else [])
            todo.extend(module + ".py" for module in modules if module and (ROOT / "research" / (module + ".py")).is_file())
    return sorted(found)


def freeze(output):
    require(output.parent.resolve() == (ROOT / "results/engine").resolve() and not output.exists(), "new direct results/engine snapshot required")
    sources = {name: ROOT / "artifacts/generated" / folder for name, folder in STAGES.items()}
    result = replay(sources)
    output.mkdir()
    stages = {name: pack(path, output / (name + ".tar.gz")) for name, path in sources.items()}
    with temporary_directory() as temporary:
        for name in control_closure():
            shutil.copyfile(ROOT / "research" / name, temporary / name)
        stages["controls"] = pack(temporary, output / "controls.tar.gz")
    save(output / "summary.json", result)
    (output / "README.md").write_text("# MAJAX R6 — M07 evidence\n\n"
        "Four byte-preserving stage archives retain all raw files, binaries, sources, logs and empty directories.\n"
        "The provenance records every file's SHA-256 and size. No build cache is included.\n\n"
        "Run `python research/archive_m07.py verify --output results/engine/m07-001` from the checkout.\n"
        "This unpacks into a temporary directory and replays data checks only: no compiler, executable,\n"
        "objdump, benchmark or fuzz campaign is run. The controls archive preserves the Python import closure.\n\n"
        "`delivery.tar.gz` contains the Windows ZIP and Linux tar.gz packages plus compact compilable\n"
        "source and licenses; its `result.json` lists the exact archive names and SHA-256 values.\n"
        "The packages carry the original reviewed delivered binaries, not the comparison rebuilds.\n"
        "`binary.tar.gz` includes OBSERVATIONS.md and the preexisting Windows invalid-key spill limit.\n"
        "`measurements.tar.gz` contains baseline, preregistered budgets, candidate, raw memory/latency,\n"
        "full regression receipt and finite timing diagnostic. `fuzz.tar.gz` is a new finite M07\n"
        "ASan/std-rebuilt campaign, with no LLVM source coverage or independent oracle replay claimed.\n\n"
        "See docs/M07_MEMOIRE_ET_VALIDATION.md for results and limits. These archives do not establish\n"
        "global cryptographic security, complete erasure or constant time. Historical absolute paths\n"
        "are provenance strings and are not dereferenced during verification.\n", encoding="utf-8", newline="\n")
    save(output / "provenance.json", {"schema": "m07-compact-evidence-v1", "profile": PROFILE,
         "created_utc": datetime.now(timezone.utc).isoformat(), "stages": stages,
         "sidecar_sha256": {name: sha(output / name) for name in ("README.md", "summary.json")}})
    return verify(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("freeze", "verify"))
    parser.add_argument("--output", type=Path, default=ROOT / "results/engine/m07-001")
    args = parser.parse_args()
    print(json.dumps(freeze(args.output) if args.action == "freeze" else verify(args.output), indent=2))


if __name__ == "__main__":
    main()
