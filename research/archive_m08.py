"""Freeze/replay all M08 evidence using bounded, deterministic archive shards.

Every byte and empty directory is preserved. Large logical gzip streams are
split at fixed compressed-byte boundaries; no input is omitted or truncated.
Verification extracts data under target and runs only offline data replays.
"""
import argparse
import ast
from contextlib import contextmanager
from datetime import datetime, timezone
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import tempfile

from archive_m07 import BoundedReader, safe_name
from analyze_delivery_timing import analyze as analyze_timing
from collect_m08_cli_inventory import verify as verify_cli
from package_m08 import verify as verify_delivery, verify_diagnostic_notices
from postprocess_m08_fuzz import verify as verify_postprocessing
from review_m08_imports import verify as verify_imports
from verify_m08_measurements import analyze as analyze_measurements, execution, runtime_stderr, AFFINITY_SHA

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "KEM1536-DEV-Q7681-R1"
STAGES = {"measurements": "m08-001", "imports": "m08-import-review-001",
          "cli": "m08-cli-inventory-001", "fuzz": "m08-fuzz-001",
          "delivery": "m08-delivery-001", "diagnostic-notices": "m08-diagnostic-notices-001"}
PART_BYTES = 90 * 1024 * 1024
MAX_PAYLOAD_BYTES = 16 * 1024**3
MAX_INVENTORY_BYTES = 1024**3
MAX_MEMBERS = 1_000_000
BLOCK = 512
CONTROL_ROOTS = ("archive_m08.py", "smoke_m08_package.py", "test_archive_m08.py", "test_smoke_m08_package.py",
                 "test_resume_m08_postprocess.py")


def require(condition, message):
    if not condition:
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


def name_parts(name):
    parts = safe_name(name)
    require(len(name.encode("utf-8")) <= 4096 and all(len(p.encode("utf-8")) <= 255 for p in parts),
            "archive member name exceeds portable size budget")
    return parts


def ordinary(path, directory=False):
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and not getattr(info, "st_file_attributes", 0) & 0x400,
            "archive path contains a link/reparse point")
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), "archive path is not ordinary")
    if not directory:
        require(info.st_nlink == 1, "archive input must not be a hard link")
    return info


def inventory(folder):
    ordinary(folder, directory=True)
    files, directories, spellings = {}, [], set()
    for parent, children, members in os.walk(folder, followlinks=False):
        for part in children + members:
            path = Path(parent) / part
            name = path.relative_to(folder).as_posix()
            name_parts(name)
            require(name.casefold() not in spellings, "case-aliasing archive input")
            spellings.add(name.casefold())
            info = ordinary(path, directory=part in children)
            if part in children:
                directories.append(name)
            else:
                files[name] = dict(sha256=sha(path), bytes=info.st_size)
    result = dict(files=dict(sorted(files.items())), directories=sorted(directories))
    validate_inventory(result)
    return result


def validate_inventory(value):
    require(isinstance(value, dict) and set(value) == {"files", "directories"}, "invalid M08 inventory schema")
    files, directories = value["files"], value["directories"]
    require(isinstance(files, dict) and isinstance(directories, list) and directories == sorted(set(directories)),
            "invalid file/directory inventory")
    names = set(files) | set(directories)
    require(len(names) == len(files) + len(directories) and len(names) <= MAX_MEMBERS,
            "member count budget or file/directory collision")
    folded = set()
    for name in names:
        name_parts(name)
        require(name.casefold() not in folded, "case-aliasing archive member")
        folded.add(name.casefold())
        require(all(p.as_posix() in directories for p in PurePosixPath(name).parents if p.as_posix() != "."),
                "missing parent directory in archive inventory")
    for row in files.values():
        require(isinstance(row, dict) and set(row) == {"sha256", "bytes"}
                and type(row["bytes"]) is int and row["bytes"] >= 0
                and isinstance(row["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]),
                "invalid member size/SHA-256")
    require(sum(row["bytes"] for row in files.values()) <= MAX_PAYLOAD_BYTES, "file payload budget exceeded")


def tar_byte_budget(value):
    """Account for data padding, headers, one bounded PAX path per member, EOF."""
    names = [*value["directories"], *value["files"]]
    padded_data = sum(((row["bytes"] + BLOCK - 1) // BLOCK) * BLOCK for row in value["files"].values())
    path_records = sum(BLOCK + ((len(name.encode("utf-8")) + 128 + BLOCK - 1) // BLOCK) * BLOCK for name in names)
    return padded_data + len(names) * BLOCK + path_records + tarfile.RECORDSIZE


class ShardWriter:
    """File-like sink splitting one logical compressed stream deterministically."""
    def __init__(self, output, stem, part_limit=PART_BYTES):
        require(len(name_parts(stem)) == 1, "flat archive stem required")
        require(type(part_limit) is int and 1 <= part_limit <= PART_BYTES, "invalid shard byte limit")
        ordinary(output, directory=True)
        self.output, self.stem, self.limit = output, stem, part_limit
        self.parts, self.handle = [], None
        self.total, self.part_size = 0, 0
        self.digest, self.part_digest = hashlib.sha256(), None

    def _finish_part(self):
        if self.handle is None:
            return
        self.handle.close()
        self.parts.append(dict(name=self.current.name, bytes=self.part_size, sha256=self.part_digest.hexdigest()))
        self.handle = None

    def write(self, data):
        view = memoryview(data)
        offset = 0
        while offset < len(view):
            if self.handle is None:
                require(len(self.parts) < 9999, "too many archive shards")
                self.current = self.output / f"{self.stem}.part-{len(self.parts)+1:04d}"
                self.handle = self.current.open("xb")
                self.part_size, self.part_digest = 0, hashlib.sha256()
            length = min(len(view) - offset, self.limit - self.part_size)
            chunk = view[offset:offset + length]
            require(self.handle.write(chunk) == length, "short archive write")
            self.digest.update(chunk);self.part_digest.update(chunk)
            self.total += length;self.part_size += length;offset += length
            if self.part_size == self.limit:
                self._finish_part()
        return len(view)

    def flush(self):
        if self.handle is not None:
            self.handle.flush()

    def tell(self):
        return self.total

    def close(self):
        if self.handle is not None:
            self.handle.close()
            self.handle = None

    def finish(self):
        self._finish_part()
        require(self.parts, "empty compressed archive stream")
        if len(self.parts) == 1:
            source, destination = self.output / self.parts[0]["name"], self.output / self.stem
            require(source.resolve().parent == destination.resolve().parent == self.output.resolve()
                    and not destination.exists(), "single-shard rename escaped owned output")
            source.rename(destination)
            self.parts[0]["name"] = destination.name
        return dict(stem=self.stem, parts=self.parts, bytes=self.total,
                    sha256=self.digest.hexdigest(), part_limit_bytes=self.limit)


def check_parts(record, stem):
    require(isinstance(record, dict) and set(record) == {"stem", "parts", "bytes", "sha256", "part_limit_bytes"}
            and record["stem"] == stem and len(name_parts(stem)) == 1, "archive stream schema/stem differs")
    parts = record["parts"]
    require(isinstance(parts, list) and 0 < len(parts) <= 9999
            and type(record["part_limit_bytes"]) is int and 1 <= record["part_limit_bytes"] <= PART_BYTES,
            "archive shard limits differ")
    expected = [stem] if len(parts) == 1 else [f"{stem}.part-{i+1:04d}" for i in range(len(parts))]
    for index, (part, name) in enumerate(zip(parts, expected, strict=True)):
        require(isinstance(part, dict) and set(part) == {"name", "bytes", "sha256"} and part["name"] == name
                and type(part["bytes"]) is int and 0 < part["bytes"] <= record["part_limit_bytes"]
                and isinstance(part["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", part["sha256"]),
                "invalid, reordered or oversized archive shard")
        require(index == len(parts) - 1 or part["bytes"] == record["part_limit_bytes"], "nonfinal shard is not full")
    require(type(record["bytes"]) is int and record["bytes"] == sum(p["bytes"] for p in parts)
            and isinstance(record["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", record["sha256"]),
            "archive stream total differs")
    return {p["name"] for p in parts}


class ShardReader:
    """Streaming concatenation with per-part and complete compressed SHA checks."""
    def __init__(self, output, record, stem):
        check_parts(record, stem)
        self.output, self.record = output, record
        self.index, self.handle, self.total = 0, None, 0
        self.digest = hashlib.sha256()

    def read(self, size=-1):
        require(type(size) is int and size >= 0, "sized archive reads required")
        chunks, remaining = [], size
        while remaining > 0 and self.index < len(self.record["parts"]):
            part = self.record["parts"][self.index]
            if self.handle is None:
                path = self.output / part["name"]
                require(path.resolve().parent == self.output.resolve(), "shard path escaped output")
                require(ordinary(path).st_size == part["bytes"], "archive shard size differs")
                self.handle = path.open("rb")
                self.part_size, self.part_digest = 0, hashlib.sha256()
            data = self.handle.read(remaining)
            if data:
                chunks.append(data);remaining -= len(data)
                self.total += len(data);self.part_size += len(data)
                self.digest.update(data);self.part_digest.update(data)
            else:
                require(self.part_size == part["bytes"] and self.part_digest.hexdigest() == part["sha256"],
                        "archive shard checksum differs")
                self.handle.close();self.handle = None;self.index += 1
        return b"".join(chunks)

    def finish(self):
        while self.read(1024 * 1024):
            pass
        require(self.total == self.record["bytes"] and self.digest.hexdigest() == self.record["sha256"],
                "logical compressed archive checksum differs")

    def close(self):
        if self.handle is not None:
            self.handle.close();self.handle = None


def write_inventory(output, stage, value, part_limit):
    writer = ShardWriter(output, stage + ".inventory.json.gz", part_limit)
    digest, length = hashlib.sha256(), 0
    try:
        with gzip.GzipFile(fileobj=writer, mode="wb", filename="", mtime=0) as compressed:
            encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
            for fragment in encoder.iterencode(value):
                raw = fragment.encode("utf-8")
                length += len(raw)
                require(length <= MAX_INVENTORY_BYTES, "inventory JSON byte budget exceeded")
                digest.update(raw);compressed.write(raw)
        return dict(stream=writer.finish(), json_bytes=length, json_sha256=digest.hexdigest())
    finally:
        writer.close()


def read_inventory(output, stage, record):
    require(set(record) == {"stream", "json_bytes", "json_sha256"} and type(record["json_bytes"]) is int
            and 0 < record["json_bytes"] <= MAX_INVENTORY_BYTES, "inventory JSON bounds differ")
    reader = ShardReader(output, record["stream"], stage + ".inventory.json.gz")
    try:
        with gzip.GzipFile(fileobj=reader, mode="rb") as compressed:
            bounded = BoundedReader(compressed, record["json_bytes"])
            chunks = []
            while chunk := bounded.read(1024 * 1024):
                chunks.append(chunk)
        reader.finish()
        raw = b"".join(chunks)
        require(len(raw) == record["json_bytes"] and hashlib.sha256(raw).hexdigest() == record["json_sha256"],
                "inventory JSON checksum differs")
        value = json.loads(raw)
        validate_inventory(value)
        return value
    finally:
        reader.close()


def pack_stage(source, output, stage, part_limit=PART_BYTES):
    before = inventory(source)
    encoded_inventory = write_inventory(output, stage, before, part_limit)
    writer = ShardWriter(output, stage + ".tar.gz", part_limit)
    try:
        with gzip.GzipFile(fileobj=writer, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for name in sorted([*before["directories"], *before["files"]]):
                    info = tarfile.TarInfo(name)
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ""
                    info.mode = 0o755 if name in before["directories"] else 0o644
                    if name in before["directories"]:
                        info.type = tarfile.DIRTYPE
                        archive.addfile(info)
                    else:
                        info.size = before["files"][name]["bytes"]
                        with (source / name).open("rb") as stream:
                            archive.addfile(info, stream)
        stream = writer.finish()
    finally:
        writer.close()
    require(inventory(source) == before, "archive stage changed during packing")
    return dict(archive=stream, inventory=encoded_inventory, file_count=len(before["files"]),
                directory_count=len(before["directories"]), payload_bytes=sum(r["bytes"] for r in before["files"].values()))


def unpack_stage(output, stage, record, destination):
    require(set(record) == {"archive", "inventory", "file_count", "directory_count", "payload_bytes"},
            "M08 stage record schema differs")
    value = read_inventory(output, stage, record["inventory"])
    files, directories = value["files"], value["directories"]
    require(type(record["file_count"]) is int and record["file_count"] == len(files)
            and type(record["directory_count"]) is int and record["directory_count"] == len(directories)
            and type(record["payload_bytes"]) is int and record["payload_bytes"] == sum(r["bytes"] for r in files.values()),
            "stage inventory count/byte summary differs")
    expected, seen = set(files) | set(directories), set()
    destination.mkdir()
    reader = ShardReader(output, record["archive"], stage + ".tar.gz")
    try:
        with gzip.GzipFile(fileobj=reader, mode="rb") as compressed:
            bounded = BoundedReader(compressed, tar_byte_budget(value))
            with tarfile.open(fileobj=bounded, mode="r|") as archive:
                for info in archive:
                    name_parts(info.name)
                    require(info.name in expected and info.name not in seen, "unlisted or duplicate TAR member")
                    require(set(info.pax_headers) <= {"path"}
                            and (not info.pax_headers or info.pax_headers["path"] == info.name),
                            "unexpected PAX metadata")
                    seen.add(info.name)
                    target = destination.joinpath(*name_parts(info.name))
                    require(target.resolve().is_relative_to(destination.resolve()), "TAR member escaped extraction")
                    if info.name in directories:
                        require(info.type == tarfile.DIRTYPE and info.size == 0, "invalid directory TAR member")
                        target.mkdir(parents=True, exist_ok=True)
                    else:
                        require(info.type == tarfile.REGTYPE and info.size == files[info.name]["bytes"], "invalid regular TAR member")
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with archive.extractfile(info) as source, target.open("xb") as sink:
                            shutil.copyfileobj(source, sink, length=1024 * 1024)
                        require(sha(target) == files[info.name]["sha256"], "unpacked member checksum differs")
                # tarfile's stream reader may have prefetched bytes past TAR EOF.
                # Only zero padding is admissible; do not hide a second archive.
                require(not any(archive.fileobj.buf), "nonzero buffered data follows TAR EOF")
            while trailing := bounded.read(1024 * 1024):
                require(not any(trailing), "nonzero data follows TAR EOF")
        reader.finish()
    finally:
        reader.close()
    require(seen == expected and inventory(destination) == value, "extracted stage inventory differs")


@contextmanager
def temporary_directory():
    parent = ROOT / "target/m08-archive-temp"
    require(parent.resolve().is_relative_to(ROOT.resolve()), "temporary parent escapes project")
    parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="evidence-", dir=parent) as directory:
        path = Path(directory)
        require(path.resolve().parent == parent.resolve(), "temporary directory escapes owned parent")
        yield path


def moment(text):
    value = datetime.fromisoformat(text)
    require(value.tzinfo is not None and value.utcoffset().total_seconds() == 0, "UTC timestamp required")
    return value


def same_file(left, right, description):
    require(sha(left) == sha(right), description + " differs")


def check_timing(measurements):
    folder = measurements / "timing"
    capture = read(folder / "capture.json")
    require(capture["source_manifest_sha256"] == sha(measurements / "candidate-source.json")
            and capture["controller_sha256"] == sha(measurements / "run_validation_and_measurements.py")
            and capture["observations"] == 32000 and capture["CPU"] == 10
            and capture["constant_time_proved"] is False and set(capture["hosts"]) == {"windows", "linux"},
            "timing acquisition/source/scope differs")
    results = {}
    for host, row in capture["hosts"].items():
        binary = read(measurements / "candidate" / host / "build.json")["binaries"]["timing"]
        require(row["binary_sha256"] == binary["sha256"] == sha(measurements / binary["path"])
                and row["raw_sha256"] == sha(folder / host / "observations.jsonl")
                and row["analysis_sha256"] == sha(folder / host / "analysis.json"), "timing image/data differs")
        execution(row["command"], host, binary["path"], ["delivery-timing"], 10 if host == "linux" else None)
        runtime_stderr((folder / host / "runtime.stderr").read_bytes(), host)
        with (folder / host / "observations.jsonl").open(encoding="utf-8") as stream:
            computed = analyze_timing(json.loads(line) for line in stream)
        require(computed == read(folder / host / "analysis.json")
                and computed["maximum_absolute_t"] == row["maximum_absolute_t"]
                and computed["threshold_crossings"] == row["threshold_crossings"], "timing diagnostic does not replay")
        results[host] = {key: computed[key] for key in ("observations", "maximum_absolute_t", "threshold_crossings", "constant_time_proved")}
    return results


def check_launch(measurements, imports, fuzz):
    gate_path = measurements / "LONG_CAMPAIGN_ACCEPTED.json"
    launch_path = measurements / "long-campaign-launch.json"
    gate, launch, finished, config = (read(path) for path in (gate_path, launch_path,
          measurements / "long-campaign-exit.json", fuzz / "config.json"))
    require(gate["profile"] == PROFILE and gate["accepted"] is True
            and gate["targeted_import_spill_correction_qualified"] is True
            and gate["candidate_source_manifest_sha256"] == sha(measurements / "candidate-source.json")
            and gate["fuzz_plan_sha256"] == sha(measurements / "m08-fuzz-plan.json")
            and gate["memory_acceptance_sha256"] == sha(measurements / "MEMORY_AND_LATENCY_ACCEPTED.json")
            and gate["import_review_receipt_sha256"] == sha(imports / "provenance.json"), "root long-campaign gate differs")
    require(launch["long_campaign_acceptance_sha256"] == sha(gate_path)
            and launch["controller_sha256"] == config["controller_sha256"]["run_m08_fuzz.py"]
            == sha(fuzz / "controls/run_m08_fuzz.py")
            and finished["launch_receipt_sha256"] == sha(launch_path)
            and type(finished["exit_code"]) is int and finished["exit_code"] == 0, "root launch/exit receipt differs")
    command = launch["command"]
    require(isinstance(command, list) and all(type(item) is str for item in command)
            and len(command) == 15 and command[:5] == ["wsl.exe", "-d", "Ubuntu-22.04", "--", "python3"]
            and command[5].endswith("/research/run_m08_fuzz.py") and command[6] == "run"
            and command[7::2] == ["--measurements", "--plan", "--output", "--target-dir"],
            "recorded root launch command differs")
    root = command[5][:-len("/research/run_m08_fuzz.py")]
    require(PurePosixPath(root).is_absolute() and root == str(PurePosixPath(root)) and ".." not in PurePosixPath(root).parts,
            "invalid historical launch root")
    for value, suffix in zip(command[8::2], ["/artifacts/generated/m08-001", "/research/m08-fuzz-plan.json",
                                          "/artifacts/generated/m08-fuzz-001", "/target/m08-fuzz-001"], strict=True):
        require(value == root + suffix, "recorded root launch argument/root differs")
    build = config["build_command"]
    require(build.count("--fuzz-dir") == build.count("--target-dir") == 1
            and build[build.index("--fuzz-dir") + 1] == root + "/artifacts/generated/m08-fuzz-001/source/fuzz"
            and build[build.index("--target-dir") + 1] == root + "/target/m08-fuzz-001", "root launch/campaign build paths differ")
    require(moment(read(measurements / "MEMORY_AND_LATENCY_ACCEPTED.json")["created_utc"])
            <= moment(gate["created_utc"]) <= moment(launch["created_utc"]) <= moment(config["started_utc"])
            <= moment(read(fuzz / "fuzz-summary.json")["finished_utc"]) <= moment(finished["finished_utc"]),
            "root gate/launch/campaign/exit chronology differs")
    return {"root_launch_gate_bound_to_sealed_review": True,
            "controller_enforces_quantitative_gate_only": True, "recorded_exit_code": 0,
            "recorded_UTC_order_verified": True, "external_timestamp_attestation": False}


def check_links(stages):
    measurements, imports, cli, fuzz, delivery, notices = (stages[name] for name in STAGES)
    manifest = sha(measurements / "candidate-source.json")
    memory_path, delivery_path = (measurements / name for name in ("MEMORY_AND_LATENCY_ACCEPTED.json", "DELIVERY_ACCEPTED.json"))
    memory, accepted = read(memory_path), read(delivery_path)
    require(memory["profile"] == accepted["profile"] == PROFILE and memory["accepted"] is True and accepted["accepted"] is True
            and memory["candidate_source_manifest_sha256"] == accepted["candidate_source_manifest_sha256"] == manifest,
            "M08 acceptance source/profile differs")
    for field, name in (("evaluation_sha256", "measurements-evaluation.json"), ("acceptance_sha256", "m08-acceptance.json"),
                        ("fuzz_plan_sha256", "m08-fuzz-plan.json"), ("regression_receipt_sha256", "regression/summary.json"),
                        ("helper_bindings_sha256", "helper-bindings.json"), ("timing_capture_sha256", "timing/capture.json")):
        require(memory[field] == sha(measurements / name), "quantitative acceptance evidence differs: " + field)
    require(accepted["import_review_receipt_sha256"] == sha(imports / "provenance.json")
            and accepted["cli_inventory_receipt_sha256"] == sha(cli / "provenance.json")
            and accepted["timing_capture_sha256"] == memory["timing_capture_sha256"], "delivery review/timing receipt differs")
    review, inventory_ = read(imports / "collection.json"), read(cli / "collection.json")
    require(review["memory_acceptance_sha256"] == inventory_["memory_acceptance_sha256"] == sha(memory_path)
            and inventory_["source_manifest_sha256"] == manifest, "review/CLI quantitative gate differs")
    for label in ("baseline", "candidate"):
        source_path = measurements / (label + "-source.json")
        require(review["source_manifest_sha256"][label] == sha(source_path), "review source differs")
        same_file(imports / "inputs" / (label + "-source.json"), source_path, "review source copy")
        for host in ("windows", "linux"):
            build_path = measurements / label / host / "build.json"
            build = read(build_path)
            key = label + "-" + host
            require(review["build_receipt_sha256"][key] == sha(build_path)
                    and review["binaries"][key] == build["binaries"]["consumer"], "consumer review original image differs")
            same_file(imports / "inputs" / (key + "-build.json"), build_path, "consumer build copy")
    same_file(imports / "inputs/memory-accepted.json", memory_path, "import review gate copy")
    same_file(cli / "inputs/memory-accepted.json", memory_path, "CLI gate copy")
    same_file(cli / "inputs/candidate-source.json", measurements / "candidate-source.json", "CLI source copy")
    for host in ("windows", "linux"):
        build_path = measurements / "candidate" / host / "build.json"
        build = read(build_path)
        require(inventory_["build_receipt_sha256"][host] == sha(build_path)
                and build["binaries"]["delivered"]["sha256"] == accepted["delivered_binary_sha256"][host],
                "CLI/delivery original build differs")
        for kind in ("research", "delivered"):
            require(inventory_["binaries"][host + "-" + kind] == build["binaries"][kind], "CLI inventory original identity differs")
        same_file(cli / "inputs" / (host + "-build.json"), build_path, "CLI build copy")
        same_file(delivery / "validation" / (host + "-original-build.json"), build_path, "delivery build copy")
    for name, source in (("memory-accepted.json", memory_path), ("delivery-accepted.json", delivery_path),
            ("candidate-source.json", measurements / "candidate-source.json"), ("import-review.json", imports / "provenance.json"),
            ("import-review-collection.json", imports / "collection.json"), ("cli-inventory.json", cli / "provenance.json"),
            ("cli-inventory-collection.json", cli / "collection.json"), ("timing-capture.json", measurements / "timing/capture.json")):
        same_file(delivery / "validation" / name, source, "delivery cross-stage copy " + name)
    same_file(fuzz / "accepted-marker.json", memory_path, "fuzz quantitative marker")
    same_file(fuzz / "candidate-source.json", measurements / "candidate-source.json", "fuzz measured source")
    same_file(fuzz / "fuzz-plan.json", measurements / "m08-fuzz-plan.json", "fuzz preregistered plan")
    config = read(fuzz / "config.json")
    require(config["measured_source_sha256"] == read(measurements / "candidate-source.json")["source_sha256"],
            "fuzz compiled measured source map differs")
    same_file(notices / "inputs/campaign-config.json", fuzz / "config.json", "diagnostic notice campaign")
    same_file(notices / "inputs/fuzz-Cargo.lock", fuzz / "source/fuzz/Cargo.lock", "diagnostic notice lock")
    binaries = {"fuzz/" + name: sha(fuzz / "bin" / name) for name in read(fuzz / "built.json")["binary_sha256"]}
    binaries.update({"coverage/" + name: sha(fuzz / "postprocessing/bin" / name)
                     for name in read(fuzz / "built.json")["binary_sha256"]})
    binaries["deterministic-replay"] = sha(fuzz / "bin/m08-replay")
    require(read(notices / "notices.json")["diagnostic_binary_sha256"] == binaries, "all nine notice binary identities differ")
    chronology = check_launch(measurements, imports, fuzz)
    require(moment(read(measurements / "timing/capture.json")["created_utc"]) <= moment(memory["created_utc"]),
            "quantitative gate predates timing completion")
    return chronology


def local_imports(path, folder):
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8-sig"))):
        modules = ([node.module] if isinstance(node, ast.ImportFrom)
                   else [alias.name for alias in node.names] if isinstance(node, ast.Import) else [])
        for module in modules:
            if module and (folder / (module + ".py")).is_file():
                yield module + ".py"


def control_closure(folder=None):
    folder = ROOT / "research" if folder is None else folder
    todo, found = list(CONTROL_ROOTS), set()
    while todo:
        name = todo.pop()
        if name in found:
            continue
        require(len(name_parts(name)) == 1, "flat control names required")
        ordinary(folder / name)
        found.add(name)
        todo.extend(local_imports(folder / name, folder))
    return sorted(found)


def check_controls(stages):
    folder = stages["controls"]
    members = inventory(folder)
    require(not members["directories"] and set(members["files"]) == set(control_closure(folder)),
            "recursive Python controls closure differs")
    helper = read(stages["measurements"] / "helper-bindings.json")
    require(sha(folder / "capture_m07_timing.py") == helper["sha256"] == AFFINITY_SHA
            and helper["matches_preregistered_git_blob"] is True and helper["os_affinity_attestation"] is False,
            "actual preserved affinity helper differs from preregistered blob")
    same_file(folder / "run_m08.py", stages["measurements"] / "candidate-source/research/run_m08.py", "candidate acquisition controller")
    for name, checksum in read(stages["fuzz"] / "config.json")["controller_sha256"].items():
        require(sha(folder / name) == checksum, "preserved launch controller differs: " + name)
    return {"Python_control_files": len(members["files"]), "recursive_import_closure_retained": True,
            "affinity_helper_matches_preregistered_blob": True, "OS_affinity_attested": False}


def postprocessing_recovery(campaign):
    """Replay an optional interruption receipt without renewing any experiment."""
    folder = campaign / "postprocessing"
    final = read(folder / "postprocess.json")
    if "recovery_receipt_sha256" not in final:
        preserved = []
        for name in ("recovery-request.json", "recovery.json", "recovery-adapter.py", "interrupted-oracle-001"):
            try:
                (folder / name).lstat()
            except FileNotFoundError:
                continue
            preserved.append(name)
        require(not preserved, "preserved recovery evidence lacks postprocessing receipt marker")
        return None
    # Kept local so a campaign with no recovery receipt does not invoke the
    # recovery verifier. The AST control closure still preserves this helper.
    from resume_m08_postprocess import verify_recovery
    result = verify_recovery(campaign)
    require(type(result) is dict and set(result) == {"interrupted_oracle_attempt_preserved",
                "original_campaign_or_coverage_rerun", "resumed_oracle_exit_code"}
            and result["interrupted_oracle_attempt_preserved"] is True
            and result["original_campaign_or_coverage_rerun"] is False
            and type(result["resumed_oracle_exit_code"]) is int and result["resumed_oracle_exit_code"] == 0,
            "postprocessing recovery result/scope differs")
    return result


def replay(stages):
    require(set(stages) == set(STAGES) | {"controls"}, "complete six data stages and controls required")
    measurements = analyze_measurements(stages["measurements"])
    require(measurements == read(stages["measurements"] / "measurements-evaluation.json")
            and measurements["data_valid"] is True and measurements["candidate_within_budgets"] is True
            and len(measurements["budget_checks"]) == 210 and all(row["pass"] for row in measurements["budget_checks"]),
            "saved quantitative evidence or one of 210 budgets differs")
    chronology = check_links(stages)
    # postprocessing.verify invokes run_m08_fuzz.verify before coverage/oracle checks.
    # Its main CPU total is retained once and never added to coverage execution.
    fuzz = verify_postprocessing(stages["fuzz"])
    recovery = postprocessing_recovery(stages["fuzz"])
    return {"profile": PROFILE, "measurements_valid": True, "budget_checks_passed": 210, "budget_checks_total": 210,
            "runtime_stderr_diagnostics": measurements["runtime_stderr_diagnostics"],
            "timing": check_timing(stages["measurements"]), "launch_chronology": chronology,
            "imports": verify_imports(stages["imports"]), "CLI_inventory": verify_cli(stages["cli"]),
            "fuzz_and_postprocessing": fuzz, "postprocessing_recovery": recovery,
            "delivery": verify_delivery(stages["delivery"]),
            "diagnostic_notices": verify_diagnostic_notices(stages["diagnostic-notices"]), "controls": check_controls(stages),
            "main_campaign_CPU_is_counted_once": True, "new_experiments_performed_by_replay": False,
            "consumer_import_review_is_not_CLI_PKE_erasure_proof": True,
            "global_security_constant_time_or_erasure_proved": False}


@contextmanager
def extracted(output, provenance):
    with temporary_directory() as temporary:
        paths = {}
        for name, record in provenance["stages"].items():
            require(name in STAGES or name == "controls", "unknown M08 evidence stage")
            paths[name] = temporary / name
            unpack_stage(output, name, record, paths[name])
        yield paths


def snapshot_provenance(output):
    """Validate the compact manifest and flat physical shard/sidecar inventory."""
    ordinary(output, directory=True)
    provenance = read(output / "provenance.json")
    require(provenance["schema"] == "m08-sharded-evidence-v1" and provenance["profile"] == PROFILE
            and set(provenance["stages"]) == set(STAGES) | {"controls"}
            and set(provenance["sidecar_sha256"]) == {"README.md", "summary.json"}, "invalid M08 snapshot schema")
    moment(provenance["created_utc"])
    required = {"provenance.json", *provenance["sidecar_sha256"]}
    for name, record in provenance["stages"].items():
        required |= check_parts(record["archive"], name + ".tar.gz")
        required |= check_parts(record["inventory"]["stream"], name + ".inventory.json.gz")
    require({path.name for path in output.iterdir()} == required, "snapshot file inventory differs")
    for path in output.iterdir():
        ordinary(path)
        require(path.stat().st_size < 100 * 1024 * 1024, "snapshot member exceeds GitHub file budget")
    for name, checksum in provenance["sidecar_sha256"].items():
        require(len(name_parts(name)) == 1 and sha(output / name) == checksum, "snapshot sidecar differs")
    return provenance


@contextmanager
def extracted_stage(output, name):
    """Extract a selected stage and checksum-bound recursive controls, without execution.

    Used by the explicitly separate native smoke action. Other data stages are
    checked against the top-level physical inventory but are not decompressed.
    The selected stage and controls verify every shard, member size/hash and dir.
    """
    require(name in STAGES, "unknown selected M08 data stage")
    provenance = snapshot_provenance(output)
    with temporary_directory() as temporary:
        controls = temporary / "controls"
        unpack_stage(output, "controls", provenance["stages"]["controls"], controls)
        members = inventory(controls)
        require(not members["directories"] and set(members["files"]) == set(control_closure(controls)),
                "selected archive recursive controls closure differs")
        stage = temporary / name
        unpack_stage(output, name, provenance["stages"][name], stage)
        yield stage


def verify(output):
    provenance = snapshot_provenance(output)
    with extracted(output, provenance) as paths:
        result = replay(paths)
    require(result == read(output / "summary.json"), "M08 archived outcome does not replay")
    return {"data_stages_verified": len(STAGES), "all_raw_files_and_empty_directories_retained": True, **result}


def freeze(output):
    require(output.parent.resolve() == (ROOT / "results/engine").resolve() and not output.exists(),
            "new direct results/engine snapshot required")
    sources = {name: ROOT / "artifacts/generated" / folder for name, folder in STAGES.items()}
    with temporary_directory() as temporary:
        controls = temporary / "controls"
        controls.mkdir()
        for name in control_closure():
            shutil.copyfile(ROOT / "research" / name, controls / name)
        sources["controls"] = controls
        result = replay(sources)  # Refuse incomplete panels before creating any result.
        output.mkdir()
        stages = {name: pack_stage(path, output, name) for name, path in sources.items()}
    save(output / "summary.json", result)
    (output / "README.md").write_text("# MAJAX R6 — M08 evidence\n\n"
        "Six complete data stages and the recursive Python controls retain every raw file, source, binary, log\n"
        "and empty directory. Each logical deterministic TAR gzip stream and JSON gzip inventory is split,\n"
        "when necessary, into consecutive compressed-byte shards of at most 90 MiB. No input is omitted.\n"
        "The manifest records every shard and complete stream checksum; inventories retain per-file sizes/SHA-256.\n\n"
        "Run `python -B research/archive_m08.py verify --output results/engine/m08-001`. Verification extracts\n"
        "under target and replays data checks only. No Git, compiler, executable, disassembler, benchmark,\n"
        "fuzzer or new oracle execution is run. Historical absolute paths remain provenance strings.\n\n"
        "Measurements retain 46 baseline and 46 candidate inputs, 300000 paired observations, 2880 memory rows,\n"
        "complete regressions, finite consumer validations and 32000 timing observations. Root launch gate\n"
        "and exit receipts separately bind the sealed import review; the campaign controller enforces the\n"
        "quantitative gate only. The four long ASan/std-rebuilt harnesses credit no historical CPU. Separate\n"
        "LLVM coverage objects use distributed std; stored Rust/Python corpus transcripts replay without execution.\n\n"
        "The import consumer review and shipped CLI inventories concern distinct images. Delivery retains\n"
        "the original inventoried CLI images plus repetition comparisons, source and notices. Diagnostic notices\n"
        "identify all four main fuzz, four coverage and one replay binaries. The controls preserve acquisition\n"
        "and verification import dependencies, including the unchanged preregistered affinity helper.\n\n"
        "These finite checks do not prove global cryptographic security, constant time, complete erasure,\n"
        "OS affinity, third-party reproduction or entropy of imported private keys. See docs/M08_IMPORTS_ET_VALIDATION.md.\n",
        encoding="utf-8", newline="\n")
    save(output / "provenance.json", {"schema": "m08-sharded-evidence-v1", "profile": PROFILE,
        "created_utc": datetime.now(timezone.utc).isoformat(), "stages": stages,
        "sidecar_sha256": {name: sha(output / name) for name in ("README.md", "summary.json")}})
    return verify(output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("freeze", "verify"))
    parser.add_argument("--output", type=Path, default=ROOT / "results/engine/m08-001")
    args = parser.parse_args()
    print(json.dumps(freeze(args.output) if args.action == "freeze" else verify(args.output), indent=2))


if __name__ == "__main__":
    main()
