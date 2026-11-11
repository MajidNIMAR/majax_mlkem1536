"""Replay deduplicated M08 corpus-derived requests against Rust and frozen Python.

Fresh-randomness API operations are counted, not represented as deterministic
oracle requests. No application keys or externally supplied secrets are used.
"""
import argparse
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True

from run_m08_fuzz import PROFILE, TARGETS, inventory, read, require, save, sha


def requests_from_corpus(campaign):
    fixtures = (campaign / "source/fuzz/fixtures/cases.bin").read_bytes()
    require(len(fixtures) == 164864, "wrong synthetic fixture corpus")
    records = [fixtures[i * 10304:(i + 1) * 10304] for i in range(16)]
    requests, counts, fresh = {}, {}, 0

    def add(kind, key, raw):
        identity = (kind, key, raw)
        # Keep compact bytes until streaming a single request. Materializing a
        # list of Python ints for every retained key would multiply the memory.
        requests[identity] = None

    corpus_hashes = {}
    for name in TARGETS:
        folder = campaign / "harvested-corpus" / name
        corpus_hashes[name] = inventory(folder)
        counts[name] = len(corpus_hashes[name])
        for member in sorted(corpus_hashes[name]):
            data = (folder / member).read_bytes()
            if name == "import_public":
                add("public", 0, data)
            elif name == "import_private":
                add("private", 0, data)
            elif name == "decapsulate" and data:
                add("ciphertext", data[0] % 16, data[1:])
            elif name == "api_sequence" and data:
                key = data[0] % 16
                record = records[key]
                for i in range(1, min(len(data), 65), 4):
                    step = data[i:i + 4]
                    if len(step) != 4:
                        break
                    op = step[0] % 4
                    if op == 3:
                        fresh += 1
                        continue
                    kind, raw = [("public", record[:2528]), ("private", record[2528:7616]),
                                 ("ciphertext", record[7616:10272])][op]
                    altered = bytearray(raw)
                    altered[int.from_bytes(step[1:3], "little") % len(raw)] ^= step[3]
                    add(kind, key, bytes(altered))
    return requests, counts, fresh, records, corpus_hashes


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def request_value(identity):
    kind, key, raw = identity
    return {"kind": kind, "key": key, "raw": list(raw)}


def replay(campaign, binary):
    require(not (campaign / "oracle-replay.json").exists()
            and not (campaign / "oracle-transcript.jsonl.gz").exists(), "never overwrite a replay attempt")
    oracle = campaign / "source/oracle/kem_r1_reference.py"
    config = read(campaign / "config.json")
    require(sha(oracle) == config["oracle_sha256"], "independent oracle changed")
    spec = importlib.util.spec_from_file_location("m08_frozen_oracle", oracle)
    ref = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ref)
    require(ref.np.__version__ == "2.3.5", "pinned NumPy 2.3.5 required")
    require(sha(Path(__file__)) == config["controller_sha256"]["replay_m08_fuzz_corpus.py"],
            "replay controller differs from frozen launch closure")
    requests, counts, fresh, records, corpus_hashes = requests_from_corpus(campaign)
    require(requests, "at least one deterministic harvested request is required")
    built = read(campaign / "replay-build.json")
    binary_file = (Path(subprocess.check_output(["wsl", "-d", "Ubuntu-22.04", "--", "wslpath", "-w", binary],
                                               text=True).strip()) if os.name == "nt" else Path(binary))
    require(sha(binary_file) == built["binary_sha256"], "replay executable changed")
    command = (["wsl", "-d", "Ubuntu-22.04", "--", binary] if os.name == "nt" else [binary])
    digest, matched, accepted, private_probes = hashlib.sha256(), 0, 0, 0
    transcript = campaign / "oracle-transcript.jsonl.gz"
    stderr_path = campaign / "oracle-replay-runtime.stderr"
    with transcript.open("xb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed, \
         stderr_path.open("xb") as errors, \
         subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors) as process:
        try:
            for identity in requests:
                kind, key, value = identity
                request = request_value(identity)
                process.stdin.write((json.dumps(request, separators=(",", ":")) + "\n").encode())
                process.stdin.flush()
                line = process.stdout.readline()
                require(line, "replay executable ended before returning every result")
                actual = json.loads(line)
                expected = {"accepted": False}
                reencryption = None
                if kind in ("public", "private"):
                    try:
                        (ref.public if kind == "public" else ref.private)(value)
                        expected = {"accepted": True}
                        if kind == "private":
                            probe, _ = ref.decapsulate(value, records[0][7616:10272])
                            expected["probe_shared"] = list(probe)
                            private_probes += 1
                    except ValueError:
                        pass
                elif len(value) == 2656:
                    shared, reencryption_accepted = ref.decapsulate(records[key][2528:7616], value)
                    accepted += int(reencryption_accepted)
                    reencryption = bool(reencryption_accepted)
                    expected = {"accepted": True, "shared": list(shared)}
                require(actual == expected, f"M08 Python/Rust mismatch in {kind}, synthetic fixture {key}")
                entry = {"request": request, "Rust": actual, "Python": expected,
                         "oracle_reencryption_accepted": reencryption}
                compressed.write(canonical(entry) + b"\n")
                digest.update(canonical([request, actual]))
                matched += 1
            process.stdin.close()
            require(process.wait(timeout=60) == 0, "replay binary failed")
            require(process.stdout.read() == b"", "unrequested additional replay output")
        except BaseException:
            process.kill()
            process.wait()
            raise
    require(corpus_hashes == {name: inventory(campaign / "harvested-corpus" / name) for name in TARGETS},
            "harvested corpus changed during replay")
    result = {"profile": PROFILE, "corpus_files": counts, "corpus_sha256": corpus_hashes,
              "distinct_deterministic_requests": matched, "all_Rust_Python_outputs_equal": True,
              "oracle_reencryption_acceptances": accepted,
              "accepted_private_import_requests_with_independent_decapsulation_probe": private_probes,
              "fresh_operations_encoded_in_corpus_not_recreated_by_oracle": fresh,
              "fuzzer_execution_count_is_not_unique_inputs": True,
              "cumulative_sha256": digest.hexdigest(), "numpy": ref.np.__version__,
              "oracle_sha256": sha(oracle), "transcript_sha256": sha(transcript),
              "replay_controller_sha256": sha(Path(__file__)), "replay_binary_sha256": built["binary_sha256"],
              "replay_command": command, "Rust_platform": "Linux", "Python_platform": os.name}
    save(campaign / "oracle-replay.json", result)
    return result


def verify(campaign):
    saved = read(campaign / "oracle-replay.json")
    requests, counts, fresh, _, hashes = requests_from_corpus(campaign)
    config, built = read(campaign / "config.json"), read(campaign / "replay-build.json")
    transcript = campaign / "oracle-transcript.jsonl.gz"
    require(saved["profile"] == PROFILE and saved["corpus_files"] == counts and saved["corpus_sha256"] == hashes
            and saved["fresh_operations_encoded_in_corpus_not_recreated_by_oracle"] == fresh,
            "independent replay corpus inventory differs")
    require(saved["all_Rust_Python_outputs_equal"] is True and saved["numpy"] == "2.3.5"
            and saved["oracle_sha256"] == sha(campaign / "source/oracle/kem_r1_reference.py") == config["oracle_sha256"]
            and saved["replay_binary_sha256"] == built["binary_sha256"]
            and saved["replay_controller_sha256"] == config["controller_sha256"]["replay_m08_fuzz_corpus.py"]
            and saved["transcript_sha256"] == sha(transcript), "independent replay source/binary/transcript binding differs")
    digest, matched, private_probes, reencryption = hashlib.sha256(), 0, 0, 0
    expected = iter(requests)
    with gzip.open(transcript, "rt", encoding="utf-8") as stream:
        for line in stream:
            entry = json.loads(line)
            identity = next(expected, None)
            request = request_value(identity) if identity is not None else None
            require(request is not None and entry["request"] == request and entry["Rust"] == entry["Python"],
                    "oracle transcript request inventory or equality differs")
            result = entry["Rust"]
            require(entry["oracle_reencryption_accepted"] is None
                    if request["kind"] != "ciphertext" or len(request["raw"]) != 2656
                    else type(entry["oracle_reencryption_accepted"]) is bool,
                    "invalid oracle reencryption counter field")
            reencryption += int(entry["oracle_reencryption_accepted"] is True)
            private_probes += int(request["kind"] == "private" and "probe_shared" in result)
            digest.update(canonical([request, result]))
            matched += 1
    require(next(expected, None) is None and matched == saved["distinct_deterministic_requests"]
            and digest.hexdigest() == saved["cumulative_sha256"]
            and private_probes == saved["accepted_private_import_requests_with_independent_decapsulation_probe"]
            and reencryption == saved["oracle_reencryption_acceptances"],
            "incomplete or changed oracle transcript")
    return {"independent_replay_requests_verified": matched, "new_oracle_execution_by_verifier": False,
            "accepted_private_key_probes": private_probes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("run", "verify"))
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--linux-binary")
    args = parser.parse_args()
    require(args.action != "run" or args.linux_binary, "replay executable required")
    result = replay(args.campaign.resolve(), args.linux_binary) if args.action == "run" else verify(args.campaign.resolve())
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
