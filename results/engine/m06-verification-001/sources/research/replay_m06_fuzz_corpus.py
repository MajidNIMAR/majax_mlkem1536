"""Replay retained M06 synthetic inputs with a frozen independent Python oracle."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--campaign", type=Path, required=True)
    parser.add_argument("--linux-binary", required=True)
    args = parser.parse_args()
    campaign = args.campaign.resolve()
    oracle = campaign / "source/oracle/kem_r1_reference.py"
    spec = importlib.util.spec_from_file_location("m06_frozen_oracle", oracle)
    ref = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ref)
    if ref.np.__version__ != "2.3.5":
        raise ValueError("pinned NumPy 2.3.5 required")
    fixtures = (campaign / "source/fuzz/fixtures/cases.bin").read_bytes()
    if len(fixtures) != 164864:
        raise ValueError("wrong synthetic fixture corpus")
    records = [fixtures[i * 10304:(i + 1) * 10304] for i in range(16)]
    requests, counts, supplement_counts, fresh = {}, {}, {}, 0

    def add(kind, key, raw):
        requests[(kind, key, raw)] = dict(kind=kind, key=key, raw=list(raw))

    for name in ("import_public", "import_private", "decapsulate", "api_sequence"):
        counts[name] = 0
        supplement_counts[name] = 0
        paths = [(p, False) for p in sorted((campaign / name / "corpus").iterdir())]
        extra = campaign / "supplement-001" / name / "corpus"
        if extra.is_dir():
            paths += [(p, True) for p in sorted(extra.iterdir())]
        for path, supplemental in paths:
            data = path.read_bytes()
            if supplemental:
                supplement_counts[name] += 1
            else:
                counts[name] += 1
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
    command = (["wsl", "-d", "Ubuntu-22.04", "--", args.linux_binary]
               if os.name == "nt" else [args.linux_binary])
    digest, matched, accepted, private_probes = hashlib.sha256(), 0, 0, 0
    with subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        try:
            for identity, request in requests.items():
                kind, key, raw = identity
                process.stdin.write((json.dumps(request, separators=(",", ":")) + "\n").encode())
                process.stdin.flush()
                actual = json.loads(process.stdout.readline())
                expected = {"accepted": False}
                if kind in ("public", "private"):
                    try:
                        (ref.public if kind == "public" else ref.private)(raw)
                        expected = {"accepted": True}
                        if kind == "private":
                            probe, _ = ref.decapsulate(raw, records[0][7616:10272])
                            expected["probe_shared"] = list(probe)
                            private_probes += 1
                    except ValueError:
                        pass
                elif len(raw) == 2656:
                    shared, reencryption_accepted = ref.decapsulate(records[key][2528:7616], raw)
                    accepted += int(reencryption_accepted)
                    expected = dict(accepted=True, shared=list(shared))
                if actual != expected:
                    raise ValueError(f"M06 Python/Rust mismatch in {kind}, fixture {key}")
                digest.update(json.dumps([request, actual], sort_keys=True, separators=(",", ":")).encode())
                matched += 1
            process.stdin.close()
            if process.wait(timeout=60) != 0:
                raise ValueError("M06 replay binary failed")
        except BaseException:
            process.kill()
            process.wait()
            raise
    result = {"corpus_files": counts, "supplement_corpus_files": supplement_counts, "distinct_deterministic_requests": matched,
        "all_Rust_Python_outputs_equal": True, "oracle_reencryption_acceptances": accepted,
        "accepted_private_keys_with_independent_decapsulation_probe": private_probes,
        "fresh_operations_tested_by_fuzzer_not_recreated_by_this_oracle": fresh,
        "cumulative_sha256": digest.hexdigest(), "numpy": ref.np.__version__,
        "oracle_sha256": hashlib.sha256(oracle.read_bytes()).hexdigest(),
        "replay_controller_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "replay_command": command, "Rust_platform": "Linux", "Python_platform": os.name}
    with (campaign / "oracle-replay.json").open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
