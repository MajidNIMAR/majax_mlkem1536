"""Execute concrete exact block decoders at q=3329/7681 and preserve data.

Uniform-torus test vectors are synthetic deterministic samples. The study
compares concrete distortion with the GV radius proxy; no attack cost update.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import platform
import sys
import time

from block_decoder import exhaustive_toy, make_code

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = 256


def write(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def targets(q, n, count, label):
    """Public test generator, with rejection of incomplete 16-bit intervals."""
    values, counter = [], 0
    limit = 65536 // q * q
    while len(values) < n * count:
        block = hashlib.shake_256(label + counter.to_bytes(8, "little")).digest(4096)
        counter += 1
        for offset in range(0, len(block), 2):
            word = int.from_bytes(block[offset:offset + 2], "little")
            if word < limit:
                values.append(word % q)
                if len(values) == n * count:
                    break
    return [values[i * n:(i + 1) * n] for i in range(count)]


def target_hash(values):
    return hashlib.sha256(b"".join(x.to_bytes(2, "little") for x in values)).hexdigest()


def statistics(squares, radius):
    norms = [math.sqrt(d) for d in squares]
    mean = math.fsum(norms) / len(norms)
    sd = math.sqrt(math.fsum((v - mean) ** 2 for v in norms) / len(norms))
    return dict(samples=len(squares), sum_squared_norms=sum(squares), sum_fourth_norms=sum(d * d for d in squares),
                mean_norm=mean, population_sd_norm=sd, maximum_observed_norm=max(norms),
                mean_over_GV_radius_proxy=mean / radius,
                observed_within_GV_radius_proxy=sum(d <= radius * radius for d in squares))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output == ROOT or not output.is_relative_to(ROOT) or output.exists():
        raise ValueError("new output directory below NIST required")
    from verify_coded_dual_refinement import verify as verify_parent
    verify_parent()
    from block_decoder_numpy import decode, warm_tables
    import numpy as np
    output.mkdir(parents=True)
    toys = []
    for q, n, k in ((5, 3, 1), (5, 4, 2), (7, 4, 2)):
        for family in ("repeated", "radix"):
            toys.append(exhaustive_toy(q, n, k, family))
    write(output / "toy-enumeration.json", toys)
    parent = json.loads((ROOT / "results/j2/run-009/study.json").read_text(encoding="utf-8"))
    records, oracles, timing = [], [], []
    with (output / "observations.jsonl").open("x", encoding="utf-8", newline="\n") as stream:
        for panel, reference in enumerate(parent["minima"]):
            p = reference["inputs"]
            q, n, k = p["q"], p["nfft"], p["kfft"]
            seed = f"nist-j2-block-decoder-v1:{q}:{n}:{k}".encode("ascii")
            points = targets(q, n, SAMPLES, seed)
            radius = math.exp((1 - k / n) * math.log(q) + math.lgamma(n / 2 + 1) / n - math.log(math.pi) / 2)
            for family in ("repeated", "radix"):
                code = make_code(q, n, k, family)
                decoder = code.decode_repeated if family == "repeated" else lambda v: decode(code, v)
                if family == "radix":
                    warm_tables(code)
                experiment = f"panel-{panel}-{family}"
                squares, scores, results = [], [], []
                started = time.perf_counter()
                for index, point in enumerate(points):
                    result = decoder(point)
                    restored = code.encode(result["labels"])
                    check = sum(min(abs(x-y), q-abs(x-y)) ** 2 for x, y in zip(point, restored))
                    if check != result["squared_norm"]:
                        raise ArithmeticError("decoder output/distance mismatch")
                    stream.write(json.dumps(dict(experiment=experiment, index=index, target_sha256=target_hash(point), **result)) + "\n")
                    squares.append(result["squared_norm"])
                    scores.append(result["candidate_scores"])
                    results.append(result)
                stream.flush()
                # Benchmarks include one public decode call at a time; input
                # generation, table construction, verification and I/O excluded.
                durations = []
                for series in range(7):
                    selection = points[series * 8:series * 8 + 8]
                    start = time.perf_counter_ns()
                    decoded = [decoder(v) for v in selection]
                    elapsed = time.perf_counter_ns() - start
                    if any(r["squared_norm"] != squares[series * 8 + i] or r["labels"] != results[series * 8 + i]["labels"]
                           for i, r in enumerate(decoded)):
                        raise ArithmeticError("benchmark decoding changed")
                    durations.append(elapsed)
                timing.append(dict(experiment=experiment, batch_size=8, batches_ns=durations,
                                   median_ns_per_decode=sorted(durations)[3] / 8,
                                   includes="Python call, validation, decoding; warm tables; no generation or I/O"))
                for j in range(8):
                    block_index = j * (k - 1) // 7
                    offset = sum(len(g) for g in code.generators[:block_index])
                    block = code.generators[block_index]
                    values = points[j][offset:offset + len(block)]
                    label = results[j]["labels"][block_index]
                    distance = sum(min(abs(x-a), q-abs(x-a)) ** 2 for x, a in zip(values, (label * g % q for g in block)))
                    oracles.append(dict(experiment=experiment, q=q, values=values, generator=list(block),
                                        label=label, squared_norm=distance))
                records.append(dict(experiment=experiment, parent_point_index=reference["index"],
                                    attack_dimension=p["n"], mlwe_heuristic=p["mlwe"], code=code.record(),
                                    seed_ascii=seed.decode("ascii"), input_model="synthetic uniform-torus samples via fixed SHAKE rejection stream",
                                    GV_radius_proxy=radius, observations=statistics(squares, radius),
                                    mean_candidate_scores=math.fsum(scores) / SAMPLES,
                                    decoder="exact_piecewise_quadratic_sweep" if family == "repeated" else "exact_full_symbol_enumeration_numpy",
                                    exhaustive_coordinate_terms_per_decode=q * n if family == "radix" else None))
                print(f"{experiment}: q={q}, n={n}, k={k}, mean/GV={records[-1]['observations']['mean_over_GV_radius_proxy']:.6f}, "
                      f"median_ms={timing[-1]['median_ns_per_decode']/1e6:.6f}, study_seconds={time.perf_counter()-started:.3f}", flush=True)
    write(output / "oracle-cases.json", oracles)
    cpu = platform.processor()
    if Path("/proc/cpuinfo").exists():
        cpu = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines() if line.startswith("model name")), cpu)
    write(output / "timings.json", dict(environment=dict(platform=platform.platform(), processor=cpu, machine=platform.machine(),
                                                          python=platform.python_version(), numpy=np.__version__,
                                                          timer_resolution_seconds=time.get_clock_info("perf_counter").resolution),
                                        measurements=timing, limits="local warm-cache Python prototype measurements; not estimator rop units or production performance"))
    study = dict(experiments=records, profile_selected=False, j2_closed=False, attack_costs_updated=False,
                 role="concrete quantization decoder experiments for the coded-dual attack model, not KEM Decaps",
                 limits=["direct-product codes differ from the ideal/random/polar code assumed in the attack model",
                         "only 256 fixed synthetic targets per experiment; no covering-radius or tail probability claim",
                         "exact nearest-codeword decoding does not imply good quantization quality",
                         "GV radius is the prior model's continuum proxy, not an achieved or certified covering radius",
                         "radix nearest-root generator choice is explicit, not an optimization or novelty claim",
                         "no covariance/score proof, constant-time implementation or KEM correctness bound",
                         "timing in nanoseconds cannot be substituted into an estimator's rop formula"])
    write(output / "study.json", study)
    inputs = ["research/block_decoder.py", "research/block_decoder_numpy.py", "research/run_block_decoder.py",
              "research/test_block_decoder.py", "research/verify_block_decoder_results.py",
              "research/verify_block_decoder_independent.py", "scripts/block-decoder.sh",
              "results/j2/run-009/study.json", "results/j2/run-009/provenance.json", "results/j2/run-009/numeric-provenance.json"]
    outputs = ("toy-enumeration.json", "observations.jsonl", "oracle-cases.json", "timings.json", "study.json")
    write(output / "provenance.json", dict(created_utc=datetime.now(timezone.utc).isoformat(), python=platform.python_version(),
                                            input_sha256={name: digest(ROOT / name) for name in inputs},
                                            output_sha256={name: digest(output / name) for name in outputs}))


if __name__ == "__main__":
    main()
