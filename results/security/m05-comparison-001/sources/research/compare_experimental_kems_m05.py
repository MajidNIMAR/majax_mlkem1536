"""M05: explicit LWE proxy comparisons for experimental KEM parameter sets.

The actual compressed observations are specified separately from estimator
inputs. Rounded error laws below are sensitivity models, never claims of
independence for the actual scheme. No upstream KEM code is executed.
"""

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
import contextlib
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import io
import json
import math
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import traceback
from urllib.request import urlopen
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ESTIMATOR_COMMIT = "f31b86fe490ab11abb4a69efa13007583791e10a"
AIGIS_COMMIT = "b9ea5ce134966b8f90d637bab97178a92ae130f3"
KYBER_COMMIT = "ca375e3e3391360a863efd4122b14e396c994dde"
KINDI_URL = "https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/round-1/submissions/KINDI.zip"
KINDI_SHA = "ed51557337dee49deeda4d97c057ef65e98074a49af683eb621660f271b6963c"
SOURCES = ROOT / "artifacts/generated/m05-comparison-sources"
CLASSICAL = "MATZOV-classical"
QUANTUM = "BCSS23-quantum-asymptotic"
ALGORITHMS = ("usvp", "bdd", "dual_hybrid")
CODE_FILES = {
    "aigis": {
        "params.h": "2cbd7593cf0af10e93943f6d7ab9365cce4f9b80482dc4d8e49f9b392d8f5ad9",
        "owcpa.c": "ed43064819ca636126adc7b0b5b5d0380402622218e8735a6aec20ee9845f552",
        "kem.c": "6a95a7726cc0e21226c7ea01c545791577edee20d5ba3e762d65534a85584a47",
        "poly.c": "87c714a5eb6d12633c1cdbe5dd82749a240a1c838ad9a323a01adb4311ee6589",
        "polyvec.c": "54304d8ee8b9b49e006e641fcef8fbaf3dba603d29bee641fa40d861f6388b3e",
        "cbd.c": "aef3e17a7c6ca3c15c969b841cbff2ea3f817945796f0c66e3e1bb25bd20b897",
    },
    "kyber2017": {
        "params.h": "d262761dfc2446c2fb346f7eec534c7f70aab65e29fc41e72bbba327663f1591",
        "indcpa.c": "964ddfd4fb83e31c207cb03a6e46365b640f8930037eca2b9ecc4a24285fa682",
        "poly.c": "17e739bfb0fe15ee3a561ef3adf7bb8b4fe282bb414d348ad9e9d4de261dcfd3",
        "polyvec.c": "6ff296e3959f4e29b95474b7a12109559e5776060e46fc4d59bbe8ac184e5d12",
        "cbd.c": "a30ef8171d4a65082d32965a8373dae37ec144b5259cdd257cd6d16ae465eb17",
    },
    "kindi": {
        "params.h": "64b62c5de4d35a8d8d7c6c00fa66810408e1ecc1a3131b280c7c2a4ca23e7f50",
        "core.c": "fc83dd167d5f63d979a1f85555b2ababf341175f6f6685d2b4e4599b95663252",
        "poly.c": "deda3b15270971d882efa784253eeca2d1641742705d2d0c1905e2cde6115308",
        "poly_encode.c": "5becfb548ae6f75460a28985f17776195159ba4401e8b2963fcb7ded61e59acf",
        "gen_randomness.c": "cec2a52ebfe5e6db0822d1ca957660d191445390bc59b31792afa58630608334",
        "kem.c": "6cee5950db1e0adf4ad57a9613046786d5a22916c605f0c6b58889763c3f71f1",
    },
}


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_new(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def rational(value):
    value = Fraction(value)
    return {"numerator": value.numerator, "denominator": value.denominator}


def from_rational(value):
    return Fraction(value["numerator"], value["denominator"])


def cbd_law(eta):
    return {x: Fraction(math.comb(2 * eta, eta + x), 1 << (2 * eta))
            for x in range(-eta, eta + 1)}


def distribution_law(description):
    if description["kind"] == "CBD":
        return cbd_law(description["eta"])
    if description["kind"] == "Uniform":
        a, b = description["bounds"]
        return {x: Fraction(1, b - a + 1) for x in range(a, b + 1)}
    raise ValueError("finite source distribution required")


def law_moments(law):
    if sum(law.values()) != 1:
        raise ValueError("probability mass is not one")
    mean = sum(x * chance for x, chance in law.items())
    variance = sum((x - mean) ** 2 * chance for x, chance in law.items())
    return {"mean": rational(mean), "variance": rational(variance), "support": [min(law), max(law)]}


def centered(x, q):
    return (x + q // 2) % q - q // 2


def quantize(x, q, bits, kind):
    if kind == "nearest":
        encoded = ((x << bits) + q // 2) // q % (1 << bits)
        reconstructed = (q * encoded + (1 << (bits - 1))) >> bits
    elif kind == "truncate":
        if q != 1 << (q.bit_length() - 1):
            raise ValueError("the reviewed truncation requires a power-of-two modulus")
        shift = q.bit_length() - 1 - bits
        encoded, reconstructed = x >> shift, (x >> shift) << shift
    else:
        raise ValueError("unknown public-key quantizer")
    return encoded, reconstructed


def quantizer_diagnostic(profile):
    q, bits, kind = profile["q"], profile["pk_bits"], profile["pk_quantizer"]
    counts, cells = Counter(), Counter()
    for x in range(q):
        encoded, reconstructed = quantize(x, q, bits, kind)
        counts[centered(reconstructed - x, q)] += 1
        cells[encoded] += 1
    marginal = {value: Fraction(count, q) for value, count in counts.items()}
    error = distribution_law(profile["error"])
    combined = Counter()
    for e, pe in error.items():
        for delta, pd in marginal.items():
            combined[e + delta] += pe * pd
    conditional = []
    for signal in (0, 1, q // 2, q - 1):
        law = Counter()
        for e, chance in error.items():
            value = (signal + e) % q
            _, reconstructed = quantize(value, q, bits, kind)
            law[e + centered(reconstructed - value, q)] += chance
        conditional.append({"fixed_signal_residue": signal, "moments": law_moments(law),
                            "pmf": {str(x): rational(p) for x, p in sorted(law.items())}})
    return {
        "coefficient_values_enumerated": q,
        "quantizer": kind, "public_key_bits": bits,
        "preimage_size_histogram": {str(size): count for size, count in sorted(Counter(cells.values()).items())},
        "rounding_error_under_uniform_input": law_moments(marginal),
        "rounding_error_pmf_under_uniform_input": {str(x): rational(p) for x, p in sorted(marginal.items())},
        "independent_sum_error_moments": law_moments(combined),
        "independent_sum_error_pmf": {str(x): rational(p) for x, p in sorted(combined.items())},
        "actual_error_laws_at_fixed_signals": conditional,
        "actual_conditional_laws_differ": len({json.dumps(row["pmf"], sort_keys=True) for row in conditional}) > 1,
        "actual_scheme_rounding_independence_established": False,
        "gaussian_moment_substitution_is_exact_distribution": False,
    }


def profiles():
    cbd = lambda eta: {"kind": "CBD", "eta": eta}
    rows = [
        dict(id="R1", degree=256, rank=6, q=7681, secret=cbd(3), error=cbd(3),
             pk_bits=13, u_bits=13, v_bits=5, pk_quantizer=None,
             source="docs/SPECIFICATION_DEV_Q7681_R1.md", implementation=True),
        dict(id="ML-KEM-1024", degree=256, rank=4, q=3329, secret=cbd(2), error=cbd(2),
             pk_bits=12, u_bits=11, v_bits=5, pk_quantizer=None,
             source="NIST FIPS 203 final; NTT encoding is exactly invertible", implementation=True),
        dict(id="Aigis-Enc-mode4", degree=256, rank=4, q=7681, secret=cbd(3), error=cbd(8),
             pk_bits=11, u_bits=11, v_bits=5, pk_quantizer="nearest",
             source="PQMagic@" + AIGIS_COMMIT, implementation=True),
        dict(id="Kyber2017-k4", degree=256, rank=4, q=7681, secret=cbd(3), error=cbd(3),
             pk_bits=11, u_bits=11, v_bits=3, pk_quantizer="nearest",
             source="pq-crystals/kyber@" + KYBER_COMMIT, implementation=True),
        dict(id="KINDI-512-3-2-1", degree=512, rank=3, q=8192,
             secret={"kind": "Uniform", "bounds": [-2, 1]}, error={"kind": "Uniform", "bounds": [-2, 1]},
             pk_bits=12, u_bits=13, v_bits=13, pk_quantizer="truncate",
             source="NIST round-1 KINDI archive sha256:" + KINDI_SHA, implementation=True),
        dict(id="Kyber1536-paper-point", degree=256, rank=6, q=3329, secret=cbd(2), error=cbd(2),
             pk_bits=None, u_bits=None, v_bits=None, pk_quantizer=None,
             source="ePrint 2023/016, Table 4; rounding omitted in that simplified construction", implementation=False),
    ]
    for row in rows:
        row["flattened_secret_dimension"] = row["degree"] * row["rank"]
        row["actual_public_observation"] = (
            "C_pk(A*s+e mod q), with published seed for A" if row["pk_quantizer"]
            else "A*s+e mod q; matrix seed and exact/invertible representation")
        row["secret_moments"] = law_moments(distribution_law(row["secret"]))
        row["error_moments_before_serialization"] = law_moments(distribution_law(row["error"]))
        row["key_observation_is_unrounded"] = row["pk_quantizer"] is None
        row["composite_modulus_algebraic_attacks_not_modeled"] = row["id"].startswith("KINDI")
    return rows


def plan(pilot=False):
    rows = profiles()
    diagnostics = {p["id"]: quantizer_diagnostic(p) for p in rows if p["pk_quantizer"]}
    jobs = []
    for p in rows:
        if pilot and not p["implementation"]:
            continue
        for panel in ("before_serialization_LWE_proxy", "independent_rounding_Gaussian_moment_proxy"):
            if panel.startswith("independent") and (pilot or p["pk_quantizer"] is None):
                continue
            error = p["error"]
            if panel.startswith("independent"):
                moments = diagnostics[p["id"]]["independent_sum_error_moments"]
                error = {"kind": "Gaussian-moments", "mean": moments["mean"], "variance": moments["variance"]}
            for budget in (("key",) if pilot else ("key", "ideal_k_plus_1")):
                samples = p["degree"] * (p["rank"] + (budget == "ideal_k_plus_1"))
                for model in ((CLASSICAL,) if pilot else (CLASSICAL, QUANTUM)):
                    for algorithm in ALGORITHMS:
                        jobs.append({
                            "scenario": p["id"], "degree": p["degree"], "rank": p["rank"],
                            "n": p["flattened_secret_dimension"], "q": p["q"],
                            "secret": p["secret"], "error": error, "panel": panel,
                            "sample_budget": budget, "samples": samples,
                            "abstract_matrix_blocks": [p["rank"] + (budget == "ideal_k_plus_1"), p["rank"]],
                            "targets": 1, "leakage_oracle": "none", "memory_cap": None,
                            "exponential_memory_allowed": True, "shape_model": "GSA",
                            "cost_model": model, "algorithm": algorithm,
                            "estimator_commit": ESTIMATOR_COMMIT,
                            "actual_compressed_scheme_attack_cost": False,
                            "ciphertext_rows_claimed_independent_samples": False,
                        })
    # Exercise every family/profile promptly, instead of leaving the last
    # distribution untested until a large batch has finished.
    jobs.sort(key=lambda j: (j["panel"], j["sample_budget"], j["cost_model"], j["scenario"], j["algorithm"]))
    return {"schema": 1, "pilot": pilot, "profiles": rows, "rounding_diagnostics": diagnostics,
            "jobs": [dict(index=i, **job) for i, job in enumerate(jobs)],
            "comparison_scope": "Explicit unstructured-LWE heuristic proxies, not total KEM security",
            "global_security_rating": None}


def primary_sources(fetch=False):
    SOURCES.mkdir(parents=True, exist_ok=True)
    zip_path = SOURCES / "KINDI.zip"
    if not zip_path.exists() and fetch:
        with urlopen(KINDI_URL, timeout=90) as stream:
            zip_path.write_bytes(stream.read())
    if not zip_path.exists() or sha(zip_path) != KINDI_SHA:
        raise ValueError("fetch and verify the fixed KINDI archive before preparing the panel")
    receipts = [{"url": KINDI_URL, "sha256": KINDI_SHA, "bytes": zip_path.stat().st_size,
                 "external_code_executed": False, "tracked_full_source_copy": False}]
    with zipfile.ZipFile(zip_path) as bundle:
        for name, expected in CODE_FILES["kindi"].items():
            member = "KINDI/Reference_Implementation/kem/KINDI-512-3-2-1/" + name
            content = bundle.read(member)
            if hashlib.sha256(content).hexdigest() != expected:
                raise ValueError("KINDI primary source member changed")
            receipts.append({"url": KINDI_URL, "member": member, "sha256": expected,
                             "external_code_executed": False, "tracked_full_source_copy": False})
    for label, repository, commit, prefix in (
        ("aigis", "pqcrypto-cn/PQMagic", AIGIS_COMMIT, "kem/aigis-enc/std"),
        ("kyber2017", "pq-crystals/kyber", KYBER_COMMIT, "ref"),
    ):
        for name, expected in CODE_FILES[label].items():
            url = f"https://raw.githubusercontent.com/{repository}/{commit}/{prefix}/{name}"
            path = SOURCES / label / name
            if not path.exists() and fetch:
                path.parent.mkdir(exist_ok=True)
                with urlopen(url, timeout=60) as stream:
                    path.write_bytes(stream.read())
            if not path.exists() or sha(path) != expected:
                raise ValueError(f"primary code source mismatch: {label}/{name}")
            receipts.append({"url": url, "sha256": expected, "commit": commit,
                             "external_code_executed": False, "tracked_full_source_copy": False})
    for name in ("docs/SPECIFICATION_DEV_Q7681_R1.md", "references/NIST.FIPS.203.pdf",
                 "profiles/kem1536-p0.toml"):
        receipts.append({"project_file": name, "sha256": sha(ROOT / name)})
    receipts.append({"url": "https://eprint.iacr.org/2023/016.pdf",
                     "scope": "Table 4 parameter point consulted through the web PDF index; no byte-pinned PDF copy available (direct HTTP 403)",
                     "parameter_point": {"degree": 256, "rank": 6, "q": 3329, "eta": 2},
                     "local_independent_parameter_witness": "profiles/kem1536-p0.toml",
                     "article_implementation_executed": False})
    return receipts


def prepare(output, pilot, fetch=False):
    receipts = primary_sources(fetch)
    data = plan(pilot)
    output.mkdir(parents=True, exist_ok=False)
    (output / "jobs").mkdir()
    write_new(output / "plan.json", data)
    write_new(output / "primary-sources.json", receipts)
    for job in data["jobs"]:
        write_new(output / "jobs" / f"input-{job['index']:03d}.json", job)
    dependencies = ["compare_experimental_kems_m05.py", "modern_tools.py", "sieve_models.py",
                    "cost_serialization.py", "compare_attacks_common.py", "modern-tools-manifest.json",
                    "test_compare_experimental_kems_m05.py"]
    source_dir = output / "sources/research"
    source_dir.mkdir(parents=True)
    for name in dependencies:
        shutil.copyfile(ROOT / "research" / name, source_dir / name)
    write_new(output / "prepared.json", {"created_utc": now(), "jobs": len(data["jobs"]),
              "plan_sha256": sha(output / "plan.json"), "pilot": pilot,
              "source_sha256": {name: sha(source_dir / name) for name in dependencies}})
    return {"prepared_jobs": len(data["jobs"]), "pilot": pilot}


def worker(job):
    from sage.all import QQ, log, sqrt
    from sage.version import version as sage_version
    import modern_tools
    from cost_serialization import log2_record
    from compare_attacks_common import success_contract
    # Workers execute the archived sources. Cache paths stay rooted in the
    # project, while MANIFEST remains the archived, checked manifest.
    modern_tools.ROOT = ROOT
    cached = modern_tools.sources()
    sys.path.insert(0, str(cached["lattice-estimator"]))
    from estimator import LWE, ND
    from estimator.reduction import RC

    def distribution(description):
        if description["kind"] == "CBD":
            return ND.CenteredBinomial(description["eta"])
        if description["kind"] == "Uniform":
            return ND.Uniform(*description["bounds"])
        if description["kind"] == "Gaussian-moments":
            mu, var = description["mean"], description["variance"]
            return ND.DiscreteGaussian(sqrt(QQ(var["numerator"]) / var["denominator"]),
                                       QQ(mu["numerator"]) / mu["denominator"])
        raise ValueError("unsupported noise descriptor")

    if (job["degree"] * job["rank"] != job["n"] or job["estimator_commit"] != ESTIMATOR_COMMIT
            or job["targets"] != 1 or job["leakage_oracle"] != "none"):
        raise ValueError("invalid estimator instance contract")
    xs, xe = distribution(job["secret"]), distribution(job["error"])
    params = LWE.Parameters(n=job["n"], q=job["q"], Xs=xs, Xe=xe, m=job["samples"], tag=job["scenario"])
    if job["cost_model"] == CLASSICAL:
        model = RC.MATZOV
    elif job["cost_model"] == QUANTUM:
        from sieve_models import bcss23_model
        model = bcss23_model()
    else:
        raise ValueError("cost model is not fixed by this study")
    functions = {"usvp": LWE.primal_usvp, "bdd": LWE.primal_bdd, "dual_hybrid": LWE.dual_hybrid}
    kwargs = {"red_cost_model": model}
    if job["algorithm"] in ("usvp", "bdd"):
        kwargs["red_shape_model"] = "gsa"
    messages = io.StringIO()
    with contextlib.redirect_stdout(messages), contextlib.redirect_stderr(messages):
        cost = functions[job["algorithm"]](params, **kwargs)
    logs = {key: log2_record(cost[key], log) for key in
            ("rop", "red", "svp", "mem", "guess", "N", "prob", "repetitions") if key in cost}
    reduction_dimensions = {key: int(cost[key]) for key in ("beta", "beta_", "eta") if key in cost}
    return {
        "job": job, "status": "estimated_proxy" if isinstance(logs.get("rop"), (int, float))
                and math.isfinite(logs["rop"]) else "nonfinite_proxy_estimate",
        "cost": {str(k): str(v) for k, v in cost.items()},
        "log2_cost": logs, "success_contract": success_contract(job["algorithm"]),
        "input_distribution_repr": {"Xs": repr(xs), "Xe": repr(xe)},
        "input_distribution_means": {"Xs": str(xs.mean), "Xe": str(xe.mean)},
        "normalized_parameters_repr": repr(params.normalize()),
        "reported_memory_unit": "estimator-native units, not bytes; N is vector count",
        "cost_is_global_security_lower_bound": False,
        "quantum_physical_gate_count": None,
        "sage": sage_version, "python": platform.python_version(),
        "estimator_messages": messages.getvalue(),
        "executing_worker_sha256": sha(Path(__file__)),
        "reduction_dimensions": reduction_dimensions,
        "classical_fit_used_beyond_1024": job["cost_model"] == CLASSICAL and any(value > 1024 for value in reduction_dimensions.values()),
        "fit_flag_is_not_an_attack_cost_correction": True,
    }


def execute_job(output, job, timeout):
    path = output / "jobs" / f"result-{job['index']:03d}.json"
    if path.exists():
        result = read(path)
        if result["job"] != job:
            raise ValueError("existing result has another instance")
        return result
    command = [sys.executable, str(output / "sources/research/compare_experimental_kems_m05.py"), "--worker",
               str(output / "jobs" / f"input-{job['index']:03d}.json"), "--worker-output", str(path),
               "--project-root", str(ROOT)]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        if not path.exists():
            write_new(path, {"job": job, "status": "process_error", "exit_code": completed.returncode,
                             "stderr": completed.stderr[-4000:], "stdout": completed.stdout[-1000:]})
    except subprocess.TimeoutExpired:
        write_new(path, {"job": job, "status": "timeout", "timeout_seconds": timeout})
    return read(path)


def run(output, workers, timeout):
    from sage.version import version as sage_version
    data, prepared = read(output / "plan.json"), read(output / "prepared.json")
    if sha(output / "plan.json") != prepared["plan_sha256"]:
        raise ValueError("prepared plan changed")
    if data != plan(data["pilot"]):
        raise ValueError("runner differs from the prepared plan")
    for name, expected in prepared["source_sha256"].items():
        if sha(output / "sources/research" / name) != expected:
            raise ValueError("archived estimator worker source changed")
    started = time.perf_counter()
    results = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        pending = {executor.submit(execute_job, output, job, timeout): job for job in data["jobs"]}
        for future in as_completed(pending):
            result = future.result()
            results.append(result)
            print(f"{len(results)}/{len(pending)} {result['job']['scenario']} "
                  f"{result['job']['algorithm']} {result['status']} "
                  f"{result.get('log2_cost', {}).get('rop', '')}", flush=True)
    results.sort(key=lambda row: row["job"]["index"])
    write_new(output / "historical-crosscheck.json", historical_crosscheck(results))
    write_new(output / "comparison.json", {"schema": 1, "results": results,
              "statuses": dict(Counter(row["status"] for row in results)),
              "new_attack_algorithm_executed": False, "new_estimator_jobs": len(results),
              "global_security_rating": None})
    files = [path for path in output.rglob("*") if path.is_file()]
    write_new(output / "provenance.json", {
        "created_utc": now(), "sage": sage_version, "python": platform.python_version(),
        "platform": platform.platform(), "workers": workers, "timeout_seconds": timeout,
        "elapsed_wall_seconds": time.perf_counter() - started,
        "output_sha256": {path.relative_to(output).as_posix(): sha(path) for path in sorted(files)},
        "upstream_estimator_commit": ESTIMATOR_COMMIT,
        "no_global_security_level": True,
    })
    return verify(output)


def historical_crosscheck(results):
    """Replay the shared exact input points, without importing old conclusions."""
    directory = ROOT / "results/j2/run-002"
    provenance = read(directory / "provenance.json")
    expected = provenance["output_sha256"]["modern-attacks.json"]
    if sha(directory / "modern-attacks.json") != expected:
        raise ValueError("historical estimator reference changed")
    historical = read(directory / "modern-attacks.json")["results"]
    names = {"R1": "q7681-eta3", "ML-KEM-1024": "baseline-1024", "Kyber1536-paper-point": "p0-1536"}
    checks = []
    for row in results:
        job = row["job"]
        if job["scenario"] not in names or job["panel"] != "before_serialization_LWE_proxy":
            continue
        budget = "key" if job["sample_budget"] == "key" else "extended"
        matching = [old for old in historical if old["job"]["scenario"] == names[job["scenario"]]
                    and old["job"]["algorithm"] == job["algorithm"]
                    and old["job"]["cost_model"] == job["cost_model"]
                    and old["job"]["sample_budget"] == budget and old["job"]["tool"] == "community"]
        if len(matching) != 1:
            raise ValueError("historical point is not uniquely identified")
        old = matching[0]
        delta = (row["log2_cost"]["rop"] - old["log2_cost"]["rop"]
                 if row["status"] == "estimated_proxy" and old["status"] == "ok" else None)
        checks.append({"job_index": job["index"], "historical_scenario": names[job["scenario"]],
                       "delta_log2_rop": delta, "passed": delta is not None and abs(delta) < 1e-8})
    return {"snapshot": "run-002", "modern_attacks_sha256": expected, "checks": checks,
            "points": len(checks), "all_passed": all(row["passed"] for row in checks),
            "global_security_rating": None}


def verify(output):
    provenance = read(output / "provenance.json")
    for relative, expected in provenance["output_sha256"].items():
        path = (output / relative).resolve()
        if not path.is_relative_to(output.resolve()) or sha(path) != expected:
            raise ValueError(f"M05 comparison checksum mismatch: {relative}")
    data = read(output / "plan.json")
    result = read(output / "comparison.json")
    if data != plan(data["pilot"]):
        raise ValueError("M05 plan and quantizer diagnostics differ")
    if [row["job"] for row in result["results"]] != data["jobs"]:
        raise ValueError("M05 missing, duplicated or reordered result instance")
    for row in result["results"]:
        if row["status"] == "estimated_proxy":
            value = row["log2_cost"].get("rop")
            if not isinstance(value, (float, int)) or not math.isfinite(value):
                raise ValueError("finite estimate required; preserve nonfinite result as a limitation")
            if row["cost_is_global_security_lower_bound"] or row["success_contract"]["global_success_certified"]:
                raise ValueError("M05 scope overstated")
            if row["executing_worker_sha256"] != read(output / "prepared.json")["source_sha256"]["compare_experimental_kems_m05.py"]:
                raise ValueError("worker did not execute the archived source")
    counts = dict(Counter(row["status"] for row in result["results"]))
    if counts != result["statuses"] or result["global_security_rating"] is not None:
        raise ValueError("M05 status/global scope mismatch")
    historical = historical_crosscheck(result["results"])
    if (output / "historical-crosscheck.json").exists():
        if historical != read(output / "historical-crosscheck.json") or not historical["all_passed"]:
            raise ValueError("shared historical input points do not reproduce")
    return {"jobs_verified": len(result["results"]), "statuses": counts,
            "quantizer_coefficients_enumerated": sum(v["coefficient_values_enumerated"] for v in data["rounding_diagnostics"].values()),
            "global_security_rating": None}


def freeze(output, archive):
    verify(output)
    archive = archive.resolve()
    if archive != ROOT / "results/security/m05-comparison-001":
        raise ValueError("this comparison freeze uses its declared new snapshot identifier")
    if archive.exists():
        raise FileExistsError("never replace the frozen M05 comparison")
    archive.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(output, archive)
    return verify(archive)


def main():
    global ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--prepare", action="store_true")
    action.add_argument("--run", action="store_true")
    action.add_argument("--verify", action="store_true")
    action.add_argument("--worker", type=Path)
    action.add_argument("--freeze", action="store_true")
    parser.add_argument("--worker-output", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--pilot", action="store_true")
    parser.add_argument("--fetch-sources", action="store_true")
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=180)
    parser.add_argument("--archive", type=Path, default=ROOT / "results/security/m05-comparison-001")
    parser.add_argument("--project-root", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        if args.project_root is not None:
            ROOT = args.project_root.resolve()
        job = read(args.worker)
        started = time.perf_counter()
        try:
            result = worker(job)
        except Exception as error:
            result = {"job": job, "status": "error", "error_type": type(error).__name__,
                      "error": str(error), "traceback": traceback.format_exc()[-5000:]}
        result["elapsed_seconds"] = time.perf_counter() - started
        write_new(args.worker_output, result)
        return
    if args.output is None:
        raise ValueError("an explicit new comparison output is required")
    output = args.output.resolve()
    if not (output.is_relative_to(ROOT / "artifacts/generated") or output.is_relative_to(ROOT / "results/security")):
        raise ValueError("comparison outputs must remain inside NIST research directories")
    if args.prepare:
        result = prepare(output, args.pilot, args.fetch_sources)
    elif args.run:
        result = run(output, args.workers, args.timeout)
    elif args.freeze:
        result = freeze(output, args.archive)
    else:
        result = verify(output)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
