"""Consolidate frozen attack estimates under explicit, separate contracts.

No estimator, Sage, network access or attack is executed. Costs remain
conditional upper estimates of specified attacks, never security lower bounds.
The output directory must be new, inside artifacts/generated.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import platform

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = {
    "baseline-1024": {"n": 256, "k": 4, "q": 3329, "eta": 2},
    "q7681-eta3": {"n": 256, "k": 6, "q": 7681, "eta": 3},
}
ESTIMATOR = "f31b86fe490ab11abb4a69efa13007583791e10a"
RING_ESTIMATOR = "6019056011d10d7e9c30a0d5da2d2f729fbc2eec"
RING_CODE = "a92f335665eef69927d2d8f49832bd595a6dac32"
CODED_CODE = "e2104ca50a293ed09b8fcec703cd2b143d21bee8"
CLASSICAL = "MATZOV-classical"
QUANTUM = "BCSS23-quantum-asymptotic"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked_snapshot(root, run, filename, seen):
    """Check frozen bytes, without requiring obsolete current source versions."""
    directory = root / "results/j2" / run
    provenance_path = directory / "provenance.json"
    provenance = read(provenance_path)
    path = directory / filename
    expected = provenance["output_sha256"][filename]
    if sha(path) != expected:
        raise ValueError(f"frozen input checksum mismatch: {run}/{filename}")
    seen[path.relative_to(root).as_posix()] = expected
    seen[provenance_path.relative_to(root).as_posix()] = sha(provenance_path)
    return read(path)


def checked_manifest(root, run, filename, seen):
    provenance = read(root / "results/j2" / run / "provenance.json")
    path = root / filename
    expected = provenance["input_sha256"][filename]
    if sha(path) != expected:
        raise ValueError(f"estimator manifest changed: {filename}")
    seen[filename] = expected
    return read(path)


def signature(job):
    """Only pair the same algorithm, access, resources and success convention."""
    return tuple(job[k] for k in ("tool", "cost_model", "algorithm", "sample_budget",
                                 "targets", "oracle", "shape_model", "memory_cap"))


def success_contract(algorithm):
    if algorithm == "dual_hybrid":
        return {
            "id": "MATZOV_Nf_mu_half",
            "meaning": "MATZOV Nf internal mu=0.5; not a certified 0.99 recovery probability",
            "global_success_certified": False,
        }
    if algorithm == "dual":
        return {
            "id": "dual_default_success_0.99",
            "meaning": "solver target 0.99 under estimator distribution and sampling heuristics",
            "global_success_certified": False,
        }
    if algorithm in ("bdd", "bdd_hybrid", "bdd_mitm_hybrid") or algorithm.startswith("rot_"):
        return {
            "id": "primal_BDD_guess_amplification_0.99",
            "meaning": "hybrid guessing amplification 0.99 where applicable; geometric success is heuristic",
            "global_success_certified": False,
        }
    if algorithm == "usvp":
        return {
            "id": "uSVP_GSA_geometric_condition",
            "meaning": "GSA success predicate; no explicit end-to-end success target in preserved job",
            "global_success_certified": False,
        }
    if algorithm == "bkw":
        return {
            "id": "coded_BKW_internal_target_0.99",
            "meaning": "internal distinguish target 0.99, with sample amplification and changed noise",
            "global_success_certified": False,
        }
    if algorithm == "arora-gb":
        return {
            "id": "Arora_GB_degree_regularity",
            "meaning": "degree-of-regularity heuristic; no common recovery-success certificate",
            "global_success_certified": False,
        }
    raise ValueError(f"unknown algorithm: {algorithm}")


def cost_row(row):
    if row["status"] != "ok":
        return {"status": row["status"], "log2_operations": None}
    value = row["log2_cost"]["rop"]
    if not isinstance(value, (float, int)) or not math.isfinite(value):
        raise ValueError("finite operation cost required")
    cost = row["cost"]
    return {
        "status": row["status"],
        "log2_operations": value,
        "log2_reported_mem": row["log2_cost"].get("mem"),
        "log2_reported_N": row["log2_cost"].get("N"),
        "reported_mem_is_bytes": False,
        "reported_fields": {k: cost[k] for k in ("beta", "beta_", "eta", "d", "m", "zeta", "t", "p")
                            if k in cost},
        "guess_probability_not_global_success": cost.get("prob"),
        "repetitions": cost.get("repetitions"),
    }


def pair_rows(rows):
    grouped = {}
    selected_count = 0
    for index, row in enumerate(rows):
        job = row["job"]
        scenario = job["scenario"]
        if scenario not in SCENARIOS:
            continue
        selected_count += 1
        if job["parameters"] != SCENARIOS[scenario]:
            raise ValueError("scenario parameters do not match the concrete profiles")
        expected_samples = 256 * (job["parameters"]["k"] + (job["sample_budget"] == "extended"))
        if (job["samples"] != expected_samples or job["targets"] != 1 or job["oracle"] != "none"
                or job["shape_model"] != "GSA"
                or job["memory_cap"] != "none; exponential memory allowed"):
            raise ValueError("target/oracle/sample/memory contract mismatch")
        key = signature(job)
        group = grouped.setdefault(key, {})
        if scenario in group:
            raise ValueError("duplicate attack row; do not choose the cheaper duplicate")
        group[scenario] = index, row
    pairs = []
    for key, group in sorted(grouped.items()):
        if set(group) != set(SCENARIOS):
            raise ValueError("unpaired attack contract; no cross-model subtraction allowed")
        tool, model, algorithm, budget, *_ = key
        baseline_index, baseline = group["baseline-1024"]
        r1_index, r1 = group["q7681-eta3"]
        left, right = cost_row(baseline), cost_row(r1)
        finite = all(item["log2_operations"] is not None for item in (left, right))
        pairs.append({
            "tool": tool,
            "estimator_commit": ESTIMATOR if tool == "community" else RING_ESTIMATOR,
            "ring_code_commit": RING_CODE if tool == "ring-2026" else None,
            "cost_model": model,
            "algorithm": algorithm,
            "sample_budget": budget,
            "sample_counts": [baseline["job"]["samples"], r1["job"]["samples"]],
            "success_contract": success_contract(algorithm),
            "targets": 1,
            "oracle": "none",
            "memory_cap_bytes": None,
            "unit": "asymptotic reduction sensitivity plus retained estimator work" if model == QUANTUM
                    else "estimator modeled word operations",
            "interpretation": "exploratory dense-CBD use of sparse-secret rotation code" if tool == "ring-2026"
                              else "conditional unstructured-LWE model",
            "ciphertext_samples_validated": False,
            "source_indices_in_modern_attacks": [baseline_index, r1_index],
            "baseline_1024": left,
            "r1_1536": right,
            "conditional_log2_cost_difference": right["log2_operations"] - left["log2_operations"]
                                                if finite else None,
            "security_gain_bits": None,
        })
    return selected_count, pairs


def list_storage(point, log2_list_size, caps=(40, 60, 80)):
    """Explicit materialized-list representation; not universal attack memory."""
    dimension, q = point["lattice_dimension"], point["inputs"]["q"]
    bits = (q - 1).bit_length()
    bytes_per_vector = (dimension * bits + 7) // 8
    log_bytes = log2_list_size + math.log2(bytes_per_vector)
    return {
        "representation": "dense_mod_q_packed",
        "coordinate_bits": bits,
        "bytes_per_vector": bytes_per_vector,
        "log2_list_bytes": log_bytes,
        "includes_auxiliary_memory": False,
        "universal_memory_lower_bound": False,
        "fixed_representation_cap_sensitivity": [
            {"log2_cap_bytes": cap,
             "log2_max_vectors": math.log2((1 << cap) // bytes_per_vector),
             "fits": log_bytes <= cap,
             "log2_excess_bytes": log_bytes - cap} for cap in caps],
        "bounded_memory_attack_cost": None,
    }


def coded_rows(minima, diagnostics):
    by_index = {p["parent_index"]: p for p in diagnostics}
    if len(by_index) != 4:
        raise ValueError("four distinct H09 parent diagnostics required")
    output = []
    for point in minima:
        inputs = point["inputs"]
        diagnostic = by_index[point["index"]]
        if diagnostic["inputs"] != inputs or not 1 <= inputs["samples"] <= inputs["n"]:
            raise ValueError("coded-dual point/diagnostic/sample mismatch")
        if not 0.6 - 1e-12 <= point["zero_guess_success"] <= 0.6 + 1e-12:
            raise ValueError("zero-guess target drift")
        if point["log2_epsilon"] > math.log2(0.05):
            raise ValueError("wrong-candidate normal budget drift")
        storage = list_storage(point, point["log2_list_size"])
        frozen_storage = diagnostic["storage_models"][0]
        if (storage["bytes_per_vector"] != frozen_storage["bytes_per_vector"]
                or abs(storage["log2_list_bytes"] - frozen_storage["log2_list_bytes"]) > 1e-10):
            raise ValueError("independent materialized storage calculation differs from H09")
        output.append({
            "dimension": inputs["n"], "degree": 256, "rank": inputs["n"] // 256,
            "q": inputs["q"], "eta": inputs["eta"],
            "mode": "author_MLWE_zero_count_heuristic" if inputs["mlwe"] else "LWE",
            "index": point["index"], "inputs": inputs,
            "algorithm_source_commit": CODED_CODE,
            "decoder": "ideal_GV_radius_ratio_1",
            "success_contract": {"zero_subset_target": 0.6, "normal_false_budget": 0.05,
                                 "global_success_certified": False,
                                 "probability_0_55_not_asserted": True},
            "cost_model": "authors embedded MATZOV list_decoding-classical, distinct from run-002",
            "log2_operations": point["log2_rop"], "beta0": point["beta0"], "beta1": point["beta1"],
            "reduction_table_extrapolated": point["reduction_table_extrapolated"],
            "search_global_optimum": False,
            "search_locally_stable": True,
            "log2_list_size": point["log2_list_size"],
            "storage": storage,
            "normal_variance_relative_excess_at_budget": diagnostic["normal_budget_variance_limit"]["relative_excess"],
            "moment_only_clipped_false_union_bound": diagnostic["moment_only_diagnostic"]["clipped_union_bound"],
            "tail_law_validated": False,
            "score_corrected_attack_cost": None,
            "security_level_bits": None,
        })
    return output


def calculate(root=ROOT):
    seen = {}
    modern = checked_snapshot(root, "run-002", "modern-attacks.json", seen)
    coded = checked_snapshot(root, "run-009", "study.json", seen)
    diagnostic = checked_snapshot(root, "run-016", "study.json", seen)
    # Bind the inherited dual model/calibrations as well as its refined minima.
    checked_snapshot(root, "run-008", "study.json", seen)
    calibration = checked_snapshot(root, "run-008", "calibration.json", seen)
    if len(calibration) != 6 or not all(case["passed"] for case in calibration):
        raise ValueError("six published calibrations must remain successful")
    modern_manifest = checked_manifest(root, "run-002", "research/modern-tools-manifest.json", seen)
    commits = {entry["id"]: entry["commit"] for entry in modern_manifest["archives"]}
    if commits != {"lattice-estimator": ESTIMATOR, "paper-estimator": RING_ESTIMATOR,
                   "mlwe-hybrids": RING_CODE}:
        raise ValueError("estimator versions differ; no silent comparison across versions")
    coded_manifest = checked_manifest(root, "run-008", "references/coded-dual-evaluation/manifest.json", seen)
    if coded_manifest["commit"] != CODED_CODE:
        raise ValueError("coded-dual version differs")
    selected, pairs = pair_rows(modern["results"])
    if selected != 60 or len(pairs) != 30:
        raise ValueError("expected 60 preserved estimates, giving 30 strict pairs")
    coded_points = coded_rows(coded["minima"], diagnostic["points"])
    if len(coded_points) != 4:
        raise ValueError("four coded-dual comparison points required")
    return {
        "schema": 1,
        "scope": "single-target algorithm-model comparison, not a global KEM security rating",
        "source_attack_cutoff": modern["cutoff_date"],
        "new_estimator_runs": 0,
        "source_hashes": seen,
        "profiles": SCENARIOS,
        "conventions": {
            "single_target": True, "leakage_oracle": "none",
            "all_families_common_success_probability": None,
            "all_families_common_physical_cost_unit": None,
            "finite_memory_budgets_are_sensitivities_only": [40, 60, 80],
            "global_security_lower_bound": None,
            "global_security_bits": None,
            "new_attack_from_small_moment_studies": False,
        },
        "strict_pairs": pairs,
        "coded_dual_points": coded_points,
        "generic_message_search": {
            "profiles": ["ML-KEM-1024", "KEM1536-DEV-Q7681-R1"],
            "message_bits": 256,
            "classical_search_exponent": 256,
            "ideal_coherent_quantum_query_exponent": 128,
            "candidate_check": "deterministic encapsulation matches the public challenge ciphertext",
            "scope": "generic attack ceiling in the ideal search model, not a security guarantee or physical gate count",
            "multi_target_adjustment_performed": False,
        },
        "decision": {
            "continue_R1_engineering": True,
            "parameter_change_justified_by_this_comparison": False,
            "claim_global_superiority_over_ML_KEM_1024": False,
            "claim_all_recent_attacks_integrated": False,
            "require_higher_order_moment_campaign": False,
        },
    }


def write_new(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.write("\n")


def verify_output(directory, root=ROOT):
    provenance = read(directory / "provenance.json")
    if sha(directory / "comparison.json") != provenance["comparison_sha256"]:
        raise ValueError("comparison output changed")
    if read(directory / "comparison.json") != calculate(root):
        raise ValueError("consolidated comparison differs from frozen inputs")
    source = root / "research/compare_attacks_common.py"
    if hashlib.sha256(source.read_bytes().replace(b"\r\n", b"\n")).hexdigest() != provenance["consolidator_sha256_normalized_LF"]:
        raise ValueError("consolidator version changed")
    return {"strict_pairs_verified": 30, "coded_dual_points_verified": 4,
            "new_estimator_runs": 0, "global_security_rating": None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    operation = parser.add_mutually_exclusive_group(required=True)
    operation.add_argument("--output", type=Path)
    operation.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.verify:
        print(json.dumps(verify_output(args.verify.resolve()), indent=2))
        return
    destination = args.output.resolve()
    allowed = ROOT / "artifacts/generated"
    if not destination.is_relative_to(allowed.resolve()) or destination == allowed.resolve():
        raise ValueError("new output must be a child of artifacts/generated")
    result = calculate()
    destination.mkdir(parents=True, exist_ok=False)
    write_new(destination / "comparison.json", result)
    write_new(destination / "provenance.json", {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(), "platform": platform.platform(),
        "consolidator_sha256_normalized_LF": hashlib.sha256(Path(__file__).read_bytes().replace(b"\r\n", b"\n")).hexdigest(),
        "comparison_sha256": sha(destination / "comparison.json"),
        "source_hashes": result["source_hashes"],
        "no_external_estimator_or_WSL_process_launched": True,
    })
    print(json.dumps(verify_output(destination), indent=2))


if __name__ == "__main__":
    main()
