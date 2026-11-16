"""Data-only interpretation and sealing of the pre-registered 40-job panel."""
import argparse
from collections import Counter
from datetime import datetime, timezone
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import urllib.request

from m10_parameters_model import bounded_memory_counterexample, finite_search_checks, fraction_record, memory_diagnostic, symmetric_panels, wire_sizes

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts/generated/m10-parameters-001"
RESULT = ROOT / "results/security/m10-parameters-001"


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def save(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write("\n")


def collect_inputs(output):
    inputs = output / "inputs"
    inputs.mkdir()
    for original, name in (("results/security/m05-comparison-001/comparison.json", "m05-comparison.json"),
                           ("results/security/m05-comparison-001/provenance.json", "m05-provenance.json"),
                           ("results/j2/run-004/correctness-certificate.json", "r1-correctness-certificate.json"),
                           ("results/j2/run-004/provenance.json", "run004-provenance.json"),
                           ("research/sage-bootstrap-manifest.json", "sage-bootstrap-manifest.json"),
                           ("research/sage-linux-explicit.txt", "sage-linux-explicit.txt"),
                           ("research/sage-linux-packages.json", "sage-linux-packages.json")):
        shutil.copyfile(ROOT / original, inputs / name)
    primary = []
    cache = ROOT / ".tools/primary-sources/m10-parameters-001"
    cache.mkdir(parents=True, exist_ok=False)
    for label, url, scope in (
        ("kaiburr", "https://www.cryptojedi.org/papers/kaiburr-20261103.pdf", "author-hosted paper; selected parameter/method sections read, not all proofs reproduced"),
        ("FIPS203", "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf", "official tables1/2/3 and their declared heuristic failure population"),
        ("dual-covariance", "https://eprint.iacr.org/2026/1048", "primary abstract and revision metadata, no numeric correction transferred"),
        ("provable-dual", "https://eprint.iacr.org/2026/2565", "primary abstract and metadata, no gain subtracted from MATZOV panel")):
        record = {"id": label, "url": url, "consulted_utc": datetime.now(timezone.utc).isoformat(), "scope": scope,
                  "external_content_redistributed": False}
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "MAJAX-NIST-research"}), timeout=45) as response:
                raw = response.read(12_000_001)
            require(len(raw) <= 12_000_000, "primary source exceeds capture bound")
            path = cache / (label + (".pdf" if url.endswith(".pdf") else ".html"))
            path.write_bytes(raw)
            record.update(status="captured", bytes=len(raw), sha256=sha(raw), cache=path.relative_to(ROOT).as_posix())
        except Exception as error:
            record.update(status="capture_unavailable", error_type=type(error).__name__, error=str(error),
                          reading_basis="primary page/PDF was consulted with the web reader; no local bytes or hash claimed")
        primary.append(record)
    save(output / "primary-sources.json", primary)


def signature(job):
    return tuple(job[k] for k in ("sample_game", "cost_model", "family", "success_contract", "targets",
                                 "leakage_oracle", "memory_cap", "shape_model", "estimator_commit"))


def usable_cost(result, receipt):
    value = result.get("log2_cost", {}).get("rop")
    return (result["status"] == "returned" and receipt["exit_code"] == 0 and receipt["expired"] is False
            and type(value) in (int, float) and math.isfinite(value))


def correction_report(certificate):
    encoded = certificate["message_upper"]
    delta = Fraction(int(encoded["numerator_hex"], 16), int(encoded["denominator_hex"], 16))
    require(0 < delta < 1, "invalid historical correction fraction")
    c05 = delta.numerator ** 5 * (1 << 874) <= delta.denominator ** 5
    require(c05 and certificate["c05_exact_comparison"] is True, "historical C05 certificate no longer passes")
    ro = delta * Fraction((1 << 256) - 1, 1 << 256)
    return {"source": "run-004 exact fraction reused, not a new tail computation",
            "population": "independent ideal CBD; RO transfer average over oracles/keys, worst message with fresh uniform PKE coins",
            "log2_certificate_display_reused": certificate["log2_message_upper_display"],
            "threshold": {"exponent_numerator": -874, "exponent_denominator": 5},
            "C05_exact_rational_comparison": c05, "delta_RO_not_larger_than_certificate": ro <= delta,
            "seed_collision_case": "equal key/encryption noise seeds imply r=s and e1=e; residual e2 within +/-3 in commutative ring",
            "adaptive_failure_search_covered": False, "every_fixed_key_and_concrete_SHAKE_certified": False,
            "MLKEM1024_reference": {"published_log2_failure_estimate": -174.8,
                "population": "uniform d,z,m and random-function hash/XOF heuristic, FIPS203Table1",
                "treated_as_same_kind_of_rational_certificate": False}}


def analyze(members):
    def parsed(name):
        return json.loads(members[name])
    plan = parsed("plan.json")
    require(plan["schema"] == "m10-parameters-plan-v1" and len(plan["jobs"]) == 40
            and plan["old_M05_jobs_credited_as_new"] == 0, "wrong finite parameter plan")
    require(sha(members["protocol.md"]) == plan["protocol_sha256"], "preregistered parameter protocol changed")
    for name, digest in plan["controls_sha256"].items():
        require(sha(members["sources/research/" + name]) == digest, "frozen acquisition control changed")
    launch = parsed("launch.json")
    require(sha(members["plan.json"]) == launch["plan_sha256"], "launch plan binding differs")
    require(sha(members["estimator-source.json"]) == launch["estimator_manifest_sha256"], "estimator source identity differs")
    historical = parsed("inputs/m05-comparison.json")
    historical_provenance = parsed("inputs/m05-provenance.json")
    require(sha(members["inputs/m05-comparison.json"]) == historical_provenance["output_sha256"]["comparison.json"], "historical M05 input changed")
    cert_provenance = parsed("inputs/certificate-provenance.json")
    require(sha(members["inputs/r1-correctness-certificate.json"]) == cert_provenance["output_sha256"]["correctness-certificate.json"], "historical correctness fraction changed")
    rows, grouped = [], {}
    for index, job in enumerate(plan["jobs"]):
        profiles = {"R1": (256, 6, 7681, 3), "ML-KEM-1024": (256, 4, 3329, 2)}
        require(job["profile"] in profiles and (job["degree"], job["rank"], job["q"], job["eta"]) == profiles[job["profile"]], "profile transcription differs")
        require(job["sample_game"] in ("key", "ideal_k_plus_1") and job["dimension"] == job["degree"] * job["rank"]
                and job["samples"] == job["degree"] * (job["rank"] + (job["sample_game"] == "ideal_k_plus_1")), "finite sample game differs")
        require(job["family"] in ("usvp", "bdd", "primal_hybrid_mitm", "dual", "dual_hybrid_matzov")
                and job["cost_model"] in ("MATZOV-classical", "BCSS23-quantum-reduction-sensitivity"), "attack/model contract differs")
        require(job["index"] == index and job["targets"] == 1 and job["memory_cap"] is None
                and job["leakage_oracle"] == "none" and job["real_MLWE_claimed_IID_LWE"] is False
                and job["real_ciphertext_rows_claimed_independent"] is False, "job grid/access contract differs")
        require(parsed(f"jobs/input-{index:03d}.json") == job, "recorded input differs")
        result, receipt = parsed(f"jobs/result-{index:03d}.json"), parsed(f"jobs/receipt-{index:03d}.json")
        require(result["job"] == job and sha(members[f"jobs/result-{index:03d}.json"]) == receipt["result_sha256"], "job result binding differs")
        require(sha(members[f"jobs/stdout-{index:03d}.log"]) == receipt["stdout_sha256"]
                and sha(members[f"jobs/stderr-{index:03d}.log"]) == receipt["stderr_sha256"], "raw process streams changed")
        if result["status"] in ("returned", "exception"):
            require(result["worker_sha256"] == plan["controls_sha256"]["m10_parameters_worker.py"], "executed worker differs")
        finite = usable_cost(result, receipt)
        dimensions = {k: int(result["cost"][k]) for k in ("beta", "beta_", "eta", "d", "zeta", "m")
                      if k in result.get("cost", {}) and str(result["cost"][k]).isdecimal()}
        old_family = {"usvp": "usvp", "bdd": "bdd", "dual_hybrid_matzov": "dual_hybrid"}.get(job["family"])
        old = [r for r in historical["results"] if r["job"]["scenario"] == job["profile"]
               and r["job"]["sample_budget"] == job["sample_game"] and r["job"]["algorithm"] == old_family
               and r["job"]["cost_model"] == ("MATZOV-classical" if job["cost_model"] == "MATZOV-classical" else "BCSS23-quantum-asymptotic")]
        require(len(old) <= 1, "ambiguous historical counterpart")
        row = {"job": job, "result_status": result["status"], "process_exit_code": receipt["exit_code"],
               "expired": receipt["expired"], "finite_cost_available": finite,
               "log2_operations": result.get("log2_cost", {}).get("rop") if finite else None,
               "dimensions": dimensions, "memory": memory_diagnostic(job["family"], result.get("log2_cost", {})),
               "MATZOV_fit_beyond_1024": job["cost_model"] == "MATZOV-classical" and any(dimensions.get(k, 0) > 1024 for k in ("beta", "beta_", "eta")),
               "historical_M05_counterpart_log2_operations": old[0]["log2_cost"]["rop"] if old else None,
               "historical_jobs_counted_as_new": 0}
        if old and finite:
            row["new_minus_historical_same_family_log2_cost"] = row["log2_operations"] - old[0]["log2_cost"]["rop"]
        rows.append(row)
        group = grouped.setdefault(signature(job), {})
        require(job["profile"] not in group, "duplicate profile in strict pair")
        group[job["profile"]] = row
    require(len(grouped) == 20, "exactly20 attack-contract pairs required")
    pairs = []
    for key, group in sorted(grouped.items()):
        require(set(group) == {"R1", "ML-KEM-1024"}, "incomplete attack-contract pair")
        r1, reference = group["R1"], group["ML-KEM-1024"]
        both = r1["finite_cost_available"] and reference["finite_cost_available"]
        difference = r1["log2_operations"] - reference["log2_operations"] if both else None
        pairs.append({"sample_game": key[0], "cost_model": key[1], "family": key[2], "success_contract": key[3],
                      "R1": r1, "reference": reference, "conditional_log2_cost_difference": difference,
                      "R1_proxy_at_least_reference": difference >= 0 if both else None,
                      "global_security_gain_bits": None})
    monotonicity = []
    for profile in ("R1", "ML-KEM-1024"):
        for model in sorted({r["job"]["cost_model"] for r in rows}):
            for family in sorted({r["job"]["family"] for r in rows}):
                selected = {r["job"]["sample_game"]: r for r in rows if r["job"]["profile"] == profile
                            and r["job"]["cost_model"] == model and r["job"]["family"] == family}
                if all(r["finite_cost_available"] for r in selected.values()):
                    delta = selected["ideal_k_plus_1"]["log2_operations"] - selected["key"]["log2_operations"]
                    monotonicity.append({"profile": profile, "cost_model": model, "family": family,
                                         "more_samples_minus_key_log2_operations": delta,
                                         "optimizer_increase_observed": delta > 1e-9,
                                         "interpretation": "larger finite LWE sample budget may ignore extra rows; an increase is an optimization diagnostic, not stronger security"})
    failures = [p for p in pairs if p["R1_proxy_at_least_reference"] is False]
    missing = [r["job"]["index"] for r in rows if not r["finite_cost_available"]]
    return {"schema": "m10-parameters-report-v1", "requested_new_jobs": 40, "completed_finite_jobs": 40 - len(missing),
            "result_status_counts": dict(Counter(r["result_status"] for r in rows)), "missing_or_nonfinite_jobs": missing,
            "strict_pairs": pairs, "unfavorable_R1_pair_count": len(failures), "monotonicity_diagnostics": monotonicity,
            "memory_constrained_optimization_complete": False, "global_security_level_claimed": None,
            "symmetric_search_models": {"panels": symmetric_panels(), "finite_checks": finite_search_checks(),
                                        "generic_search_space_bits_both_profiles": 256, "Grover_query_scale_bits": 128,
                                        "queries_are_not_reversible_gate_or_depth_costs": True},
            "memory_filter_counterexample": bounded_memory_counterexample(), "wire_sizes": wire_sizes(),
            "correction": correction_report(parsed("inputs/r1-correctness-certificate.json")),
            "decision": {"continue_R1_engineering": not failures, "new_profile_selected": False,
                         "final_cryptographic_parameter_freeze": False,
                         "blockers": ["complete C01 incl.QROM and concrete primitives", "RAM-constrained attack optimization and physical resource model",
                                      "adaptation of modern covariance/structured attacks and validated score tails", "estimator local optimization and large-beta extrapolation"],
                         "incomplete_or_unfavorable_panel_blocks_automatic_final_selection": bool(missing or failures)}}


def collect(output):
    collect_inputs(output)
    analysis = output / "analysis-controls"
    analysis.mkdir()
    for name in ("m10_parameters_report.py", "m10_parameters_model.py", "test_m10_parameters.py"):
        shutil.copyfile(ROOT / "research" / name, analysis / name)
    members = {p.relative_to(output).as_posix(): p.read_bytes() for p in output.rglob("*") if p.is_file()}
    report = analyze(members)
    save(output / "report.json", report)
    return report


def resume_analysis(output):
    require((output / "analysis-attempts/001/failure.json").is_file()
            and not (output / "report.json").exists(), "only explicit failed analysis may be resumed")
    shutil.copyfile(ROOT / "research/m10_parameters_report.py", output / "analysis-controls/m10_parameters_report-002.py")
    members = {p.relative_to(output).as_posix(): p.read_bytes() for p in output.rglob("*") if p.is_file()}
    report = analyze(members)
    save(output / "report.json", report)
    return report


def bounded_members(path):
    members, total = {}, 0
    with tarfile.open(path, "r:gz") as archive:
        for item in archive:
            name = PurePosixPath(item.name)
            require(item.isfile() and not name.is_absolute() and ".." not in name.parts and str(name) == item.name
                    and item.name not in members and item.size <= 8_000_000, "unsafe parameter archive member")
            total += item.size
            require(total <= 80_000_000 and len(members) < 2000, "parameter archive expansion budget exceeded")
            members[item.name] = archive.extractfile(item).read()
    return members


def freeze(output, destination):
    members = {p.relative_to(output).as_posix(): p.read_bytes() for p in output.rglob("*") if p.is_file()}
    report = analyze(members)
    require(report == json.loads(members["report.json"]), "live parameter interpretation changed")
    destination.mkdir(parents=True, exist_ok=False)
    with tarfile.open(destination / "evidence.tar.gz", "x:gz", compresslevel=6) as archive:
        for name in sorted(members):
            archive.add(output / name, arcname=name, recursive=False)
    save(destination / "report.json", report)
    save(destination / "provenance.json", {"schema": "m10-parameter-capsule-v1",
         "members_sha256": {n: sha(raw) for n, raw in members.items()},
         "archive_sha256": sha((destination / "evidence.tar.gz").read_bytes()),
         "report_sha256": sha((destination / "report.json").read_bytes()),
         "no_old_estimates_credited_as_new": True, "Rust_or_profile_modified": False})
    return verify(destination)


def verify(destination):
    provenance = read(destination / "provenance.json")
    require(sha((destination / "evidence.tar.gz").read_bytes()) == provenance["archive_sha256"], "parameter archive changed")
    members = bounded_members(destination / "evidence.tar.gz")
    require({n: sha(raw) for n, raw in members.items()} == provenance["members_sha256"], "parameter archive inventory changed")
    report = analyze(members)
    require(sha((destination / "report.json").read_bytes()) == provenance["report_sha256"]
            and report == read(destination / "report.json"), "recalculated parameter report differs")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("collect", "resume-analysis", "freeze", "verify"))
    parser.add_argument("--output", type=Path, default=OUT)
    parser.add_argument("--result", type=Path, default=RESULT)
    args = parser.parse_args()
    result = collect(args.output) if args.action == "collect" else resume_analysis(args.output) if args.action == "resume-analysis" else freeze(args.output, args.result) if args.action == "freeze" else verify(args.result)
    print(json.dumps({key: result[key] for key in ("requested_new_jobs", "completed_finite_jobs", "unfavorable_R1_pair_count", "decision")}, indent=2))
