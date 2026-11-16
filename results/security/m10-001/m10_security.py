"""Freeze/replay the M10 ideal-oracle composition, laws and honest C01 gate.

No command performs cryptanalysis, builds an engine, or fetches the network.
The published security claim remains conditional and C01 remains open.
"""
import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import re
import shutil

from m10_security_bounds import (controlled_coordinate_cost, fo_coordinates, gyy_message_floor,
    mre_alternative_ledger, noise_gap_qrom, noise_gap_rom, ow_from_cpa, pke_cpa_bound,
    qrom_gyy_ledger, rom_cca_ledger, rom_cca_counted, sqrt_interval)
from m10_security_quantum import finite_controlled_oracle_checks, finite_quantum_checks
from m10_security_resources import finite_adaptive_correctness_checks, finite_simulator_law_checks, rom_resource_envelope
from m10_security_sampler import (certified_inverse_power, finite_law_checks, finite_tail_checks,
    matrix_simulation_gap, require)

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "KEM1536-DEV-Q7681-R1"
FILES = ("m10_security.py", "m10_security_sampler.py", "m10_security_bounds.py",
         "m10_security_quantum.py", "m10_security_resources.py", "test_m10_security.py")
CONTRACT = {
    "profile": (None, 'pub const PROFILE: &str = "KEM1536-DEV-Q7681-R1";'),
    "modulus": (None, "pub const Q: u16 = 7681;"),
    "rank": (None, "pub const RANK: usize = 6;"),
    "tag": (None, 'const TAG: &[u8] = b"KEM1536-DEV-Q7681-R1\\0";'),
    "matrix_domain": ("uniform", 'h.update(b"A\\0");'),
    "matrix_coordinates": ("uniform", "h.update(&[i, j]);"),
    "matrix_pair": ("uniform", "let mut pair = [0; 2];"),
    "matrix_mask": ("uniform", "let value = u16::from_le_bytes(pair) & 8191;"),
    "matrix_acceptance": ("uniform", "if value < Q {"),
    "noise_owner_size": ("noise_into", "let mut bytes = Zeroizing::new([0; 192]);"),
    "noise_domain": ("noise_into", 'xof_into(b"N\\0", &[seed, &[nonce]], &mut bytes);'),
    "noise_first_half": ("noise_into", "bit(6 * j) + bit(6 * j + 1) + bit(6 * j + 2)"),
    "noise_second_half": ("noise_into", "bit(6 * j + 3) + bit(6 * j + 4) + bit(6 * j + 5)"),
    "KG_domain": ("pke_keygen_into", 'derive_into(b"KG\\0", &[d, &[6]], &mut expanded);'),
    "G_encaps_domain": ("encaps_internal", 'derive_into(b"G\\0", &[m, &hash_public(ek.as_bytes())], &mut material);'),
    "G_decaps_domain": ("decapsulate", 'derive_into(b"G\\0", &[&m[..], &dk.0[offset..offset + 32]], &mut material);'),
    "J_domain": ("decapsulate", 'xof_into(b"J\\0", &[&dk.0[offset + 32..], c.as_bytes()], &mut key);'),
}


def sha(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def rational(value):
    return dict(numerator_hex=hex(value.numerator), denominator_hex=hex(value.denominator))


def serialize(value):
    if isinstance(value, Fraction):
        return rational(value)
    if isinstance(value, dict):
        return {key:serialize(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [serialize(item) for item in value]
    return value


def save(path, value):
    path.write_text(json.dumps(serialize(value),indent=2,ensure_ascii=False)+"\n",encoding="utf-8")


def function_body(source,name):
    """Find a reviewed top-level Rust function; skip strings/comments in braces.

    This is deliberately a literal-link reader, not a complete Rust parser.
    Scoping prevents test-only old helpers from satisfying production anchors.
    """
    found=re.search(r"(?m)^(?:pub )?fn "+re.escape(name)+r"(?:\(|<)",source)
    require(found is not None,"missing reviewed function: "+name)
    start=source.index("{",found.start())
    depth,index,state,escaped=0,start,"normal",False
    while index<len(source):
        char=source[index]
        following=source[index:index+2]
        if state=="line":
            if char=="\n":state="normal"
        elif state=="block":
            if following=="*/":state="normal";index+=1
        elif state=="string":
            if escaped:escaped=False
            elif char=="\\":escaped=True
            elif char=='"':state="normal"
        elif following=="//":state="line";index+=1
        elif following=="/*":state="block";index+=1
        elif char=='"':state="string"
        elif char=="{":depth+=1
        elif char=="}":
            depth-=1
            if depth==0:return source[start:index+1]
        index+=1
    raise ValueError("unterminated reviewed function: "+name)


def contract(source):
    scopes={name:function_body(source,name) for name,_ in CONTRACT.values() if name is not None}
    scopes[None]=source[:source.index("fn seed_tail")]
    require(all(text in scopes[name] for name,text in CONTRACT.values()), "R1 source contract differs")
    return dict(anchor_count=len(CONTRACT), anchors=CONTRACT,
                normalized_text_sha256=hashlib.sha256(source.encode("utf-8")).hexdigest(),
                scope="reviewed literal source links, not a formal Rust refinement or target-machine proof")


def certificate_delta(certificate):
    require(certificate["parameters"] == dict(q=7681,n=256,k=6,eta1=3,eta2=3,dv=5), "wrong correction population")
    require(certificate["one_sided_tail_threshold"] == 1800 and certificate["common_safe_radius"] == 1799,
            "wrong R1 decoding threshold")
    value = certificate["message_upper"]
    result = Fraction(int(value["numerator_hex"],16),int(value["denominator_hex"],16))
    require(0 < result < 1, "invalid certificate probability")
    return result


def build_report(certificate, source):
    delta = (1-Fraction(1,1<<256))*certificate_delta(certificate)
    matrix_panels = []
    for limit in (320,384,448,512,640,768,1024):
        panel = matrix_simulation_gap(word_limit=limit)
        panel.update(word_limit_per_cell=limit,
            truncation_certified_at_most_power_of_two=certified_inverse_power(panel["truncation_gap"]))
        matrix_panels.append(panel)
    quantum_diagnostics = []
    for budget_bits in (0,16,32,64,96,128):
        query_budget=1<<budget_bits
        floor=gyy_message_floor(query_budget,query_budget,query_budget)
        target=Fraction(1,1<<128)
        r=2*query_budget+query_budget+1
        # A comparison of two proof ledgers, deliberately without MLWE advantages.
        # Zero CPA below is a diagnostic lower ledger, never an asserted assumption.
        alternative=mre_alternative_ledger(delta,Fraction(0),r,r,1,Fraction(0))
        q_lower=sqrt_interval(r)[0]
        alternative_guessing_lower=Fraction(16*(10*r+1),1<<256)*q_lower
        quantum_diagnostics.append(dict(budget_bits=budget_bits,
            GYY_proof_message_floor=floor,
            GYY_target_2_minus_128_refuted_by_floor=floor["lower"]>target,
            MRE_diagnostic=alternative,
            MRE_message_term_lower=alternative_guessing_lower,
            MRE_target_refuted_by_this_known_term=alternative_guessing_lower>target,
            noise_QROM_gap_at_CPA_budgets=noise_gap_qrom(query_budget,query_budget),
            classical_noise_gap_at_CPA_budgets=noise_gap_rom(query_budget,query_budget),
            same_CPA_and_CCA_query_counts_are_not_inferred=True,
            global_security_rating_assigned=False))
    examples=[]
    for model in ("ROM","QROM"):
        for query_bits in (0,16,32,64):
            q=1<<query_bits
            # Supplying an advantage is a hypothesis of the example, not an estimator result.
            coordinates=fo_coordinates(q,q,q)
            if model=="ROM":
                cca=rom_cca_counted(delta,Fraction(1,1<<200),Fraction(1,1<<200),q,q,q)
                pke=cca["pke"]
            else:
                pke=pke_cpa_bound(model,Fraction(1,1<<200),Fraction(1,1<<200),q,q)
                cca=qrom_gyy_ledger(delta,pke["cpa_bias_upper"],q,q,q,q)
            examples.append(dict(model=model,query_bits=query_bits,
                input_MLWE_advantages_are_unproved_illustrations=True,
                CPA_query_budget_scope="derived counted classical map" if model=="ROM" else "independently supplied; no full QROM map inferred",
                no_claim_that_resource_map_closes=pke["C01_closed"] is False,
                coordinates=coordinates,pke=pke,cca=cca))
    missing=("finite concrete MLWE advantage/resource calibration",
        "full QROM FO reversible circuit/base-oracle resource map",
        "numeric ROM/QROM target with total time, memory, parallelism and multi-target budget",
        "stated and externally examined computational hypotheses for fixed SHA3/SHAKE",
        "independent cryptographic review deferred by the user")
    return dict(schema="m10-security-composition-v1",profile=PROFILE,
        source_contract=contract(source),
        correction=dict(expanded_RO_delta=delta,population="average ideal oracles and honest keys, worst message"),
        component_results=dict(matrix_inverse_rejection="perfect conditional stream law; truncation explicitly charged",
            matrix_quantum_scope="known finite prefix XOR patch before the CPA adversary's first query",
            seeded_noise_ROM="M09 exact hidden-label count retained",
            seeded_noise_QROM="norm hybrid at independent unused latent labels, with collision charged",
            CPA="two decision assumptions MLWE(6,6) and MLWE(7,6), not an estimator security proof",
            classical_FO_resources="counted lazy implicit-rejection simulator, CPA branch envelope and conservative normalized bound",
            GYY="applicable implicit-rejection theorem22, conditional resources and numerical margins",
            MRE="alternative applicable through BHHP19 graph simulation; full resource map remains unqualified"),
        fixed_function_matrix_support=dict(seed_bits=256,coefficients=6*6*256,
            total_variation_lower_formula="1-2^256/7681^9216",
            missing_mass_greater_than_one_minus_2_minus_110336=(1<<110592)<7681**9216,
            efficient_distinguisher_constructed=False),
        required_MLWE_instances=[dict(rows=6,columns=6,degree=256,q=7681,CBD_eta=3,
            flattened_secret_dimension=1536,flattened_scalar_samples=1536),
            dict(rows=7,columns=6,degree=256,q=7681,CBD_eta=3,
            flattened_secret_dimension=1536,flattened_scalar_samples=1792)],
        flattened_rotations_are_not_independent_LWE_samples=True,
        matrix_termination_panels=matrix_panels,
        finite_inverse_sampler=finite_law_checks(),finite_termination=finite_tail_checks(),
        finite_quantum_norm_hybrid=finite_quantum_checks(),
        finite_classical_implicit_simulator=finite_simulator_law_checks(),
        finite_adaptive_correctness=finite_adaptive_correctness_checks(),
        classical_resource_example=rom_resource_envelope(37,41,43,47,53),
        finite_coherent_coordinate=finite_controlled_oracle_checks(),
        graph_bridge_example=controlled_coordinate_cost(37,recovered_key=True),
        conditional_examples=examples,proof_margin_diagnostics=quantum_diagnostics,
        C01_closed=False,cryptographic_parameter_freeze_supported=False,
        concrete_primitive_security_proved=False,external_audit=False,
        remaining_obligations=missing,
        scope="new symbolic ideal-model components and bounded exact checks; no attack, engine build, benchmark or fuzz credit")


def freeze(output, source_path):
    output=output.resolve()
    require(output.parent==ROOT/"results/security" and output.name=="m10-001" and not output.exists(),
            "new owned security capsule required")
    source=source_path.read_text(encoding="utf-8")
    certificate=read(ROOT/"results/j2/run-004/correctness-certificate.json")
    acquisition=ROOT/"artifacts/generated/m10-security-001"
    test_receipt=read(acquisition/"tests.json")
    require(test_receipt["exit_code"]==0 and test_receipt["test_count"]==28,
            "final complete M10 mathematical test receipt required")
    expected_inputs={"research/"+name:sha(ROOT/"research"/name) for name in FILES}
    expected_inputs.update({"docs/SECURITE_M10.md":sha(ROOT/"docs/SECURITE_M10.md"),
        "crates/kem1536/src/dev_kem.rs":sha(source_path),
        "source-anchors.json":sha(acquisition/"source-anchors.json")})
    require(test_receipt["input_sha256_before"]==expected_inputs==test_receipt["input_sha256_after"],
            "controls or reviewed source changed after mathematical tests")
    report=build_report(certificate,source)
    output.mkdir()
    for name in FILES:
        shutil.copyfile(ROOT/"research"/name,output/name)
    shutil.copyfile(ROOT/"docs/SECURITE_M10.md",output/"SECURITE_M10.md")
    shutil.copyfile(ROOT/"artifacts/generated/m10-security-001/source-anchors.json",output/"source-anchors.json")
    for name in ("tests.json","tests.stdout","tests.stderr"):
        shutil.copyfile(acquisition/name,output/name)
    shutil.copyfile(ROOT/"results/j2/run-004/correctness-certificate.json",output/"correctness-certificate.json")
    # Preserve actual source bytes; text decode is only for literal-link checks.
    shutil.copyfile(source_path,output/"dev_kem.rs")
    save(output/"report.json",report)
    (output/"README.md").write_text("# M10 security composition\n\n"
        "Run `python -B m10_security.py verify --output .` from this directory. "
        "This replays finite exact laws and composition ledgers offline, without the engine, "
        "compiler, estimator, network or fuzzer. C01 remains open; no final bit rating, "
        "concrete primitive proof or outside audit is claimed. See SECURITE_M10.md.\n",encoding="utf-8")
    save(output/"provenance.json",dict(schema="m10-security-capsule-v1",
        output_sha256={p.name:sha(p) for p in sorted(output.iterdir())},
        C01_closed=False,external_audit=False))
    return dict(frozen=str(output),members=len(read(output/"provenance.json")["output_sha256"]),C01_closed=False)


def verify(output):
    output=output.resolve()
    require(output.is_dir() and all(p.is_file() and not p.is_symlink() for p in output.iterdir()),
            "flat regular-file security capsule required")
    provenance=read(output/"provenance.json")
    require(provenance["schema"]=="m10-security-capsule-v1" and provenance["C01_closed"] is False
            and provenance["external_audit"] is False,"security provenance scope changed")
    actual={p.name:sha(p) for p in output.iterdir() if p.is_file() and p.name!="provenance.json"}
    require(actual==provenance["output_sha256"],"security capsule inventory changed")
    expected=serialize(build_report(read(output/"correctness-certificate.json"),
                                   (output/"dev_kem.rs").read_text(encoding="utf-8")))
    require(expected==read(output/"report.json"),"recomputed security conclusion changed")
    return dict(verified=True,members=len(actual),C01_closed=False,external_audit=False,
        finite_inverse_sampler=expected["finite_inverse_sampler"],
        finite_quantum_norm_hybrid=expected["finite_quantum_norm_hybrid"],
        new_engine_builds=0,new_fuzzing_credit_seconds=0)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=("freeze","verify","report"))
    parser.add_argument("--output",type=Path,default=ROOT/"results/security/m10-001")
    parser.add_argument("--source",type=Path,default=ROOT/"crates/kem1536/src/dev_kem.rs")
    args=parser.parse_args()
    if args.action=="freeze":
        result=freeze(args.output,args.source)
    elif args.action=="verify":
        result=verify(args.output)
    else:
        result=build_report(read(ROOT/"results/j2/run-004/correctness-certificate.json"),args.source.read_text(encoding="utf-8"))
    print(json.dumps(serialize(result),indent=2,ensure_ascii=False))


if __name__=="__main__":
    main()
