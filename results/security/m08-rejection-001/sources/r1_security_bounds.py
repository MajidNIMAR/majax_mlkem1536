"""Exact conditional ROM/QROM budgets for R1; not a Keccak security proof.

HHK17 section 3.3 (with the 2021 erratum) and GYY25 Theorem 22 are kept
separate. Unknown seeded-PKE and rejection-PRF advantages are never set to zero
in a claim of complete IND-CCA security. Decimal values are display only.
"""

import argparse
from decimal import Decimal, localcontext
from fractions import Fraction
import hashlib
import json
from math import isqrt
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CERTIFICATE = ROOT / "results/j2/run-004/correctness-certificate.json"
MESSAGE_SPACE = 1 << 256
ROM_PKE_COEFFICIENT = 6  # Conservative normalization safeguard; see the M05 note.


def hash_file(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def nonnegative_integer(value, name):
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer")
    return value


def probability(value, name):
    value = Fraction(value)
    if not 0 <= value <= 1:
        raise ValueError(f"{name} must lie in [0,1]")
    return value


def load_certificate(path=CERTIFICATE):
    certificate = read_json(path)
    if certificate["parameters"] != dict(q=7681, n=256, k=6, eta1=3, eta2=3, dv=5):
        raise ValueError("the certificate is not the R1 parameter set")
    if (certificate["one_sided_tail_threshold"] != 1800
            or certificate["common_safe_radius"] != 1799
            or certificate["v_error_range"] != [-120, 120]):
        raise ValueError("R1 decoding/certificate thresholds differ")
    value = certificate["message_upper"]
    return probability(Fraction(int(value["numerator_hex"], 16),
                                int(value["denominator_hex"], 16)), "certificate delta")


def expanded_sampler_delta(delta, seed_bits=256):
    """Average over random N: coincident key/encryption seeds cancel the products.

    This does not bound every fixed N or concrete SHAKE. Keygen's seed must be
    independent of the random N function, and encryption's seed is fresh uniform.
    """
    delta = probability(delta, "delta")
    nonnegative_integer(seed_bits, "seed_bits")
    return (1 - Fraction(1, 1 << seed_bits)) * delta


def inclusive_queries(g512, rejection_j, decapsulations):
    """Public G512 reveals TWO independent coordinates; include implicit calls.

    One challenge G512 evaluation; each Decaps evaluates G512 and J, including
    unselected outputs. Base oracles KG/N/A/Hpk remain in the PKE/PRF games.
    """
    g512 = nonnegative_integer(g512, "g512")
    rejection_j = nonnegative_integer(rejection_j, "rejection_j")
    decapsulations = nonnegative_integer(decapsulations, "decapsulations")
    coins = g512 + decapsulations + 1
    keys_and_rejection = g512 + rejection_j + 2 * decapsulations + 1
    return dict(coins=coins, key_only=coins, key_and_rejection=keys_and_rejection,
                total_rom=coins + keys_and_rejection, decapsulations=decapsulations,
                explicit_g512=g512, explicit_j=rejection_j)


def rom_terms(delta, g512, rejection_j, decapsulations):
    delta = probability(delta, "delta")
    queries = inclusive_queries(g512, rejection_j, decapsulations)
    qro = queries["total_rom"]
    coefficient = 2 * qro + decapsulations
    correction = coefficient * delta
    guessing = Fraction(3 * qro, MESSAGE_SPACE)
    return dict(queries=queries, correction_coefficient=coefficient, correction=correction,
                message_guessing=guessing, known_additive=correction + guessing,
                unknown_pke_cpa_coefficient=ROM_PKE_COEFFICIENT)


def rom_pke_obligation(delta, g512, rejection_j, decapsulations, target):
    target = probability(target, "target")
    if target > Fraction(1, 2):
        raise ValueError("the advantage convention is |Pr[win]-1/2|")
    residual = rom_terms(delta, g512, rejection_j, decapsulations)["known_additive"]
    return None if residual > target else (target - residual) / ROM_PKE_COEFFICIENT


def qrom_terms(delta, g512, rejection_j, decapsulations):
    delta = probability(delta, "delta")
    queries = inclusive_queries(g512, rejection_j, decapsulations)
    # A coherent public-key namespace dispatch can be implemented with
    # compute/controlled-XOR/uncompute: at most two calls to each target half.
    qf = qk = 2 * g512 + decapsulations + 1
    queries = dict(explicit_g512=g512, public_shake256_budget=rejection_j,
                   decapsulations=decapsulations, qrom_coins=qf, qrom_key=qk,
                   rejection_keyed_classical_queries_max=decapsulations,
                   coherent_namespace_query_multiplier=2)
    coefficient = 16 * (qf + 1) ** 2
    return dict(queries=queries, correction_coefficient=coefficient, correction=coefficient * delta,
                sqrt_ow_coefficient=2 * (qf + qk),
                unknown_rejection_prf_coefficient=1)


def qrom_ow_obligation(delta, g512, rejection_j, decapsulations, target, prf_advantage):
    target = probability(target, "target")
    prf_advantage = probability(prf_advantage, "prf_advantage")
    if target > Fraction(1, 2):
        raise ValueError("the advantage convention is |Pr[win]-1/2|")
    terms = qrom_terms(delta, g512, rejection_j, decapsulations)
    remaining = target - terms["correction"] - prf_advantage
    return None if remaining < 0 else (remaining / terms["sqrt_ow_coefficient"]) ** 2


def sqrt_interval(value, precision_bits=512):
    """Dyadic interval enclosing sqrt(value), proved by integer inequalities."""
    value = probability(value, "value")
    nonnegative_integer(precision_bits, "precision_bits")
    scale = 1 << precision_bits
    numerator = value.numerator * scale * scale
    lower = isqrt(numerator // value.denominator)
    upper = lower if lower * lower * value.denominator == numerator else lower + 1
    return Fraction(lower, scale), Fraction(upper, scale)


def qrom_total_upper(delta, g512, rejection_j, decapsulations, ow_advantage, prf_advantage):
    terms = qrom_terms(delta, g512, rejection_j, decapsulations)
    _, root_upper = sqrt_interval(ow_advantage)
    total = (terms["correction"] + probability(prf_advantage, "prf_advantage")
             + terms["sqrt_ow_coefficient"] * root_upper)
    return min(Fraction(1, 2), total)


def display(value):
    value = Fraction(value)
    if value == 0:
        return dict(approx_probability="0", approx_log2=None)
    with localcontext() as context:
        context.prec = 90
        decimal = Decimal(value.numerator) / Decimal(value.denominator)
        log2 = decimal.ln() / Decimal(2).ln()
        return dict(approx_probability=format(decimal, ".24E"), approx_log2=format(log2, ".18f"))


def rational(value):
    value = Fraction(value)
    return dict(numerator_hex=hex(value.numerator), denominator_hex=hex(value.denominator), **display(value))


def make_report(delta):
    expanded_delta = expanded_sampler_delta(delta)
    panels = []
    for bits in (0, 16, 32, 64, 96, 128):
        budget = (1 << bits) if bits else 0
        rom = rom_terms(expanded_delta, budget, budget, budget)
        quantum = qrom_terms(expanded_delta, budget, budget, budget)
        target = Fraction(1, 1 << 128)
        rom_needed = rom_pke_obligation(expanded_delta, budget, budget, budget, target)
        # This allocation is a requirement, not an assumed/established PRF bound.
        prf_allocation = target / 4
        ow_needed = qrom_ow_obligation(expanded_delta, budget, budget, budget, target, prf_allocation)
        panels.append(dict(explicit_g512=budget, explicit_j=budget, decapsulations=budget,
                           queries=rom["queries"], target_bias="2^-128",
                           rom=dict(correction_coefficient=rom["correction_coefficient"],
                                    correction=display(rom["correction"]),
                                    message_guessing=display(rom["message_guessing"]),
                                    known_additive=display(rom["known_additive"]),
                                    pke_cpa_coefficient=ROM_PKE_COEFFICIENT,
                                    pke_cpa_required=None if rom_needed is None else display(rom_needed),
                                    target_not_certified_by_this_rom_bound_even_with_zero_pke_advantage=rom_needed is None),
                           qrom_theorem22=dict(correction_coefficient=quantum["correction_coefficient"],
                                              queries=quantum["queries"],
                                              correction=display(quantum["correction"]),
                                              sqrt_ow_coefficient=quantum["sqrt_ow_coefficient"],
                                              prf_advantage_allocation_required="2^-130; not established",
                                              ow_probability_required=None if ow_needed is None else display(ow_needed),
                                              generic_zero_work_message_guess_probability="2^-256",
                                              sufficient_ow_requirement_below_message_guess_floor=(ow_needed is not None and ow_needed < Fraction(1, MESSAGE_SPACE)),
                                              full_bound_evaluated=False)))
    return dict(schema="m05-r1-conditional-security-bounds-v1", profile="KEM1536-DEV-Q7681-R1",
                advantage_convention="absolute bias |Pr[win]-1/2|, maximum 1/2",
                pke_ow_convention="plaintext recovery success probability in [0,1]",
                rejection_prf_convention="absolute distinguishing probability gap in [0,1]; quantum public-oracle access and classical indexed queries",
                model="mono-user, one challenge, classical Decaps; independent ideal domain-separated oracles",
                complete_concrete_keccak_bound=False, certificate_delta=display(delta),
                expanded_sampler_delta=display(expanded_delta),
                expanded_sampler_factor=dict(numerator_hex=hex(MESSAGE_SPACE - 1), denominator_hex=hex(MESSAGE_SPACE)),
                rom_formula="6*epsilon_CPA_bias_seeded_aux + (2*Q_RO+D)*delta_RO + 3*Q_RO/2^256",
                rom_pke_coefficient_status="Conservative coefficient 6; source table prints 3 but an OW-to-CPA normalization inconsistency is documented in M05. No claim that HHK prints 6.",
                inclusive_query_formula="Q_RO=2*g512+j+3*D+2; challenge and implicit decapsulation calls included",
                qrom_formula="epsilon_PRF_J + 2*(Q_F+Q_K)*sqrt(epsilon_OW_seeded_aux) + 16*(Q_F+1)^2*delta_RO",
                qrom_queries="Q_F=Q_K=2*g512+D+1; conservative coherent namespace dispatch and implicit calls included. Public J/Noise queries remain in the PRF/PKE games.",
                unknowns=["seeded PKE CPA in ROM with public matrix/noise/KG oracles",
                          "seeded PKE OW in QROM with auxiliary oracles",
                          "rejection-prefix PRF against quantum adversaries and public quantum J access",
                          "all substitutions of ideal oracles by concrete Keccak"], panels=panels)


def primary_source_records():
    return [dict(id="HHK17", title="A Modular Analysis of the Fujisaki-Okamoto Transformation",
                 url="https://people.inf.ethz.ch/dhofheinz/pdf/conf/tcc/HofheinzHK17.pdf",
                 cached_version="26 September 2017", pages=35,
                 sha256="33412e6927c288f40384d594fd21915dce0a755487489a0a5f7c1961a63df290",
                 read_scope="section 2.1 definitions/conventions; section 3.1-3.3 including table page 21"),
            dict(id="HHK21-erratum", title="Erratum to HHK17, 2 November 2021",
                 url="https://eprint.iacr.org/2017/604.pdf",
                 full_pdf_retrieved=False, full_pdf_sha256=None,
                 read_scope="primary indexed first-page erratum, independently checked twice; global ROM section 3.3 unchanged, individual theorem counting and rigidity corrected",
                 no_claim_of_reading_unretrieved_pages=True),
            dict(id="Hov21-thesis", title="Generic Constructions of Quantum-Resistant Cryptosystems",
                 url="https://doi.org/10.13154/294-7758", retrieved_copy="https://d-nb.info/1227710364/34",
                 cover_date="9 December 2020; thesis catalogued/published 2021", pages=189,
                 sha256="06fd15e5930057285c9c0101b2517b64df03a7e52169475365f7c050ff569ce9",
                 read_scope="Definitions pages 26,32; sections 2.1.1,2.1.3,2.1.4 including rigidity and corrected qPCO terms; normalization caveat noted"),
            dict(id="GYY25", title="Fujisaki-Okamoto Transformation under Average-Case Decryption Error: Tighter and More General Proofs with Applications to PQC",
                 url="https://eprint.iacr.org/2025/1641", retrieved_copy="https://eprint.iacr.asia/2025/1641.pdf",
                 pdf_creation_date="2025-09-30", pages=97,
                 sha256="408b2f6f880658b4026e19393ef2d6cd764255f823b0a5ec28538e40f14d34ff",
                 read_scope="Figure 7 pages 15-16, definitions appendix E pages 49-50, Theorem 22 and Remark 6 pages 96-97; ACWC constructions excluded"),
            dict(id="MS25", title="Provable decryption failure security for practical lattice-based PKE",
                 url="https://eprint.iacr.org/2025/1997", retrieved_copy="https://eprint.iacr.asia/2025/1997.pdf",
                 pdf_creation_date="2025-10-25", pages=31,
                 sha256="5bab9b2ca4b8a73e6c48ae05a2f5d6d2f14ae57b5558e0d3b3c775177b30a4e8",
                 read_scope="Figure 3.2 page 17, Figure 4.1-4.2 and Theorem 4.3 pages 22-27, applicability limitation page 27, Appendix A pages 30-31",
                 finite_numeric_bound_imported=False),
            dict(id="HHM22-v1", title="Failing gracefully: Decryption failures and the Fujisaki-Okamoto transform",
                 url="https://arxiv.org/abs/2203.10182v1", pages=52,
                 sha256="8ae9bc66b45d58c8ce055bae6978440211c532566b395dd03f8e8e682bb09a12",
                 read_scope="Section 6 and Theorem 10 pages 31-32, FFP-NG/FFP-NK distinction",
                 no_claim_to_be_latest_version=True)]


def freeze(output):
    output = Path(output).resolve()
    allowed = ROOT / "results/security"
    if not output.is_relative_to(allowed.resolve()) or output == allowed.resolve():
        raise ValueError("a new snapshot below results/security is required")
    if output.exists():
        raise ValueError("refusing to replace a security snapshot")
    output.mkdir(parents=True)
    sources = output / "sources"
    sources.mkdir()
    names = ["research/r1_security_bounds.py", "research/test_r1_security_bounds.py",
             "docs/SECURITE_CONCRETE_R1_M05.md", "crates/kem1536/src/dev_kem.rs",
             "crates/kem1536/src/engine_poly.rs", "docs/SPECIFICATION_DEV_Q7681_R1.md",
             "results/j2/run-004/correctness-certificate.json"]
    inputs = []
    for name in names:
        original = ROOT / name
        destination = sources / original.name
        shutil.copyfile(original, destination)
        inputs.append(dict(original=name, frozen=destination.relative_to(output).as_posix(), sha256=hash_file(original)))
    write_json(output / "bounds.json", make_report(load_certificate()))
    write_json(output / "source-anchors.json", primary_source_records())
    provenance = dict(schema="m05-security-provenance-v1",
                      git_base=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                      input_files=inputs, output_files={name: hash_file(output / name) for name in ("bounds.json", "source-anchors.json")},
                      external_pdfs_redistributed=False)
    write_json(output / "provenance.json", provenance)
    print(json.dumps(dict(snapshot=str(output), panels=6, bounds_sha256=provenance["output_files"]["bounds.json"])))


def verify(snapshot):
    snapshot = Path(snapshot).resolve()
    provenance = read_json(snapshot / "provenance.json")
    for record in provenance["input_files"]:
        path = (snapshot / record["frozen"]).resolve()
        if not path.is_relative_to(snapshot) or hash_file(path) != record["sha256"]:
            raise ValueError("frozen security source checksum mismatch")
    for name, expected in provenance["output_files"].items():
        if hash_file(snapshot / name) != expected:
            raise ValueError("frozen security output checksum mismatch")
    saved = read_json(snapshot / "bounds.json")
    if saved != make_report(load_certificate(snapshot / "sources/correctness-certificate.json")):
        raise ValueError("rational security budget replay mismatch")
    print(json.dumps(dict(snapshot=snapshot.name, rational_replay="passed", panels=len(saved["panels"]),
                          concrete_keccak_proof=False)))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument("--output", type=Path)
    choice.add_argument("--verify", type=Path)
    arguments = parser.parse_args()
    if arguments.output:
        freeze(arguments.output)
    elif arguments.verify:
        verify(arguments.verify)
    else:
        print(json.dumps(make_report(load_certificate()), indent=2))


if __name__ == "__main__":
    main()
