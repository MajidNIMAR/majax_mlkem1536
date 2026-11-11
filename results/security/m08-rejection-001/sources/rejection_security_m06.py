"""Exact ideal-RO bounds for R1's hidden-prefix rejection PRF.

The QROM constant is AHU Theorem 3's 2*q, also consistent with SXY's
August 2021 correction. No concrete SHAKE or complete KEM proof is asserted.
The keyed interface is classical; the public interface remains quantum.
"""

import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from r1_security_bounds import (display, expanded_sampler_delta, load_certificate,
                                qrom_ow_obligation, qrom_terms, rational)

ROOT = Path(__file__).resolve().parents[1]
TAG = b"KEM1536-DEV-Q7681-R1\0"
KEY_BITS = 256
CIPHERTEXT_BYTES = 2656


def natural(value, name):
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a nonnegative integer")
    return value


def even_key_bits(value):
    natural(value, "key_bits")
    if not value or value % 2:
        raise ValueError("this rational calculator requires a positive even key_bits")
    return value


def rejection_bounds(public_queries, keyed_queries, key_bits=KEY_BITS):
    """Probability GAP bounds, not a CCA bias or key-recovery probability.

    q counts all public global SHAKE queries, including coherent mixtures of
    domains and longer output prefixes. D counts classical indexed queries.
    No D factor is needed: the coupling changes the whole secret row at once.
    """
    q = natural(public_queries, "public_queries")
    d = natural(keyed_queries, "keyed_queries")
    bits = even_key_bits(key_bits)
    if not d:
        # With no indexed response the public oracle is random in both worlds.
        return dict(rom=Fraction(0), qrom=Fraction(0))
    return dict(rom=min(Fraction(1), Fraction(q, 1 << bits)),
                qrom=min(Fraction(1), Fraction(2 * q, 1 << (bits // 2))))


def query_limits_for_gap(gap, key_bits=KEY_BITS):
    """Sufficient q limits when D>0; not necessary attack thresholds."""
    gap = Fraction(gap)
    if not 0 <= gap < 1:
        raise ValueError("allocation gap must lie in [0,1)")
    bits = even_key_bits(key_bits)
    rom = gap * (1 << bits)
    qrom = gap * (1 << (bits // 2)) / 2
    return dict(rom_max_public_queries=rom.numerator // rom.denominator,
                qrom_max_public_queries=qrom.numerator // qrom.denominator)


def one_candidate_gap(key_bits, output_bits, distinct_ciphertexts=1):
    """Exact distinguishing GAP for one fixed candidate and t distinct inputs.

    The attacker spends t public + t keyed calls, checks all t output matches.
    A wrong candidate matches by chance with probability 2^(-t*output_bits).
    This diagnostic is not a generic upper bound on arbitrary adversaries.
    """
    bits = natural(key_bits, "key_bits")
    out = natural(output_bits, "output_bits")
    count = natural(distinct_ciphertexts, "distinct_ciphertexts")
    if not bits or not out or not count:
        raise ValueError("positive key_bits, output_bits and distinct_ciphertexts required")
    return Fraction(1, 1 << bits) * (1 - Fraction(1, 1 << (out * count)))


def hash_file(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def source_contract(path):
    """Check the narrow reviewed J interface; not a Rust verifier or RNG proof."""
    source = Path(path).read_text(encoding="utf-8")
    required = [
        'const TAG: &[u8] = b"KEM1536-DEV-Q7681-R1\\0";',
        'pub const CIPHERTEXT_BYTES: usize = 2656;',
        'pub const SHARED_SECRET_BYTES: usize = 32;',
        'h.update(TAG);', 'h.update(label);', 'h.update(p);',
        'h.finalize_xof().read(&mut out[..]);',
        'sk[PRIVATE_KEY_BYTES - 32..].copy_from_slice(z);',
        'random_bytes::<64>(|out| getrandom::fill(out).map_err(|_| Error::RandomnessUnavailable))?',
        'seeds[..32].try_into().expect("32 bytes")',
        'seeds[32..].try_into().expect("32 bytes")',
        'let fallback = xof::<32>(b"J\\0", &[&dk.0[offset + 32..], c.as_bytes()]);',
        '(*fallback).ct_select(&*good, c.as_bytes().ct_eq(&cp[..]))',
    ]
    missing = [item for item in required if item not in source]
    if missing:
        raise ValueError(f"the reviewed R1 rejection source contract changed: {missing}")
    return dict(profile="KEM1536-DEV-Q7681-R1", key_bits=KEY_BITS,
                ciphertext_bytes=CIPHERTEXT_BYTES, output_bits=256,
                public_j_prefix_hex=(TAG + b"J\0").hex(),
                j_input_bytes=len(TAG) + 2 + KEY_BITS // 8 + CIPHERTEXT_BYTES,
                noise_input_bytes=len(TAG) + 2 + 32 + 1,
                fixed_length_namespace_injective=True,
                checked_source_fragments=required,
                source_sha256=hash_file(path),
                scope="literal interface checks plus documented human review; not a source-level formal proof or an OS entropy proof")


def make_report(certificate_path):
    delta = expanded_sampler_delta(load_certificate(certificate_path))
    allocation = Fraction(1, 1 << 130)
    target = Fraction(1, 1 << 128)
    panels = []
    for bits in (None, 0, 16, 32, 64, 96, 128):
        q = 0 if bits is None else 1 << bits
        d = q
        bounds = rejection_bounds(q, d)
        terms = qrom_terms(delta, q, q, d)
        ow = qrom_ow_obligation(delta, q, q, d, target, bounds["qrom"])
        panels.append(dict(public_global_shake256_queries=q, keyed_classical_queries=d,
                           g512_queries_for_m05_panel=q,
                           epsilon_j_rom_upper=rational(bounds["rom"]),
                           epsilon_j_qrom_upper=rational(bounds["qrom"]),
                           m05_prf_allocation=rational(allocation),
                           m05_allocation_certified_by_this_qrom_bound=bounds["qrom"] <= allocation,
                           qrom_correction=display(terms["correction"]),
                           qrom_correction_coefficient=terms["correction_coefficient"],
                           qrom_known_additive_upper=display(bounds["qrom"] + terms["correction"]),
                           target_bias=rational(target),
                           target_certified_by_this_bound_with_ow_zero=(bounds["qrom"] + terms["correction"] <= target),
                           sufficient_ow_requirement=None if ow is None else display(ow),
                           full_ind_cca_bound_evaluated=False))
    return dict(schema="m06-r1-rejection-ideal-ro-v1", study_date="2026-11-10",
                study_timezone="Europe/Paris", key_bits=KEY_BITS,
                rejection_output_bits=256, ciphertext_bytes=CIPHERTEXT_BYTES,
                exact_correction_recipe="qrom_correction_coefficient * (1-2^-256) * archived certificate message_upper fraction",
                exact_ow_requirement_recipe="[(target_bias-epsilon_j_qrom_upper-qrom_correction)/(4*(2*g512+D+1))]^2 when residual>=0",
                advantage="absolute distinguishing probability gap in [0,1]; NOT |Pr[win]-1/2|",
                scope="single uniformly random independent z; global public SHAKE ideal bitstream oracle, classical indexed oracle, independent auxiliary domains",
                rom_formula="D=0: 0; otherwise min(1,q/2^256)",
                qrom_formula="D=0: 0; otherwise min(1,2*q/2^128)",
                q_counts_all_potentially_j_public_calls_of_prf_distinguisher=True,
                proven_other_namespace_calls_charged_to_auxiliary_resources=True,
                keyed_queries_already_counted_separately=True,
                coherent_namespace_multiplier=1,
                no_extra_ciphertext_or_output_collision_penalty=True,
                qrom_reference="AHU2018/904 Theorem3 pp11,25-28; constant agrees with SXY2017/1005 corrected Lemma2.2 (2021)",
                prf_allocation_limits_for_d_positive=query_limits_for_gap(allocation),
                one_candidate_one_ciphertext_gap=rational(one_candidate_gap(256, 256)),
                complete_concrete_shake_bound=False, complete_kem_proof=False,
                remaining=["seeded PKE CPA/OW with public quantum auxiliary oracles",
                           "complete FO theorem instantiation and ROM constants review",
                           "all substitutions of ideal oracles by concrete Keccak",
                           "tighter rejection bound if a smaller gap is required at large q"],
                panels=panels)


def primary_sources():
    return [dict(id="AHU19", title="Quantum Security Proofs Using Semi-classical Oracles",
                 url="https://eprint.iacr.org/2018/904", retrieved_copy="https://eprint.iacr.asia/2018/904.pdf",
                 cached_pdf_version="18 February 2019", pages=45,
                 pdf_sha256="a3b09922553b2138dc022db72035e8378c30cf27cfad312b1a45558bad03d69d",
                 read_scope="Theorem3 p11, auxiliary-oracle discussion p10, full proof pp25-28",
                 latest_notice="9 December 2021; primary indexed disclaimer limits flaw to FO AppendixB, main O2H results unaffected",
                 latest_full_pdf_retrieved=False),
            dict(id="SXY21-index", title="Tightly-Secure Key-Encapsulation Mechanism in the Quantum Random Oracle Model",
                 url="https://eprint.iacr.org/2017/1005.pdf",
                 version="August2021 correction; official notice last revision25August2021",
                 read_scope="official indexed Lemma2.2 proof AppendixC.1 p27 and correction footnote9",
                 corrected_constant="2*q*2^(-ell/2); NOT sqrt(2)*q*2^(-ell/2)",
                 full_corrected_pdf_retrieved=False, corrected_pdf_sha256=None,
                 older_mirror_pdf_retrieved="16May2018; excluded as proof for corrected constant",
                 older_mirror_sha256="97f6a84ff8ee7cb845b0adda6c66947635bdea1903fe2c5ad216639c5889b1bb"),
            dict(id="J25-v1", title="Nonadaptive One-Way to Hiding Implies Adaptive Quantum Reprogramming",
                 url="https://arxiv.org/abs/2511.16009v1", retrieved_copy="https://arxiv.org/pdf/2511.16009v1",
                 pdf_cover_date="21November2025", pages=24,
                 pdf_sha256="95609e630baf7fd7572591e5cdf2e4693d768dab51c8d2a095b9d120922d8965",
                 read_scope="section2 Theorems1-2 pp10-11, comparison with AHU and auxiliary-game interpretation",
                 no_tighter_adaptive_constant_imported=True),
            dict(id="GYY25", title="Fujisaki-Okamoto Transformation under Average-Case Decryption Error",
                 url="https://eprint.iacr.org/2025/1641", pdf_creation_date="30September2025", pages=97,
                 pdf_sha256="408b2f6f880658b4026e19393ef2d6cd764255f823b0a5ec28538e40f14d34ff",
                 read_scope="Theorem22 p96, Figure7 pp15-16 and Def4 p49, as frozen in M05")]


def freeze(output):
    output = Path(output).resolve()
    allowed = (ROOT / "results/security").resolve()
    if not output.is_relative_to(allowed) or output == allowed:
        raise ValueError("a new snapshot below results/security is required")
    if output.exists():
        raise ValueError("refusing to overwrite a security snapshot")
    source_names = ["research/rejection_security_m06.py", "research/test_rejection_security_m06.py",
                    "docs/REJET_IMPLICITE_R1_M06.md", "research/r1_security_bounds.py",
                    "docs/SECURITE_CONCRETE_R1_M05.md", "docs/PROTOCOLE_M06_MOTEUR.md",
                    "docs/SPECIFICATION_DEV_Q7681_R1.md", "crates/kem1536/src/dev_kem.rs",
                    "results/j2/run-004/correctness-certificate.json"]
    # Verify readable inputs/contract before creating the append-only snapshot.
    before = {name: hash_file(ROOT / name) for name in source_names}
    contract = source_contract(ROOT / "crates/kem1536/src/dev_kem.rs")
    report = make_report(ROOT / "results/j2/run-004/correctness-certificate.json")
    output.mkdir(parents=True)
    sources = output / "sources"
    sources.mkdir()
    copied = []
    for name in source_names:
        target = sources / Path(name).name
        shutil.copyfile(ROOT / name, target)
        if hash_file(target) != before[name] or hash_file(ROOT / name) != before[name]:
            raise ValueError(f"input changed during snapshot: {name}")
        copied.append(dict(original=name, frozen="sources/" + target.name, sha256=before[name]))
    write_json(output / "rejection-bounds.json", report)
    write_json(output / "source-contract.json", contract)
    write_json(output / "source-anchors.json", primary_sources())
    outputs = [{"path": name, "sha256": hash_file(output / name)} for name in
               ("rejection-bounds.json", "source-contract.json", "source-anchors.json")]
    git_base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    write_json(output / "provenance.json", dict(schema="m06-rejection-provenance-v1",
               date="2026-11-10", timezone="Europe/Paris", git_base=git_base,
               source_snapshot_contains_working_tree_bytes=True,
               source_scope="J interface; concurrent M06 arithmetic changes are not security evidence",
               concrete_keccak_proof=False, inputs=copied, outputs=outputs))
    return verify(output)


def verify(output):
    output = Path(output).resolve()
    provenance = read_json(output / "provenance.json")
    if provenance.get("schema") != "m06-rejection-provenance-v1":
        raise ValueError("unknown provenance schema")
    for entry in provenance["inputs"]:
        path = (output / entry["frozen"]).resolve()
        if not path.is_relative_to(output) or hash_file(path) != entry["sha256"]:
            raise ValueError(f"frozen source mismatch: {entry['frozen']}")
    for entry in provenance["outputs"]:
        path = (output / entry["path"]).resolve()
        if not path.is_relative_to(output) or hash_file(path) != entry["sha256"]:
            raise ValueError(f"output mismatch: {entry['path']}")
    expected = make_report(output / "sources/correctness-certificate.json")
    if read_json(output / "rejection-bounds.json") != expected:
        raise ValueError("the rational security report does not replay")
    if read_json(output / "source-contract.json") != source_contract(output / "sources/dev_kem.rs"):
        raise ValueError("the reviewed J source contract does not replay")
    if read_json(output / "source-anchors.json") != primary_sources():
        raise ValueError("primary-source anchors differ")
    return dict(snapshot=str(output), rational_replay="passed", panels=len(expected["panels"]),
                source_contract="passed", ideal_rejection_prf_bounded=True,
                concrete_keccak_proof=False, complete_kem_proof=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--output", type=Path, help="freeze a new append-only result directory")
    group.add_argument("--verify", type=Path, help="check hashes and replay a frozen result")
    args = parser.parse_args()
    if args.output:
        result = freeze(args.output)
    elif args.verify:
        result = verify(args.verify)
    else:
        result = make_report(ROOT / "results/j2/run-004/correctness-certificate.json")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
