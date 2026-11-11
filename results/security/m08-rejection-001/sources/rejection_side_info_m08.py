"""M08 ideal-J gap bounds with classical side information about its key.

This generalizes the hypothesis of M06; it does not tighten its uniform-key
bound, certify imported-key entropy, concrete SHAKE, quantum side information,
or the complete KEM. Snapshot replay performs no experiments or network calls.
"""
import argparse
from fractions import Fraction
import hashlib
import json
from math import isqrt
from pathlib import Path
import shutil
import subprocess

from rejection_security_m06 import source_contract

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "KEM1536-DEV-Q7681-R1"
KEY_BITS = 256
SOURCE_NAMES = ("rejection_side_info_m08.py", "test_rejection_side_info_m08.py",
                "rejection_security_m06.py", "r1_security_bounds.py",
                "REJET_ET_INFORMATION_LATERALE_M08.md", "dev_kem.rs")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def natural(value, name):
    require(type(value) is int and value >= 0, name + " must be a nonnegative integer")
    return value


def probability(value):
    require(not isinstance(value, bool) and isinstance(value, (int, Fraction)),
            "guessing probability must be an exact integer or Fraction")
    value = Fraction(value)
    require(0 < value <= 1, "guessing probability must lie in (0,1]")
    return value


def guessing_probability(joint_counts):
    """Compute sum_e max_z Pr[E=e,Z=z] from a finite nonempty count table.

    Rows denote classical E values, columns key labels. Zero-count columns
    are allowed, but each declared row must have positive mass. This only
    computes the supplied distribution; it cannot inspect an application's
    secret generation or the adversary's information.
    """
    require(isinstance(joint_counts, (list, tuple)) and len(joint_counts) > 0,
            "a nonempty joint count table is required")
    width = None
    total, maxima = 0, 0
    for row in joint_counts:
        require(isinstance(row, (list, tuple)) and len(row) > 0, "nonempty count rows required")
        width = len(row) if width is None else width
        require(len(row) == width, "joint count rows must have equal key alphabets")
        for count in row:
            natural(count, "joint count")
        mass = sum(row)
        require(mass > 0, "each side-information row must have positive mass")
        total += mass
        maxima += max(row)
    return Fraction(maxima, total)


def sqrt_interval(value, precision_bits=256):
    """Outward dyadic sqrt interval, certified by integer inequalities."""
    value = probability(value)
    natural(precision_bits, "precision_bits")
    require(1 <= precision_bits <= 4096, "precision_bits must lie in [1,4096]")
    scale = 1 << precision_bits
    scaled_numerator = value.numerator * scale * scale
    lower = isqrt(scaled_numerator // value.denominator)
    upper = lower if lower * lower * value.denominator == scaled_numerator else lower + 1
    return Fraction(lower, scale), Fraction(upper, scale)


def gap_bounds(public_queries, keyed_queries, p_guess_upper, precision_bits=256):
    """Probability-gap upper bounds; q is global public-oracle query budget.

    Hypotheses: E is classical and (Z,E) is independent of the J-domain
    ideal H_J and ideal R. Other auxiliary domains are independent of H_J/R
    and do not reveal further key information conditional on E. Thus,
    conditional on E the complete ideal view is independent of Z. The indexed
    interface receives classical queries. p_guess_upper upper-bounds
    sum_e Pr[E=e] max_z Pr[Z=z|E=e]. No D multiplier is charged.
    """
    q = natural(public_queries, "public_queries")
    d = natural(keyed_queries, "keyed_queries")
    p = probability(p_guess_upper)
    require(p >= Fraction(1, 1 << KEY_BITS), "a 256-bit key cannot have guessing probability below 2^-256")
    _, root_upper = sqrt_interval(p, precision_bits)
    if q == 0 or d == 0:
        return dict(rom=Fraction(0), qrom=Fraction(0))
    return dict(rom=min(Fraction(1), q * p),
                qrom=min(Fraction(1), 2 * q * root_upper))


def rational(value):
    value = Fraction(value)
    return dict(numerator_hex=hex(value.numerator), denominator_hex=hex(value.denominator))


def make_report(source_path):
    contract = source_contract(source_path)
    panels = []
    for bits in (0, 64, 128, 192, 256):
        p = Fraction(1, 1 << bits)
        lower, upper = sqrt_interval(p)
        for q_bits in (32, 64):
            result = gap_bounds(1 << q_bits, 1, p)
            panels.append(dict(conditional_min_entropy_bits_at_least=bits,
                               guessing_probability_upper=rational(p),
                               public_global_queries=1 << q_bits, keyed_classical_queries=1,
                               epsilon_j_rom_upper=rational(result["rom"]),
                               epsilon_j_qrom_upper=rational(result["qrom"]),
                               sqrt_interval=dict(lower=rational(lower), upper=rational(upper))))
    no_indexed = gap_bounds(1 << 256, 0, Fraction(1))
    toy = [[3, 1, 0], [0, 1, 3]]
    return dict(schema="m08-j-classical-side-information-v1", profile=PROFILE,
                source_contract=contract, panels=panels,
                no_indexed_query=dict(public_global_queries=1 << 256, keyed_classical_queries=0,
                                      rom=rational(no_indexed["rom"]), qrom=rational(no_indexed["qrom"])),
                finite_distribution=dict(joint_counts=toy, exact_guessing_probability=rational(guessing_probability(toy))),
                probability_convention="absolute distinguishing probability gap, not CCA guessing bias",
                assumptions=["classical side information E", "J-domain H_J and R independent of (E,Z) and auxiliary ideal domains",
                             "conditional on E the ideal view is independent of Z",
                             "all public domain/coherent-prefix queries included in q",
                             "only classical indexed-function queries",
                             "p_guess_upper bounds average posterior maximum, not Shannon entropy"],
                uniform_256_recovers_m06=True, import_format_checks_prove_entropy=False,
                unknown_imported_key_entropy_is_certified=False,
                quantum_side_information_covered=False, concrete_shake_security_proved=False,
                full_kem_security_proved=False, c01_closed=False,
                scope="Conditional extension of the existing ideal-J bound. Arithmetic and finite fixtures do not prove application entropy or a general quantum adversary theorem by enumeration.")


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
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def freeze(output):
    output = output.resolve()
    require(output.parent == (ROOT / "results/security").resolve() and not output.exists(),
            "a new direct results/security snapshot is required")
    sources = [Path(__file__).resolve(), ROOT / "research/test_rejection_side_info_m08.py",
               ROOT / "research/rejection_security_m06.py", ROOT / "research/r1_security_bounds.py",
               ROOT / "docs/REJET_ET_INFORMATION_LATERALE_M08.md", ROOT / "crates/kem1536/src/dev_kem.rs"]
    before = {path.name: sha(path) for path in sources}
    report = make_report(sources[-1])
    output.mkdir()
    (output / "sources").mkdir()
    for path in sources:
        shutil.copyfile(path, output / "sources" / path.name)
    require(all(sha(path) == before[path.name] == sha(output / "sources" / path.name) for path in sources),
            "side-info input changed during source capture")
    require(report == make_report(output / "sources/dev_kem.rs"), "copied rejection source differs before sealing")
    save(output / "bounds.json", report)
    files = {path.relative_to(output).as_posix(): sha(path) for path in sorted(output.rglob("*")) if path.is_file()}
    save(output / "provenance.json", dict(schema="m08-j-side-info-provenance-v1",
         source_base_git=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
         output_sha256=files, new_fuzz_or_benchmark_performed=False))
    return verify(output)


def verify(snapshot):
    snapshot = snapshot.resolve()
    provenance = read(snapshot / "provenance.json")
    require(provenance["schema"] == "m08-j-side-info-provenance-v1", "unknown M08 side-info schema")
    expected = provenance["output_sha256"]
    require(set(expected) == {"bounds.json"} | {"sources/" + name for name in SOURCE_NAMES}
            and provenance["new_fuzz_or_benchmark_performed"] is False,
            "M08 side-info required source inventory or scope differs")
    require({path.relative_to(snapshot).as_posix() for path in snapshot.rglob("*") if path.is_file()}
            == set(expected) | {"provenance.json"}, "M08 side-info inventory differs")
    for name, checksum in expected.items():
        path = (snapshot / name).resolve()
        require(path.is_relative_to(snapshot) and sha(path) == checksum, "M08 side-info source/output differs")
    saved = read(snapshot / "bounds.json")
    require(saved == make_report(snapshot / "sources/dev_kem.rs"), "M08 side-info rational replay differs")
    return dict(profile=PROFILE, files_verified=len(expected), panels=len(saved["panels"]),
                rational_replay=True, quantum_side_information_covered=False,
                concrete_shake_security_proved=False, c01_closed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group()
    choice.add_argument("--freeze", type=Path)
    choice.add_argument("--verify", type=Path)
    args = parser.parse_args()
    result = (freeze(args.freeze) if args.freeze else verify(args.verify) if args.verify else
              make_report(ROOT / "crates/kem1536/src/dev_kem.rs"))
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
