"""M09 classical ideal-oracle hybrid for hidden seeded noise in the R1 PKE.

This is a bounded sub-lemma, not an IND-CCA proof. The public matrix remains
seeded, query budgets belong to the PKE distinguisher, and no quantum or
concrete-Keccak substitution is supplied. All arithmetic is rational.
"""
import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
PROFILE = "KEM1536-DEV-Q7681-R1"
BASELINE_SHA = "b39c2fdfcdd7c22634162a2c451213a6c4309b27524a82069f37903653e12334"
SOURCE_NAMES = ("m09_security_noise.py", "test_m09_security_noise.py", "SECURITE_M09.md", "dev_kem.rs")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def natural(value, name):
    require(type(value) is int and value >= 0, name + " must be a nonnegative integer")
    return value


def hybrid_gap(kg_queries, noise_seed_queries, seed_bits=256):
    """One hidden KG address and two hidden N labels; one CPA challenge.

    In the fresh-noise game the three labels are independent uniform and
    unobservable. KG and N query sets may be adaptive but are independent of
    these unused labels. Distinct seed counts are bounded by the supplied
    integers. The collision sigma=rseed is charged even at zero queries.
    """
    natural(seed_bits, "seed_bits")
    require(1 <= seed_bits <= 4096, "seed_bits must lie in [1,4096]")
    kg_queries = natural(kg_queries, "kg_queries")
    noise_seed_queries = natural(noise_seed_queries, "noise_seed_queries")
    space = 1 << seed_bits
    g, n = min(kg_queries, space), min(noise_seed_queries, space)
    return 1 - Fraction((space - g) * (space - n) * (space - n - 1), space**3)


def union_gap(kg_queries, noise_seed_queries, seed_bits=256):
    natural(seed_bits, "seed_bits")
    require(1 <= seed_bits <= 4096, "seed_bits must lie in [1,4096]")
    natural(kg_queries, "kg_queries")
    natural(noise_seed_queries, "noise_seed_queries")
    return min(Fraction(1), Fraction(kg_queries + 2 * noise_seed_queries + 1, 1 << seed_bits))


def symmetric_query_limit(target, coefficient=6, seed_bits=256):
    """Maximum common q for coefficient*hybrid_gap(q,q)<=target.

    This allocates the ENTIRE target to this sub-term alone. It is not the
    query limit of the full KEM: other terms and the resource map still apply.
    """
    require(isinstance(target, (int, Fraction)) and not isinstance(target, bool), "exact target required")
    target = Fraction(target)
    require(0 <= target <= Fraction(1, 2), "target bias outside [0,1/2]")
    natural(coefficient, "coefficient")
    require(coefficient > 0, "positive coefficient required")
    if coefficient * hybrid_gap(0, 0, seed_bits) > target:
        return None
    low, high = 0, 1 << seed_bits
    while low + 1 < high:
        mid = (low + high)//2
        if coefficient * hybrid_gap(mid, mid, seed_bits) <= target:
            low = mid
        else:
            high = mid
    return low


def enumerate_bad(space, kg_set, noise_set):
    """Independent finite counter: enumerate labels, do not evaluate the formula."""
    require(type(space) is int and space >= 2, "space must be an integer >=2")
    kg_set, noise_set = set(kg_set), set(noise_set)
    require(kg_set <= set(range(space)) and noise_set <= set(range(space)), "query outside alphabet")
    bad = 0
    for d in range(space):
        for sigma in range(space):
            for coins in range(space):
                bad += d in kg_set or sigma in noise_set or coins in noise_set or sigma == coins
    return Fraction(bad, space**3)


def finite_checks():
    """Exact counting over all count pairs and non-power-of-two alphabets."""
    panels = []
    for space in range(2, 10):
        for g in range(space + 1):
            for n in range(space + 1):
                observed = enumerate_bad(space, range(g), range(n))
                expected = 1 - Fraction((space-g)*(space-n)*(space-n-1), space**3)
                require(observed == expected, "finite label counting failed")
                panels.append((space, g, n))
    return dict(alphabets=list(range(2, 10)), count_panels=len(panels),
                enumerated_label_triples=sum(space**3 for space, _, _ in panels),
                all_equal=True, scope="counting the bad event, not enumerating R1 or general adversaries")


def fresh_rom_obligation(target, known_additive, kg_queries, noise_seed_queries):
    """Algebraic substitution into the conservative M05 coefficient-six ledger.

    known_additive is the EXACT already justified correction+guessing ledger
    supplied by the caller. Budgets MUST be those of the CPA reduction, not
    silently those of the original CCA adversary. No resource map is inferred.
    """
    require(isinstance(target, (int, Fraction)) and not isinstance(target, bool), "exact target required")
    require(isinstance(known_additive, (int, Fraction)) and not isinstance(known_additive, bool),
            "exact additive term required")
    target, known_additive = Fraction(target), Fraction(known_additive)
    require(0 <= target <= Fraction(1, 2), "target is a CPA/CCA bias in [0,1/2]")
    require(0 <= known_additive, "negative additive term")
    residue = target - known_additive - 6 * hybrid_gap(kg_queries, noise_seed_queries)
    return None if residue < 0 else residue / 6


def deterministic_cbd_distance_lower(seed_bits=256, polynomials=12):
    """Support-counting lower bound for a FIXED deterministic sampler.

    CBD(3)'s maximum coefficient mass is 20/64=5/16; a seed image has at
    most 2^seed_bits points in the vector of 256*polynomials coefficients.
    This diagnoses statistical substitution; it is not an attack advantage
    bound for an efficient adversary and does not contradict an RO average.
    """
    natural(seed_bits, "seed_bits")
    natural(polynomials, "polynomials")
    require(seed_bits <= 4096 and polynomials <= 64, "diagnostic size limit")
    return max(Fraction(0), 1 - (1 << seed_bits) * Fraction(5, 16)**(256 * polynomials))


def rational(value):
    value = Fraction(value)
    return dict(numerator=str(value.numerator), denominator=str(value.denominator))


def source_contract(source):
    data = Path(source).read_bytes()
    require(hashlib.sha256(data).hexdigest() == BASELINE_SHA, "study baseline source differs")
    text = data.decode("utf-8-sig")
    anchors = [
        'const TAG: &[u8] = b"KEM1536-DEV-Q7681-R1\\0";',
        'let expanded = derive(b"KG\\0", &[d, &[6]]);',
        'let (rho, sigma) = expanded.split_at(32);',
        'let bytes = xof::<192>(b"N\\0", &[seed, &[nonce]]);',
        'noise_into(sigma, i as u8, &mut coefficient);',
        'noise_into(sigma, 6 + i as u8, &mut coefficient);',
        'noise_into(seed, i as u8, &mut coefficient);',
        'noise_into(seed, 6 + i as u8, &mut coefficient);',
        'noise_into(seed, 12, &mut coefficient);',
        'let mut h = Shake128::default();',
        'h.update(b"A\\0");',
        'let c = pke_encrypt(ek, m, &material[32..]);',
    ]
    for anchor in anchors:
        require(anchor in text, "missing baseline anchor: " + anchor)
    return dict(sha256=BASELINE_SHA, literal_anchors=len(anchors),
                new_implementation_certified=False,
                scope="M08 baseline byte contract; a later realization needs its own bridge")


def make_report(source):
    panels = []
    for bits in (0, 32, 64, 96, 128, 192, 256, 300):
        q = 0 if bits == 0 else 1 << bits
        gap = hybrid_gap(q, q)
        panels.append(dict(query_exponent=None if q == 0 else bits,
                           distinct_kg_inputs_upper=q, distinct_noise_seed_labels_upper=q,
                           hybrid_gap=rational(gap), union_upper=rational(union_gap(q, q)),
                           six_times_hybrid_gap=rational(6*gap)))
    diagnostic = deterministic_cbd_distance_lower()
    return dict(schema="m09-r1-classical-hidden-noise-v1", study_date="2026-11-16",
                profile=PROFILE, seed_bits=256, source_contract=source_contract(source),
                advantage="absolute CPA bias |Pr[win]-1/2|; difference between games <= bad-event probability",
                formula="1-(1-min(q_KG,M)/M)*(M-min(q_N,M))*(M-min(q_N,M)-1)/M^2; M=2^256",
                fresh_pke="same rho-seeded public matrix and compression; independent ideal CBD(3) noise",
                one_classical_pke_challenge=True, quantum_bound_provided=False,
                ideal_KG_and_N_independent=True, labels_unrevealed=True,
                all_auxiliary_oracles_independent_of_hidden_labels_in_fresh_game=True,
                queries_are_of_pke_reduction_not_original_cca_adversary=True,
                oracle_work="lazy public tables plus at most 25 192-byte N outputs and one 64-byte KG output in coupling",
                noise_output_count=25, noise_bytes=4800, kg_bytes=64,
                finite_checks=finite_checks(), panels=panels,
                hybrid_only_symmetric_query_limits=[dict(
                    target_bias=rational(Fraction(1, 1 << exponent)),
                    cpa_reduction_query_limit=symmetric_query_limit(Fraction(1, 1 << exponent)),
                    coefficient=6, other_terms_budgeted=False)
                    for exponent in (128, 192, 224, 256)],
                fixed_sampler_support_diagnostic=dict(
                    polynomials=12, coefficients=3072, maximum_cbd3_mass="5/16",
                    complement_upper_recipe="2^256*(5/16)^3072",
                    distance_lower_exceeds_one_minus_2_pow_minus_4898=diagnostic > 1-Fraction(1, 1<<4898),
                    efficient_distinguisher_constructed=False),
                complete_C01_closed=False,
                remaining=["fresh-CBD PKE with rho-seeded public matrix CPA advantage and resources",
                           "classical CPA reduction query/resource map inside full FO proof",
                           "QROM seeded-PKE OW advantage and quantum hidden-point argument",
                           "replacement of all ideal oracles by concrete Keccak",
                           "independent review of the whole proof and final normalization constants"])


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2)+"\n", encoding="utf-8")


def create(output):
    output = Path(output).resolve()
    require(not output.exists(), "refuse to overwrite an existing capsule")
    baseline = ROOT / "artifacts/generated/m08-001/candidate-source/crates/kem1536/src/dev_kem.rs"
    require(baseline.is_file(), "frozen M08 source required")
    source_contract(baseline)
    output.mkdir(parents=True)
    sources = output / "sources"
    sources.mkdir()
    for name in SOURCE_NAMES:
        origin = baseline if name == "dev_kem.rs" else ROOT / ("docs" if name.endswith(".md") else "research") / name
        shutil.copyfile(origin, sources / name)
    write_json(output / "report.json", make_report(sources / "dev_kem.rs"))
    (output / "README.md").write_text(
        "# M09 — Hybridation classique des bruits expansés\n\n"
        "Étude conditionnelle du 16 novembre 2026. Le code M08 est conservé comme contrat de référence.\n"
        "Le lemme couvre un défi CPA classique avec oracles KG/N idéaux indépendants.\n"
        "La matrice reste issue de rho. Ni QROM, ni SHAKE concret, ni C01 complet ne sont fermés.\n\n"
        "Rejeu sans compilation ni réseau : `python -B research/m09_security_noise.py verify "
        "--output results/security/m09-001`. Les sources et tests sont copiés dans sources/.\n",
        encoding="utf-8")
    files = {p.relative_to(output).as_posix(): dict(sha256=sha(p), bytes=p.stat().st_size)
             for p in sorted(output.rglob("*")) if p.is_file()}
    write_json(output / "provenance.json", dict(schema="m09-security-capsule-v1", files=files))
    return verify(output)


def verify(output):
    output = Path(output).resolve()
    manifest = json.loads((output / "provenance.json").read_text(encoding="utf-8"))
    actual = {p.relative_to(output).as_posix() for p in output.rglob("*") if p.is_file()}
    require(actual == set(manifest["files"]) | {"provenance.json"}, "capsule inventory differs")
    for name, item in manifest["files"].items():
        path = (output / name).resolve()
        require(path.is_relative_to(output), "unsafe capsule path")
        require(path.stat().st_size == item["bytes"] and sha(path) == item["sha256"], "capsule member differs: "+name)
    recorded = json.loads((output / "report.json").read_text(encoding="utf-8"))
    require(recorded == make_report(output / "sources/dev_kem.rs"), "recalculated report differs")
    return dict(status="PASS", members=len(manifest["files"]), finite_checks=recorded["finite_checks"],
                provenance_sha256=sha(output / "provenance.json"), complete_C01_closed=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("create", "verify"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(create(args.output) if args.command == "create" else verify(args.output), sort_keys=True))


if __name__ == "__main__":
    main()
