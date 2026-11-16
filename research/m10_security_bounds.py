"""Exact composition ledgers for the R1 KEM in ideal ROM/QROM games.

Inputs epsilon6/epsilon7 are MLWE distinguishing ADVANTAGES with explicit
resources, never inverses of lattice-estimator work factors. Every returned
bound remains conditional; this module cannot certify concrete SHAKE or C01.
"""
from fractions import Fraction
from math import isqrt

from m10_security_sampler import matrix_simulation_gap, natural, require
from m10_security_resources import rom_resource_envelope


def probability(value, name):
    require(type(value) is int or isinstance(value, Fraction), name + " must be exact")
    value = Fraction(value)
    require(0 <= value <= 1, name + " must lie in [0,1]")
    return value


def seed_space(seed_bits):
    natural(seed_bits, "seed_bits", 4096)
    require(seed_bits > 0, "positive seed entropy required")
    return 1 << seed_bits


def sqrt_interval(value, precision_bits=512):
    """Dyadic square-root enclosure, valid for all nonnegative rationals."""
    require(type(value) is int or isinstance(value, Fraction), "exact radicand required")
    value = Fraction(value)
    require(value >= 0, "negative radicand")
    natural(precision_bits, "precision_bits", 8192)
    require(precision_bits > 0, "positive precision required")
    scale = 1 << precision_bits
    squared = value.numerator * scale * scale
    lower = isqrt(squared // value.denominator)
    upper = lower if lower * lower * value.denominator == squared else lower + 1
    return Fraction(lower, scale), Fraction(upper, scale)


def noise_gap_rom(kg_queries, noise_seed_queries, seed_bits=256):
    """M09 exact classical hidden-label/collision count, restated standalone."""
    space = seed_space(seed_bits)
    g = min(natural(kg_queries, "kg_queries"), space)
    n = min(natural(noise_seed_queries, "noise_seed_queries"), space)
    return 1 - Fraction((space-g)*(space-n)*(space-n-1), space**3)


def noise_gap_qrom(kg_queries, noise_queries, seed_bits=256):
    """BBBV-style norm hybrid at ONE hidden KG point and TWO hidden N rows.

    The fresh game's unused names are independent of its entire view. The
    collision of the two N labels costs 1/M. No measurements of the real
    adversary's query registers are made. Counts belong to the CPA reduction.
    This is intentionally a conservative, generally non-tight QROM bound.
    """
    space = seed_space(seed_bits)
    g, n = natural(kg_queries, "kg_queries"), natural(noise_queries, "noise_queries")
    kg_root = sqrt_interval(Fraction(1, space))[1]
    noise_root = sqrt_interval(Fraction(2, space))[1]
    value = Fraction(1, space) + 2*g*kg_root + 2*n*noise_root
    return min(Fraction(1), value)


def pke_cpa_bound(model, epsilon6, epsilon7, kg_queries, noise_queries,
                  preseed_queries=0, word_limit=512, seed_bits=256):
    """Two explicit MLWE hybrids plus seeded-noise and matrix simulations.

    Four matrix gaps conservatively cover the real/uniform branch of each
    of two reductions. Matrix QROM programming is qualified only BEFORE
    any query made by the CPA distinguisher; quantum preprocessing is not
    covered by a classical preseed collision count.
    """
    require(model in ("ROM", "QROM"), "unknown oracle model")
    epsilon6, epsilon7 = probability(epsilon6, "epsilon6"), probability(epsilon7, "epsilon7")
    matrix = matrix_simulation_gap(preseed_queries=preseed_queries, word_limit=word_limit, seed_bits=seed_bits)
    if model == "QROM":
        require(preseed_queries == 0, "QROM matrix simulator is set up before any adversary query")
        noise = noise_gap_qrom(kg_queries, noise_queries, seed_bits)
    else:
        noise = noise_gap_rom(kg_queries, noise_queries, seed_bits)
    matrix_term = 4 * matrix["total_gap"]
    return dict(epsilon6=epsilon6, epsilon7=epsilon7, seeded_noise=noise,
                matrix_simulation=matrix_term, matrix_gap_branch_count=4,
                cpa_bias_upper=min(Fraction(1, 2), epsilon6+epsilon7+noise+matrix_term),
                model=model, concrete_primitive_security_proved=False, C01_closed=False)


def ow_from_cpa(cpa_bias_upper, message_bits=256):
    """Message recovery <=2*CPA_bias+1/|M|, including a quantum inverter."""
    value = probability(cpa_bias_upper, "cpa_bias_upper")
    require(value <= Fraction(1, 2), "CPA input is a bias")
    return min(Fraction(1), 2*value + Fraction(1, seed_space(message_bits)))


def fo_coordinates(public_g512, public_shake256, decapsulations):
    g, j, d = (natural(public_g512, "public_g512"), natural(public_shake256, "public_shake256"),
               natural(decapsulations, "decapsulations"))
    # The historical HHK/M05 classical ledger includes implicit calls.
    qro = 2*g+j+3*d+2
    # Two queries per coordinate for coherent target-namespace dispatch.
    qf = qk = 2*g+d+1
    return dict(public_g512=g, public_shake256=j, decapsulations=d,
                inclusive_classical_qro=qro, quantum_f=qf, quantum_k=qk)


def rom_cca_ledger(delta, cpa_bias_upper, public_g512, public_shake256,
                   decapsulations, rejection_public_queries, seed_bits=256):
    """Conservative M05 ROM composition + a separately charged J hybrid.

    The additional J charge is conservative, not a claimed tightening of
    the historical HHK constant-six ledger or a re-derivation of HHK.
    """
    delta, cpa = probability(delta, "delta"), probability(cpa_bias_upper, "cpa_bias_upper")
    require(cpa <= Fraction(1, 2), "CPA input is a bias")
    q = fo_coordinates(public_g512, public_shake256, decapsulations)
    space = seed_space(seed_bits)
    rejection = Fraction(0) if q["decapsulations"] == 0 else min(
        Fraction(1), Fraction(natural(rejection_public_queries, "rejection_public_queries"), space))
    correction = (2*q["inclusive_classical_qro"]+q["decapsulations"])*delta
    guessing = Fraction(3*q["inclusive_classical_qro"], space)
    total = rejection+6*cpa+correction+guessing
    return dict(queries=q, rejection_upper=rejection, pke_term=6*cpa,
                correction=correction, message_guessing=guessing,
                upper=min(Fraction(1, 2), total), C01_closed=False)


def rom_cca_counted(delta, epsilon6, epsilon7, public_g512, public_shake256,
                    decapsulations, public_shake128=0, public_hash256=0, word_limit=512):
    """M10 ROM route with the classical CPA query map actually substituted.

    The deliberately rounded envelope 8*(g+j+D+1) dominates the counted
    correctness and message-guess terms, including challenge/implicit calls.
    Coefficient six conservatively covers the normalization-corrected two
    CPA branches (four). No second run of A or sum of all hybrids is credited.
    """
    delta=probability(delta,"delta")
    resources=rom_resource_envelope(public_g512,public_shake256,public_shake128,
                                    public_hash256,decapsulations,word_limit=word_limit)
    pke=pke_cpa_bound("ROM",epsilon6,epsilon7,resources["KG_queries_max"],
                       resources["N_queries_max"],word_limit=word_limit)
    total_calls=public_g512+public_shake256+decapsulations+1
    coefficient=8*total_calls
    correction=coefficient*delta
    guessing=Fraction(coefficient,1<<256)
    rejection=Fraction(0) if decapsulations==0 else min(Fraction(1),Fraction(public_shake256,1<<256))
    return dict(resources=resources,correctness_coefficient=coefficient,correction=correction,
        message_guessing=guessing,rejection_upper=rejection,pke=pke,
        upper=min(Fraction(1,2),6*pke["cpa_bias_upper"]+correction+guessing+rejection),
        classical_CPA_oracle_count_map_supplied=True,
        concrete_gate_cost_or_MLWE_advantage_calibration_supplied=False,C01_closed=False)


def qrom_gyy_ledger(delta, cpa_bias_upper, public_g512, public_shake256,
                    decapsulations, rejection_public_queries, seed_bits=256):
    delta, cpa = probability(delta, "delta"), probability(cpa_bias_upper, "cpa_bias_upper")
    q = fo_coordinates(public_g512, public_shake256, decapsulations)
    space = seed_space(seed_bits)
    rejection = Fraction(0) if q["decapsulations"] == 0 else min(
        Fraction(1), 2*natural(rejection_public_queries, "rejection_public_queries")*sqrt_interval(Fraction(1, space))[1])
    ow = ow_from_cpa(cpa, seed_bits)
    coefficient = 2*(q["quantum_f"]+q["quantum_k"])
    correction = 16*(q["quantum_f"]+1)**2*delta
    ow_term = coefficient*sqrt_interval(ow)[1]
    return dict(queries=q, ow_probability_upper=ow, rejection_upper=rejection,
                ow_sqrt_coefficient=coefficient, ow_term=ow_term, correction=correction,
                upper=min(Fraction(1, 2), rejection+ow_term+correction),
                resource_scope="CPA and PRF input budgets must cover constructed reductions; no implicit substitution",
                concrete_primitive_security_proved=False, C01_closed=False)


def gyy_message_floor(public_g512, public_shake256, decapsulations, seed_bits=256):
    """Lower bound on THIS proof ledger from the trivial uniform-message guess.

    This is not a lower bound on a successful CCA attack. It refutes the
    possibility of certifying some targets with the particular OW theorem.
    """
    q = fo_coordinates(public_g512, public_shake256, decapsulations)
    coefficient = 2*(q["quantum_f"]+q["quantum_k"])
    lower, upper = sqrt_interval(Fraction(1, seed_space(seed_bits)))
    return dict(lower=coefficient*lower, upper=coefficient*upper,
                scope="irreducible term of the selected OW proof bound, not a CCA attack")


def mre_alternative_ledger(delta, cpa_bias_upper, d_h, d_g, width,
                           rejection_upper, seed_bits=256):
    """GLX2024 Corollary1 for the (m,c)-key implicit variant, with intervals.

    R1's message-only key needs the BHHP19 Theorem5 graph simulation first.
    Its coherent encryption, oracle, reversible-workspace and preprocessing
    costs MUST be covered by the supplied budgets. This function refuses to
    describe the alternative as an already resource-qualified R1 theorem.
    """
    delta, epsilon, rejection = (probability(delta, "delta"), probability(cpa_bias_upper, "cpa_bias_upper"),
                                  probability(rejection_upper, "rejection_upper"))
    dh, dg, width = natural(d_h, "d_h"), natural(d_g, "d_g"), natural(width, "width")
    require(width > 0, "positive query width required")
    qh, qg = dh*width, dg*width
    lo, hi = sqrt_interval(dg)
    pke_factor = 2*hi*(7*dg+dh+3)
    correction = 16*(2*qh+2*qg+1)**2*delta + 4*hi*delta
    guessing = Fraction(16*(8*qg+2*qh+1), seed_space(seed_bits))*hi
    return dict(pke_coefficient_upper=pke_factor, correction=correction, guessing=guessing,
                upper=min(Fraction(1, 2), rejection+pke_factor*epsilon+correction+guessing),
                root_interval=(lo, hi), directly_resource_qualified_for_R1=False,
                missing_resource_map="BHHP graph oracle and full reversible base-oracle amplification",
                unique_randomness_recovery_assumed=False, C01_closed=False)


def controlled_coordinate_cost(public_calls, recovered_key=False):
    """Our explicit compute/copy/uncompute bridge, not a free controlled oracle.

    When recovering message-only K(m) from K(m,Enc_F(m)), a coherent public
    encryption and its inverse are required, including their N/A oracles.
    The scope excludes a full MRE reduction and is not an end-to-end gate count.
    """
    calls = natural(public_calls, "public_calls")
    require(type(recovered_key) is bool, "boolean graph flag required")
    return dict(F_queries=2*calls, K_queries=2*calls, auxiliary_queries=2*calls,
                reversible_encryption_or_inverse_calls=2*calls if recovered_key else 0,
                covered_bridge_only=True, full_FO_reduction_resources_closed=False)
