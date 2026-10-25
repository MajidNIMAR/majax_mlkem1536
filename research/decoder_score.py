"""Finite CBD score diagnostics for concrete decoder residuals.

The contribution X_r(S)=cos(2*pi*<S,r>/q) is studied for one shared ideal
iid-CBD secret S. No dual-lattice vectors, FFT attack or score-tail claim.
Formulae are exact in that auxiliary model; numerical evaluations use logs.
"""

from collections import Counter
import itertools
import math

LN2 = math.log(2)


def centered(x, q):
    return (x + q // 2) % q - q // 2


def logsum(values):
    values = list(values)
    if not values:
        return None
    peak = max(values)
    return peak + math.log(math.fsum(math.exp(v - peak) for v in values))


def logmean(values):
    return logsum(values) - math.log(len(values))


def log_phi(residual, q, eta, frequency=1):
    if q < 3 or q % 2 == 0 or eta < 1 or not isinstance(eta, int):
        raise ValueError("odd modulus and positive integer CBD parameter required")
    return 2 * eta * math.fsum(math.log(math.cos(math.pi * centered(frequency * v, q) / q)) for v in residual)


def signed_difference(log_a, log_b):
    """Signed log of exp(log_a)-exp(log_b), retaining tiny covariances."""
    if log_a == log_b:
        return dict(sign=0, log2_abs=None)
    large, small = max(log_a, log_b), min(log_a, log_b)
    return dict(sign=1 if log_a > log_b else -1,
                log2_abs=(large + math.log(-math.expm1(small - large))) / LN2)


def signed_sum(records):
    positive = [r["log2_abs"] * LN2 for r in records if r["sign"] > 0]
    negative = [r["log2_abs"] * LN2 for r in records if r["sign"] < 0]
    a, b = logsum(positive), logsum(negative)
    if a is None and b is None:
        return dict(sign=0, log2_abs=None)
    if a is None or b is None:
        return dict(sign=1 if b is None else -1, log2_abs=(a if b is None else b) / LN2)
    return signed_difference(a, b)


def covariance(a, b, q, eta):
    if len(a) != len(b):
        raise ValueError("equal vector lengths required")
    # Disjoint supports give independent functions of disjoint secret bits.
    if not any(centered(x, q) and centered(y, q) for x, y in zip(a, b)):
        return dict(sign=0, log2_abs=None)
    plus = log_phi([x + y for x, y in zip(a, b)], q, eta)
    minus = log_phi([x - y for x, y in zip(a, b)], q, eta)
    cross = logsum((plus, minus)) - LN2
    return signed_difference(cross, log_phi(a, q, eta) + log_phi(b, q, eta))


def phase_weights(residual, q, eta):
    """Exact integer phase histogram over all CBD bit strings."""
    weights = {0: 1}
    cbd = [(v, math.comb(2 * eta, eta + v)) for v in range(-eta, eta + 1)]
    for r in residual:
        updated = {}
        for phase, count in weights.items():
            for secret, multiplicity in cbd:
                p = (phase + r * secret) % q
                updated[p] = updated.get(p, 0) + count * multiplicity
        weights = updated
    return [weights.get(p, 0) for p in range(q)]


def convolution(a, b):
    q = len(a)
    if len(b) != q:
        raise ValueError("equal phase alphabets required")
    result = [0] * q
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            result[(i + j) % q] += x * y
    return result


def distribution_summary(residuals, q, eta, sizes):
    coordinate_logs = [[2 * eta * math.log(math.cos(math.pi * centered(x, q) / q)) for x in r] for r in residuals]
    exact = [math.fsum(row) for row in coordinate_logs]
    gaussian = [-eta * math.pi ** 2 * sum(x * x for x in row) / q ** 2 for row in residuals]
    if any(a > b + 1e-10 for a, b in zip(exact, gaussian)):
        raise ArithmeticError("CBD characteristic exceeds its Gaussian upper bound")
    marginal = math.fsum(logmean(list(column)) for column in zip(*coordinate_logs))
    offset, block_logs = 0, []
    for size in sizes:
        block_logs.append(logmean([math.fsum(row[offset:offset + size]) for row in coordinate_logs]))
        offset += size
    if offset != len(residuals[0]):
        raise ValueError("block sizes do not cover the residual")
    total = logsum(exact)
    return dict(empirical_log2_mean_CBD=logmean(exact) / LN2,
                empirical_log2_mean_Gaussian_upper=logmean(gaussian) / LN2,
                log2_product_empirical_coordinate_means=marginal / LN2,
                log2_product_empirical_block_means=math.fsum(block_logs) / LN2,
                log2_Gaussian_over_joint=(logmean(gaussian) - logmean(exact)) / LN2,
                log2_coordinate_product_over_joint=(marginal - logmean(exact)) / LN2,
                effective_weighted_sample_count=math.exp(2 * total - logsum([2 * v for v in exact])),
                largest_sample_share=math.exp(max(exact) - total))


def integer_moments(residuals):
    count, dimension = len(residuals), len(residuals[0])
    columns = list(zip(*residuals))
    sums = [sum(column) for column in columns]
    products = [[sum(a * b for a, b in zip(columns[i], columns[j])) for j in range(dimension)] for i in range(dimension)]
    return dict(samples=count, sums=sums, sum_products=products,
                covariance_numerators=[[count * products[i][j] - sums[i] * sums[j] for j in range(dimension)] for i in range(dimension)],
                covariance_denominator=count ** 2)


def score_bank(residuals, q, eta, size=32):
    bank = residuals[:size]
    pairs, diagonal, off_diagonal = [], [], []
    for i, a in enumerate(bank):
        for j in range(i, len(bank)):
            value = covariance(a, bank[j], q, eta)
            pairs.append(dict(i=i, j=j, **value))
            if i == j:
                diagonal.append(value)
            elif value["sign"]:
                off_diagonal.append(dict(sign=value["sign"], log2_abs=value["log2_abs"] + 1))
    diag, off = signed_sum(diagonal), signed_sum(off_diagonal)
    total = signed_sum((diag, off))
    if total["sign"] <= 0 or diag["sign"] <= 0:
        raise ArithmeticError("nonpositive numerical score variance")
    return dict(indices=list(range(len(bank))), upper_covariances=pairs,
                log2_variance_of_average=total["log2_abs"] - 2 * math.log2(len(bank)),
                log2_variance_independent_approximation=diag["log2_abs"] - 2 * math.log2(len(bank)),
                off_diagonal_sum=off, diagonal_sum=diag,
                log2_joint_over_independent_variance=total["log2_abs"] - diag["log2_abs"],
                scope="32 fixed residuals share one ideal iid-CBD secret; not the complete attack score")


def exact_toy(code):
    """Complete uniform targets, CBD1 secrets; integer joint phase laws."""
    q, n, eta = code.q, code.n, 1
    residuals = Counter()
    for target in itertools.product(range(q), repeat=n):
        decoded = code.decode_reference(target)
        word = code.encode(decoded["labels"])
        residuals[tuple(centered(x-y, q) for x, y in zip(target, word))] += 1
    phase = [0] * q
    for r, count in residuals.items():
        for p, weight in enumerate(phase_weights(r, q, eta)):
            phase[p] += count * weight
    denominator = q ** n * 4 ** n
    # The product of empirical coordinate marginals is a different exact law.
    independent, independent_denominator = [1] + [0] * (q - 1), 1
    for i in range(n):
        marginal = [0] * q
        for r, count in residuals.items():
            for p, weight in enumerate(phase_weights((r[i],), q, eta)):
                marginal[p] += count * weight
        independent = convolution(independent, marginal)
        independent_denominator *= q ** n * 4
    # Disjoint input blocks ARE independent under the complete uniform torus.
    block_law, block_denominator = [1] + [0] * (q - 1), 1
    offset = 0
    for generator in code.generators:
        block = [0] * q
        from block_decoder import decode_line_exhaustive
        for target in itertools.product(range(q), repeat=len(generator)):
            _, label = decode_line_exhaustive(target, generator, q)
            r = [centered(x - label * g, q) for x, g in zip(target, generator)]
            for p, weight in enumerate(phase_weights(r, q, eta)):
                block[p] += weight
        block_law = convolution(block_law, block)
        block_denominator *= q ** len(generator) * 4 ** len(generator)
        offset += len(generator)
    if any(x * block_denominator != y * denominator for x, y in zip(phase, block_law)):
        raise ArithmeticError("block factorization failed in the complete uniform toy")
    cosine = [math.cos(2 * math.pi * p / q) for p in range(q)]
    secret_rows = []
    for secret in itertools.product((-1, 0, 1), repeat=n):
        weight = math.prod(2 if v == 0 else 1 for v in secret)
        counts = [0] * q
        for r, count in residuals.items():
            counts[sum(a * b for a, b in zip(secret, r)) % q] += count
        score = math.fsum(counts[p] * cosine[p] for p in range(q)) / q ** n
        secret_rows.append(dict(secret=list(secret), bit_weight=weight, target_phase_counts=counts, score=score))
    mean = math.fsum(r["bit_weight"] * r["score"] for r in secret_rows) / 4 ** n
    variance = math.fsum(r["bit_weight"] * (r["score"] - mean) ** 2 for r in secret_rows) / 4 ** n
    conditional_diagonal = math.fsum(count * ((1 + math.exp(log_phi(r, q, eta, 2))) / 2 - math.exp(2 * log_phi(r, q, eta)))
                                   for r, count in residuals.items()) / q ** (2 * n)
    return dict(code=code.record(), eta=eta, uniform_targets=q ** n,
                residual_histogram=[dict(residual=list(r), count=count) for r, count in sorted(residuals.items())],
                phase_weights=phase, phase_denominator=denominator,
                coordinate_product_phase_weights=independent, coordinate_product_denominator=independent_denominator,
                block_product_phase_weights=block_law, block_product_denominator=block_denominator,
                coordinate_law_matches_joint=all(x * independent_denominator == y * denominator for x, y in zip(phase, independent)),
                block_law_matches_joint=True, secret_rows=secret_rows,
                shared_secret_score_mean=mean, shared_secret_score_variance=variance,
                independent_score_variance=conditional_diagonal,
                scope="complete finite synthetic code contribution; repeated residuals in the bank, no dual-lattice part")
