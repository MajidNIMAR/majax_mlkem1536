"""Conditional coded-dual model with explicit sample and BKZ boundaries.

Equations follow TabOg/CodedDualAttack e2104ca. GV=1 is an ideal-code
sensitivity scenario, not a measured polar decoder or a proved attack cost.
The author's MLWE zero-count heuristic is kept explicit, not re-proved here.
"""

from functools import cache
import math

LN2 = math.log(2)
C_ARITH = 1024 * 115928 + 160 * 240500


def validate(n, degree, q, eta, samples, nenu, nfft, kfft):
    if degree < 2 or degree & (degree - 1) or n % degree or q < 3 or q % 2 == 0:
        raise ValueError("power-of-two ring degree, integral rank and odd modulus required")
    if eta not in (2, 3) or not 0 <= nenu < n or not 1 <= kfft < nfft < n - nenu:
        raise ValueError("unsupported distribution or dimension split")
    if not 1 <= samples <= n or samples + n - nenu - nfft < 200:
        raise ValueError("key sample budget or lattice dimension invalid")


@cache
def zero_weights(population, guessed, eta):
    """Binomial zero-count weights and conditional zero-subset probability."""
    if not 0 <= guessed <= population or eta not in (2, 3):
        raise ValueError("invalid zero-subset model")
    p0 = math.comb(2 * eta, eta) / (1 << (2 * eta))
    denominator = math.comb(population, guessed)
    rows = []
    for zeros in range(guessed, population + 1):
        log_weight = (math.lgamma(population + 1) - math.lgamma(zeros + 1)
                      - math.lgamma(population - zeros + 1) + zeros * math.log(p0)
                      + (population - zeros) * math.log1p(-p0))
        chance = math.comb(zeros, guessed) / denominator
        rows.append((math.exp(log_weight), chance))
    return tuple(rows)


def zero_success(repetitions, weights):
    if repetitions < 1:
        raise ValueError("at least one repetition required")
    return math.fsum(w if p == 1 else w * -math.expm1(repetitions * math.log1p(-p))
                     for w, p in weights)


@cache
def repetition_model(population, guessed, eta, target=0.6):
    if not 0 < target < 1:
        raise ValueError("success target in (0,1) required")
    weights = zero_weights(population, guessed, eta)
    if zero_success(2 ** 100, weights) < target:
        return None
    if zero_success(1, weights) >= target:
        return 1.0
    lo, hi = 0.0, 100 * LN2
    for _ in range(60):
        middle = (lo + hi) / 2
        if zero_success(math.exp(middle), weights) >= target:
            hi = middle
        else:
            lo = middle
    return float(math.ceil(math.exp(hi)))


def log_integral(beta, c):
    """Log of beta*integral_0^1 t^(beta-1)*exp(-c*t^2) dt.

The positive series avoids subtracting nearly equal incomplete gamma values.
SciPy is needed only in the upper-c branch of the numerical worker.
"""
    if beta <= 0 or c < 0 or not math.isfinite(c):
        raise ValueError("positive beta and finite nonnegative c required")
    if c == 0:
        return 0.0
    s = beta / 2
    if c < s + 1:
        total = term = 1.0
        for j in range(1, 10000):
            term *= c / (s + j)
            total += term
            if term < total * 1e-16:
                return -c + math.log(total)
        raise ArithmeticError("positive incomplete-gamma series did not converge")
    from scipy.special import gammainc
    return math.lgamma(s + 1) - s * math.log(c) + math.log(float(gammainc(s, c)))


def logadd(*values):
    peak = max(values)
    return peak + math.log(math.fsum(math.exp(v - peak) for v in values))


class CodedDualModel:
    def __init__(self, reduction, real_field):
        self.reduction = reduction
        self.real = real_field

    @cache
    def sampler(self, dimension, beta):
        rho, _, _, beta1 = self.reduction.short_vectors(beta=beta, N=None, d=dimension, sieve_dim=None)
        return float(rho), int(beta1)

    def evaluate(self, *, n, degree, q, eta, samples, nenu, nfft, kfft,
                 mlwe, experimental=None, beta_cap=None):
        validate(n, degree, q, eta, samples, nenu, nfft, kfft)
        nlat = n - nenu - nfft
        dimension = samples + nlat
        population = n if mlwe else nenu + nfft
        repetitions = repetition_model(population, nenu, eta)
        inputs = dict(n=n, degree=degree, q=q, eta=eta, samples=samples, nenu=nenu,
                      nfft=nfft, kfft=kfft, mlwe=mlwe)
        if repetitions is None:
            return dict(inputs=inputs, status="zero_guess_target_unreachable_within_2^100")
        log_r = math.log(repetitions)
        high = min(dimension, beta_cap or dimension)
        threshold_budget = math.log(0.05)
        from scipy.special import log_ndtr

        @cache
        def score(beta):
            rho, beta1 = self.sampler(dimension, beta)
            b = float(beta)
            log_delta = (math.log(b / (2 * math.pi * math.e)) + math.log(math.pi * b) / b) / (2 * (b - 1))
            log_avg = math.log(rho) + nlat / dimension * math.log(q) + (dimension - 1) * log_delta
            dlat = math.exp(log_avg) * (beta1 + 1) / beta1
            log_threshold = log_integral(beta1, eta * (math.pi * dlat / q) ** 2)
            if experimental is None:
                log_avg_lsc = ((1 - kfft / nfft) * math.log(q)
                               + math.lgamma(nfft / 2 + 1) / nfft - math.log(math.pi) / 2)
                dlsc = math.exp(log_avg_lsc) * (nfft + 1) / nfft
                log_threshold += log_integral(nfft, eta * (math.pi * dlsc / q) ** 2)
            else:
                avg, sdv = experimental
                variance_factor = 1 + 2 * eta * (math.pi * sdv / q) ** 2
                log_threshold += -eta * (math.pi * avg / q) ** 2 / variance_factor - math.log(variance_factor) / 2
            log_n = beta1 * math.log(4 / 3) / 2
            log_x = math.log(2) / 2 + log_n / 2 + log_threshold
            x = math.exp(min(log_x, 350))
            log_wrong = float(log_ndtr(-x))
            return log_r + kfft * math.log(q) + log_wrong, beta1, log_n, log_threshold

        if high < 200 or score(high)[0] > threshold_budget:
            return dict(inputs=inputs, status="no_feasible_beta_within_cap", beta_cap=high,
                        log2_epsilon_at_cap=score(high)[0] / LN2)
        lo, hi = 199, high
        while hi - lo > 1:
            middle = (lo + hi) // 2
            if score(middle)[0] <= threshold_budget:
                hi = middle
            else:
                lo = middle
        beta = hi
        epsilon_log, beta1, log_n, log_threshold = score(beta)
        # Retain a monotonicity diagnostic on the entire bracket, rather than
        # silently assuming that a clipped endpoint is a successful search.
        checkpoints = sorted(set(range(200, high + 1, 64)) | {high, beta, max(200, beta - 1)})
        flags = [score(b)[0] <= threshold_budget for b in checkpoints]
        monotone = flags == sorted(flags)
        if not monotone:
            return dict(inputs=inputs, status="nonmonotone_beta_diagnostic", beta_cap=high)
        N = (self.real(4) / 3).sqrt() ** beta1
        _, sample_cost, _, _ = self.reduction.short_vectors(beta=beta, N=N, d=dimension, sieve_dim=beta1)
        log_sample = float(sample_cost.log())
        fft_log = math.log(C_ARITH * kfft) + (kfft - 1) * math.log(q)
        length = 1 << nfft.bit_length()
        decode_log = log_n + math.log(3 * C_ARITH * length * math.log2(length))
        total = logadd(log_sample, log_r + decode_log, log_r + fft_log)
        return dict(inputs=inputs, status="conditional_model_cost", beta0=beta, beta1=beta1,
                    beta_cap=high, lattice_dimension=dimension, log2_rop=total / LN2,
                    log2_sample_cost=log_sample / LN2, log2_repetitions=log_r / LN2,
                    log2_decode_all=decode_log / LN2, log2_fft=fft_log / LN2,
                    log2_list_size=log_n / LN2, log2_relative_threshold=log_threshold / LN2,
                    log2_epsilon=epsilon_log / LN2,
                    zero_guess_success=zero_success(repetitions, zero_weights(population, nenu, eta)),
                    beta_predecessor_fails=beta == 200 or score(beta - 1)[0] > threshold_budget,
                    beta_coarse_monotonicity=monotone, beta_hits_cap=beta == high,
                    reduction_table_extrapolated=beta > 1024 or beta1 > 1024,
                    decoder_model="published_polar_statistics" if experimental else "ideal_GV_radius_ratio_1",
                    applicability="conditional heuristic; no actual attack or global security level")
