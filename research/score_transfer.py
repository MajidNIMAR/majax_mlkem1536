"""H09: fixed-point diagnostics, never a revised attack estimator."""

import math

from coded_dual_model import log_integral

LN2 = math.log(2)


def normal_budget(log2_M, log2_N, log2_mu, inflation=1.0):
    if inflation <= 0 or not all(math.isfinite(v) for v in (log2_M, log2_N, log2_mu, inflation)):
        raise ValueError('finite logs and positive variance inflation required')
    x = math.exp((1 + log2_N + 2 * log2_mu - math.log2(inflation)) * LN2 / 2)
    probability = math.erfc(x / math.sqrt(2)) / 2
    if probability == 0:
        raise ArithmeticError('normal probability underflow; logarithmic tail required')
    return log2_M + math.log2(probability)


def cantelli_budget(log2_M, log2_N, log2_mu):
    """Unclipped log2 union bound under explicitly supplied null moments."""
    z = (1 + log2_N + 2 * log2_mu) * LN2
    log_denominator = max(0, z) + math.log1p(math.exp(-abs(z)))
    return log2_M - log_denominator / LN2


def sufficient_list(log2_M, log2_mu, alpha=0.05):
    if not 0 < alpha < 1 or log2_M < 0:
        raise ValueError('positive candidate count and alpha in (0,1) required')
    return (log2_M - math.log2(alpha) + math.log1p(-alpha * 2 ** -log2_M) / LN2
            - 1 - 2 * log2_mu)


def covariance_budget(log2_N, excess):
    """Mean over ordered distinct pairs; baseline diagonal variance is 1/2."""
    if log2_N <= 0 or excess <= 0:
        raise ValueError('N>1 and positive relative excess required')
    return math.log2(excess / 2) - log2_N - math.log1p(-2 ** -log2_N) / LN2


def maximum_inflation(log2_M, log2_N, log2_mu):
    target = math.log2(.05)
    if normal_budget(log2_M,log2_N,log2_mu) > target:
        raise ValueError('historical point already exceeds the normal budget')
    lo, hi = 1., 2.
    if normal_budget(log2_M,log2_N,log2_mu,hi) <= target:
        raise ValueError('registered sensitivity bracket changed')
    for _ in range(60):
        mid=(lo+hi)/2
        if normal_budget(log2_M,log2_N,log2_mu,mid) <= target:
            lo=mid
        else:
            hi=mid
    return (lo+hi)/2


def ideal_code_factor(q, eta, n, k):
    log_radius = ((1-k/n)*math.log(q) + math.lgamma(n/2+1)/n
                  - math.log(math.pi)/2 + math.log1p(1/n))
    c = eta * (math.pi * math.exp(log_radius) / q) ** 2
    # All registered points use the positive-series branch, no SciPy needed.
    if c >= n/2+1:
        raise ArithmeticError('registered integral branch changed')
    return log_integral(n, c) / LN2


def mean_log2(values):
    peak = max(values)
    return peak + math.log2(math.fsum(2 ** (v-peak) for v in values) / len(values))


def sample_statistics(rows, q, eta):
    exact, gaussian = [], []
    for row in rows:
        r = row['residual']
        if any(abs(v) > q//2 for v in r) or sum(v*v for v in r) != row['squared_norm']:
            raise ValueError('noncanonical residual or norm mismatch')
        exact.append(2*eta*math.fsum(math.log2(math.cos(math.pi*v/q)) for v in r))
        gaussian.append(-eta*math.pi**2*row['squared_norm']/q**2/LN2)
    mu = mean_log2(exact)
    return dict(count=len(rows),log2_mean_CBD=mu,log2_mean_Gaussian_upper=mean_log2(gaussian),
                effective_weighted_sample_count=2 ** (2*(mu+math.log2(len(rows)))
                                                    - mean_log2([2*v for v in exact])-math.log2(len(rows))),
                largest_sample_share=2 ** (max(exact)-mu-math.log2(len(rows))))


def audit_point(point, panel_index, residuals):
    p = point['inputs']
    q, eta, n, k = p['q'], p['eta'], p['nfft'], p['kfft']
    N, mu = point['log2_list_size'], point['log2_relative_threshold']
    M = point['log2_repetitions'] + k*math.log2(q)
    ideal = ideal_code_factor(q, eta, n, k)
    normal = [dict(variance_inflation=v,log2_union_budget=normal_budget(M,N,mu,v))
              for v in (1.0,1.01,1.1,2.0)]
    if abs(normal[0]['log2_union_budget']-point['log2_epsilon']) > 1e-8:
        raise ArithmeticError('historical normal budget not reproduced')
    samples = []
    for family in ('repeated','radix'):
        label = f'panel-{panel_index}-{family}'
        rows = [r for r in residuals if r['experiment']==label]
        if len(rows)!=256 or any(len(r['residual'])!=n for r in rows):
            raise ValueError('frozen concrete code panel missing')
        stats = sample_statistics(rows,q,eta)
        diagnostic_mu = mu - ideal + stats['log2_mean_CBD']
        samples.append(dict(experiment=label,**stats,
                            log2_mean_over_ideal_code=stats['log2_mean_CBD']-ideal,
                            log2_diagnostic_full_threshold=diagnostic_mu,
                            log2_diagnostic_normal_budget=normal_budget(M,N,diagnostic_mu),
                            certified_population_mean=False,attack_cost_updated=False))
    dimension = point['lattice_dimension']
    representations = []
    for name, size in (('dense_mod_q_packed', (dimension*(q-1).bit_length()+7)//8),
                       ('dense_64_bit_coordinates',8*dimension)):
        representations.append(dict(representation=name,bytes_per_vector=size,
                                    log2_list_bytes=N+math.log2(size),
                                    illustrative_caps=[dict(log2_bytes=cap,
                                        log2_max_vectors=math.log2((1<<cap)//size),
                                        list_excess_bits=N-math.log2((1<<cap)//size)) for cap in (40,60,80)]))
    cantelli = cantelli_budget(M,N,mu)
    required = sufficient_list(M,mu)
    limit = maximum_inflation(M,N,mu)
    return dict(parent_index=point['index'],inputs=p,lattice_dimension=dimension,
                log2_list_size=N,log2_threshold=mu,log2_candidate_budget=M,
                log2_ideal_code_factor=ideal,log2_inferred_network_factor=mu-ideal,
                normal_sensitivity=normal,
                normal_budget_variance_limit=dict(maximum_inflation=limit,relative_excess=limit-1,
                    log2_max_mean_off_diagonal_covariance=covariance_budget(N,limit-1)),
                covariance_tolerances=[dict(relative_variance_excess=e,
                    log2_max_mean_off_diagonal_covariance=covariance_budget(N,e)) for e in (.01,.1,1.)],
                moment_only_diagnostic=dict(assumed_wrong_mean=0,assumed_wrong_variance='1/(2N)',
                    log2_unclipped_union_bound=cantelli,clipped_union_bound=min(1.,2**cantelli),
                    log2_sufficient_N_at_fixed_mu=required,additional_list_bits=required-N,
                    full_wrong_candidate_moments_validated=False),
                storage_models=representations,concrete_sample_diagnostics=samples)
