"""Explicit asymptotic 2-sieve sensitivity, separate from finite cost models."""


def bcss23_model():
    from sage.all import RR, ZZ
    from estimator.reduction import ReductionCost

    class BCSS23Asymptotic(ReductionCost):
        __name__ = "BCSS23-asymptotic"
        # Reusable walks still use the 2-tuple list regime. The base estimator
        # sampler assumes that regime; it is NOT suitable for a 3-tuple sieve.
        short_vectors = ReductionCost._short_vectors_sieve

        def __call__(self, beta, d, B=None):
            return ZZ(2) ** (RR("0.2563")*beta)

    return BCSS23Asymptotic()
