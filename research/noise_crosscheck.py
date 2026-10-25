"""Independent positive floating convolutions of the authors' Kyber model."""

import importlib
import math
import sys
from types import SimpleNamespace

from upstream_tools import ensure_tools


def crosscheck(parameters: dict) -> dict:
    import numpy as np

    sys.path.insert(0, str(ensure_tools()))
    utility = importlib.import_module("proba_util")
    failure = importlib.import_module("Kyber_failure")

    def convolution(left, right):
        low_left, low_right = min(left), min(right)
        a = np.zeros(max(left)-low_left+1)
        b = np.zeros(max(right)-low_right+1)
        for x, value in left.items():
            a[x-low_left] = value
        for x, value in right.items():
            b[x-low_right] = value
        values = np.convolve(a, b)  # Direct positive sums; no FFT tail cancellation.
        return {low_left+low_right+i: float(value)
                for i, value in enumerate(values) if value > 0}

    utility.law_convolution = convolution
    failure.law_convolution = convolution
    # Original cutoff 2^-300 cannot test a 2^-434 tail. Use the same method at
    # 2^-600 and record the numerical change rather than hiding it.
    utility.clean_dist = lambda law: {x: p for x, p in law.items() if p > 2.0**-600}
    n, k, q, eta1, eta2, du, dv = (parameters[key] for key in
                                  ("n", "k", "q", "eta1", "eta2", "du", "dv"))
    # Public key is lossless, including q=7681 which needs 13 bits.
    ps = SimpleNamespace(n=n, m=k, q=q, ks=eta1, ke=eta1, ke_ct=eta2,
                         rqk=1 << (q-1).bit_length(), rqc=1 << du, rq2=1 << dv)
    distribution, probability = failure.p2_cyclotomic_error_probability(ps)
    return {"log2_historical_two_sided_union": math.log2(probability),
            "numpy_version": np.__version__, "cutoff_log2": -600,
            "method": "authors' separate convolution powers; direct NumPy positive convolution",
            "rounding": "upstream Python round", "distribution_mass": sum(distribution.values())}
