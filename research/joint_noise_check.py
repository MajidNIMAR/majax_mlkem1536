"""Exact toy experiment: uncorrelated coefficients can still be dependent."""

from collections import Counter
from fractions import Fraction
import itertools
import json
import math


def negacyclic(left, right):
    if len(left) != len(right):
        raise ValueError("equal polynomial degrees required")
    n = len(left)
    output = [0]*n
    for i, a in enumerate(left):
        for j, b in enumerate(right):
            output[(i+j) % n] += a*b*(1 if i+j < n else -1)
    return output


def experiment(n=4, threshold=2):
    """Enumerate independent CBD(1) polynomials, not a full KEM noise law."""
    vectors = list(itertools.product((-1, 0, 1), repeat=n))
    histogram = Counter()
    for left in vectors:
        wl = math.prod(2 if x == 0 else 1 for x in left)
        for right in vectors:
            wr = math.prod(2 if x == 0 else 1 for x in right)
            c = negacyclic(left, right)
            histogram[c[0], c[1]] += wl*wr
    total = sum(histogram.values())
    if total != 4**(2*n):
        raise ArithmeticError("elementary CBD enumeration lost mass")

    def expectation(function):
        return Fraction(sum(function(x, y)*w for (x, y), w in histogram.items()), total)

    p0 = expectation(lambda x, y: abs(x) >= threshold)
    p1 = expectation(lambda x, y: abs(y) >= threshold)
    joint = expectation(lambda x, y: abs(x) >= threshold and abs(y) >= threshold)
    union = p0+p1-joint
    return {"scope": "toy CBD(1) product modulo X^4+1; not a rank-six DFR estimate",
            "n": n, "threshold": threshold, "elementary_outcomes_weighted": total,
            "mean_c0": str(expectation(lambda x, y: x)),
            "covariance_c0_c1": str(expectation(lambda x, y: x*y)),
            "covariance_squared_coefficients": str(expectation(lambda x, y: x*x*y*y)-
                                                    expectation(lambda x, y: x*x)*expectation(lambda x, y: y*y)),
            "p0": str(p0), "p1": str(p1), "joint": str(joint),
            "independence_prediction_joint": str(p0*p1), "actual_union": str(union),
            "independence_prediction_union": str(p0+p1-p0*p1), "union_bound": str(p0+p1),
            "lesson": "marginal union bound needs no independence between output coefficients"}


if __name__ == "__main__":
    print(json.dumps(experiment(), indent=2))
