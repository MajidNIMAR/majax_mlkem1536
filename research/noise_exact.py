"""Exact discrete-noise arithmetic under the documented independence model.

No floating point is used to form the distribution or count failures. This is
not a proof that a real KEM's rounding errors are independent and uniform.
"""

from collections import Counter
from dataclasses import dataclass
from decimal import Decimal, localcontext
from fractions import Fraction
from functools import reduce
import hashlib
import math
import time


@dataclass(frozen=True)
class Law:
    weights: dict[int, int]
    denominator: int

    @classmethod
    def counts(cls, weights: dict[int, int]) -> "Law":
        weights = {x: count for x, count in weights.items() if count}
        if not weights or any(count < 0 for count in weights.values()):
            raise ValueError("invalid integer probability weights")
        divisor = reduce(math.gcd, weights.values())
        result = {x: count // divisor for x, count in weights.items()}
        return cls(result, sum(result.values()))

    def mean(self) -> Fraction:
        return Fraction(sum(x * w for x, w in self.weights.items()), self.denominator)

    def variance(self) -> Fraction:
        second = Fraction(sum(x*x*w for x, w in self.weights.items()), self.denominator)
        return second - self.mean() ** 2


def cbd(eta: int) -> Law:
    if eta < 1:
        raise ValueError("eta must be positive")
    return Law.counts({x: math.comb(2*eta, x+eta) for x in range(-eta, eta+1)})


def combine(left: Law, right: Law, *, product: bool = False) -> Law:
    weights = Counter()
    for x, wx in left.weights.items():
        for y, wy in right.weights.items():
            weights[x*y if product else x+y] += wx*wy
    return Law.counts(dict(weights))


def compress(x: int, q: int, bits: int) -> int:
    # q is odd: compression has no half-integer ties.
    return ((x * (1 << bits) + q // 2) // q) % (1 << bits)


def decompress(x: int, q: int, bits: int) -> int:
    # FIPS convention rounds half-integers upward, not to the nearest even value.
    return (q*x + (1 << (bits-1))) // (1 << bits)


def rounding_law(q: int, bits: int, *, historical: bool = False) -> Law:
    histogram = Counter()
    for x in range(q):
        if historical:
            y = round((1 << bits)*x/q) % (1 << bits)
            restored = round(q*y/(1 << bits)) % q
            error = x-restored  # upstream's sign; products with symmetric s erase it
        else:
            restored = decompress(compress(x, q, bits), q, bits)
            error = restored-x
        histogram[(error+q//2) % q-q//2] += 1
    return Law.counts(dict(histogram))


def symmetric_power(law: Law, exponent: int) -> tuple[int, list[int], int]:
    """Coefficients of A(x)^N via A Q' = N A' Q, using exact divisions.

    Symmetry halves the recurrence. The result's mass and second moment are
    checked against independent identities before it can be used.
    """
    if exponent < 1:
        raise ValueError("positive exponent required")
    low, high = min(law.weights), max(law.weights)
    if low != -high or any(law.weights.get(x, 0) != law.weights.get(-x, 0)
                           for x in range(low, high+1)):
        raise ValueError("a symmetric zero-mean input law is required")
    dense = [law.weights.get(x, 0) for x in range(low, high+1)]
    degree = len(dense)-1
    a0 = dense[0]
    terms = [(j, value) for j, value in enumerate(dense) if j and value]
    total_degree = degree*exponent
    coefficients = [a0**exponent]
    for position in range(1, total_degree//2+1):
        numerator = sum(((exponent+1)*j-position)*value*coefficients[position-j]
                        for j, value in terms if j <= position)
        coefficient, remainder = divmod(numerator, position*a0)
        if remainder or coefficient < 0:
            raise ArithmeticError("polynomial recurrence failed an exact-division check")
        coefficients.append(coefficient)
    mirror = coefficients[-2::-1] if total_degree % 2 == 0 else coefficients[::-1]
    coefficients.extend(mirror)
    denominator = law.denominator**exponent
    if sum(coefficients) != denominator:
        raise ArithmeticError("distribution mass does not equal one")
    offset = low*exponent
    moment = sum((offset+i)**2 * value for i, value in enumerate(coefficients))
    base_moment = sum(x*x*value for x, value in law.weights.items())
    if moment != exponent*base_moment*(law.denominator**(exponent-1)):
        raise ArithmeticError("second moment does not agree with independent addition")
    return offset, coefficients, denominator


def probability_record(value: Fraction) -> dict:
    if not 0 < value <= 1:
        raise ValueError("a nonzero probability is required")
    with localcontext() as context:
        context.prec = 80
        decimal = str(Decimal(value.numerator)/Decimal(value.denominator))
    numerator = value.numerator.to_bytes((value.numerator.bit_length()+7)//8, 'big')
    denominator = value.denominator.to_bytes((value.denominator.bit_length()+7)//8, 'big')
    return {"decimal": decimal,
            "log2": math.log2(value.numerator)-math.log2(value.denominator),
            "numerator_bits": value.numerator.bit_length(),
            "denominator_bits": value.denominator.bit_length(),
            "ratio_sha256": hashlib.sha256(numerator+b'\x00'+denominator).hexdigest()}


def analyze(n: int, k: int, q: int, eta1: int, eta2: int,
            du: int, dv: int, *, historical: bool = False) -> dict:
    started = time.perf_counter()
    secret, errors = cbd(eta1), cbd(eta2)
    rounding_u = rounding_law(q, du, historical=historical)
    rounding_v = rounding_law(q, dv, historical=historical)
    # e and y use eta1; s*(e1 + rounding_u) uses eta1, eta2 and uniform u.
    first = combine(secret, secret, product=True)
    second = combine(secret, combine(errors, rounding_u), product=True)
    pair = combine(first, second)
    final = combine(errors, rounding_v)
    offset, coefficients, denominator = symmetric_power(pair, n*k)
    prefix = [0]
    for coefficient in coefficients:
        prefix.append(prefix[-1]+coefficient)

    def interval_count(lower: int, upper: int) -> int:
        start = max(0, lower-offset)
        end = min(len(coefficients), upper-offset+1)
        return prefix[end]-prefix[start] if end > start else 0

    upper_support = offset+len(coefficients)-1
    bit_failures = []
    # Correct decoding regions before shifting the embedded bit, modulo q.
    for bit in (0, 1):
        if bit == 0:
            lower, upper = -(q//4), q//4
        else:
            mu = decompress(1, q, 1)
            # Compute the interval of residues decoded as one by integer rules.
            residues = [x for x in range(q) if compress(x, q, 1) == 1]
            lower, upper = min(residues)-mu, max(residues)-mu
        failures = 0
        for extra, weight in final.weights.items():
            first_period = (offset+extra-upper)//q-1
            last_period = (upper_support+extra-lower)//q+1
            successes = sum(interval_count(lower-extra+period*q, upper-extra+period*q)
                            for period in range(first_period, last_period+1))
            if not 0 <= successes <= denominator:
                raise ArithmeticError("invalid exact decoder interval count")
            failures += weight*(denominator-successes)
        bit_failures.append(Fraction(failures, denominator*final.denominator))

    # Match the historical q/4 tail convention, including the complete support.
    threshold = math.ceil(q/4)
    tails = 0
    for extra, weight in final.weights.items():
        central = interval_count(-threshold+1-extra, threshold-1-extra)
        tails += weight*(denominator-central)
    historical_tail = Fraction(tails, denominator*final.denominator)
    average_union = n*(bit_failures[0]+bit_failures[1])/2
    worst_bit_union = n*max(bit_failures)
    return {"parameters": dict(n=n,k=k,q=q,eta1=eta1,eta2=eta2,du=du,dv=dv),
            "rounding": "historical Python round" if historical else "FIPS integer half-up",
            "arithmetic": "exact integer distributions, no truncation, no FFT",
            "model": "independent CBD variables; independent uniform pre-compression coefficients",
            "coefficient_mean": str(final.mean()),
            "coefficient_variance": str(n*k*pair.variance()+final.variance()),
            "coefficient_standard_deviation": math.sqrt(float(n*k*pair.variance()+final.variance())),
            "rounding_u_counts": {str(x): w for x,w in sorted(rounding_u.weights.items())},
            "rounding_u_denominator": rounding_u.denominator,
            "bit0_failure": probability_record(bit_failures[0]),
            "bit1_failure": probability_record(bit_failures[1]),
            "message_lower_bound_single_coefficient": probability_record((bit_failures[0]+bit_failures[1])/2),
            "message_union_bound_uniform_bits": probability_record(average_union),
            "message_union_bound_worst_bit": probability_record(worst_bit_union),
            "historical_two_sided_union": probability_record(n*historical_tail),
            "integer_mass_check": "passed", "second_moment_check": "passed",
            "coefficient_support": [offset+min(final.weights), upper_support+max(final.weights)],
            "elapsed_seconds": time.perf_counter()-started}
