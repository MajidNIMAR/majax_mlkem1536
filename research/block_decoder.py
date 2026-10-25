"""Concrete q-ary block codes and exact circular least-squares decoding.

Each disjoint block has one field symbol. This is a research decoder for
the coded-dual study, not rank-6 KEM Decaps. No originality or constant-time
claim. All distances and tie decisions are exact integers.
"""

from dataclasses import dataclass
import itertools
import math


def validate_modulus(q):
    if not isinstance(q, int) or not 3 <= q < 65536 or q % 2 == 0:
        raise ValueError("odd prime below 2^16 required")
    if any(q % d == 0 for d in range(3, math.isqrt(q) + 1, 2)):
        raise ValueError("prime alphabet required")


def validate_values(values, q, length=None):
    if length is not None and len(values) != length:
        raise ValueError("wrong vector length")
    if any(not isinstance(v, int) or not 0 <= v < q for v in values):
        raise ValueError("canonical integer coordinates required")


def centered(value, q):
    return (value + q // 2) % q - q // 2


def nearest_root(q, degree):
    if degree < 1:
        raise ValueError("positive block length required")
    value = 1
    while (value + 1) ** degree <= q:
        value += 1
    return value if (2 * value + 1) ** degree >= q * 2 ** degree else value + 1


def decode_repetition(values, q):
    """Minimize sum centered(x_i-a)^2 over all a in Z_q, smallest a on ties.

Between consecutive wrap events the lifted objective is a quadratic. Only
the two integers neighboring its mean, clipped to the interval, are needed.
"""
    if not values:
        raise ValueError("nonempty block required")
    if not isinstance(q, int) or q < 3 or q % 2 == 0:
        raise ValueError("odd positive modulus required")
    validate_values(values, q)
    half = q // 2
    lifted = [centered(x, q) for x in values]
    total, squares = sum(lifted), sum(x * x for x in lifted)
    events = {}
    for x in values:
        boundary = (x + half + 1) % q
        if boundary:
            events[boundary] = events.get(boundary, 0) + 1
    left = 0
    best = None
    evaluations = 0
    for right_edge in sorted(events) + [q]:
        mean_floor = total // len(values)
        candidates = {max(left, min(right_edge - 1, a)) for a in (mean_floor, mean_floor + 1)}
        for a in candidates:
            score = squares - 2 * a * total + len(values) * a * a
            choice = score, a
            best = choice if best is None else min(best, choice)
            evaluations += 1
        if right_edge != q:
            multiplicity = events[right_edge]
            old_lift = right_edge - half - 1
            total += multiplicity * q
            squares += multiplicity * (2 * q * old_lift + q * q)
        left = right_edge
    return dict(label=best[1], squared_norm=best[0], candidate_scores=evaluations,
                intervals=len(events) + 1)


def decode_line_exhaustive(values, generator, q):
    """Independent slow integer oracle for a single block, all q symbols."""
    validate_values(values, q, len(generator))
    if not generator or generator[0] != 1:
        raise ValueError("systematic first block coordinate required")
    return min((sum(centered(x - a * g, q) ** 2 for x, g in zip(values, generator)), a)
               for a in range(q))


@dataclass(frozen=True)
class BlockCode:
    q: int
    generators: tuple
    family: str

    def __post_init__(self):
        validate_modulus(self.q)
        if self.family not in ("repeated", "radix") or not self.generators:
            raise ValueError("known family and nonempty generator blocks required")
        if any(not g or g[0] != 1 for g in self.generators) or self.n > 256:
            raise ValueError("systematic nonempty blocks and n<=256 required")
        for block in self.generators:
            validate_values(block, self.q)
        if self.family == "repeated" and any(g != 1 for block in self.generators for g in block):
            raise ValueError("repeated family requires unit coefficients")

    @property
    def n(self):
        return sum(len(g) for g in self.generators)

    @property
    def k(self):
        return len(self.generators)

    def encode(self, labels):
        validate_values(labels, self.q, self.k)
        return [a * g % self.q for a, block in zip(labels, self.generators) for g in block]

    def decode_repeated(self, values):
        if self.family != "repeated":
            raise ValueError("quadratic interval decoder restricted to repeated blocks")
        validate_values(values, self.q, self.n)
        labels, norm, candidates, intervals, offset = [], 0, 0, 0, 0
        for block in self.generators:
            row = decode_repetition(values[offset:offset + len(block)], self.q)
            labels.append(row["label"])
            norm += row["squared_norm"]
            candidates += row["candidate_scores"]
            intervals += row["intervals"]
            offset += len(block)
        return dict(labels=labels, squared_norm=norm, candidate_scores=candidates, intervals=intervals)

    def decode_reference(self, values):
        validate_values(values, self.q, self.n)
        labels, norm, offset = [], 0, 0
        for block in self.generators:
            score, label = decode_line_exhaustive(values[offset:offset + len(block)], block, self.q)
            labels.append(label)
            norm += score
            offset += len(block)
        return dict(labels=labels, squared_norm=norm)

    def record(self):
        return dict(q=self.q, n=self.n, k=self.k, family=self.family,
                    generators=[list(g) for g in self.generators],
                    codewords=str(self.q ** self.k), block_sizes=[len(g) for g in self.generators],
                    tie_rule="lexicographically smallest field-symbol vector",
                    metric="sum of squared centered modular coordinate errors")


def make_code(q, n, k, family):
    validate_modulus(q)
    if not isinstance(n, int) or not isinstance(k, int) or not 1 <= k <= n <= 256:
        raise ValueError("1<=k<=n<=256 required")
    if family not in ("repeated", "radix"):
        raise ValueError("unknown block code family")
    sizes = [n // k + (i < n % k) for i in range(k)]
    blocks = []
    for size in sizes:
        base = 1 if family == "repeated" else nearest_root(q, size)
        blocks.append(tuple(pow(base, j, q) for j in range(size)))
    return BlockCode(q, tuple(blocks), family)


def exhaustive_toy(q, n, k, family):
    code = make_code(q, n, k, family)
    words = [(list(labels), code.encode(labels)) for labels in itertools.product(range(q), repeat=k)]
    histogram = {}
    for target in itertools.product(range(q), repeat=n):
        expected = min((sum(centered(x - y, q) ** 2 for x, y in zip(target, word)), labels)
                       for labels, word in words)
        actual = code.decode_repeated(target) if family == "repeated" else code.decode_reference(target)
        if (actual["squared_norm"], actual["labels"]) != expected:
            raise ArithmeticError("block decoding disagrees with the full codebook")
        histogram[expected[0]] = histogram.get(expected[0], 0) + 1
    return dict(code=code.record(), targets=q ** n,
                histogram=[dict(squared_norm=d, count=count) for d, count in sorted(histogram.items())],
                full_codebook_match=True)
