"""Exact R1 matrix-XOF simulation and finite, data-only law checks.

The inverse rejection sampler preserves ALL sixteen raw bits: accepted
13-bit candidates are replaced, the three unused high bits and rejected
words are retained. It is an ideal-oracle simulator, never a cryptographic
implementation or an oracle for concrete SHAKE security.
"""
from collections import Counter
from fractions import Fraction
from itertools import product
from math import comb


def require(condition, message):
    if not condition:
        raise ValueError(message)


def natural(value, name, maximum=None):
    require(type(value) is int and value >= 0, name + " must be a nonnegative integer")
    require(maximum is None or value <= maximum, name + " exceeds the explicit model bound")
    return value


def parameters(q, bits, high_bits):
    natural(bits, "bits", 20)
    natural(high_bits, "high_bits", 8)
    require(bits > 0 and type(q) is int and 0 < q <= (1 << bits), "invalid sampler modulus")
    return 1 << bits, 1 << (bits + high_bits)


def rewrite_prefix(raw_words, target, q=7681, bits=13, high_bits=3):
    """Push a uniform word prefix to the conditional law given Parse=target.

    A prefix can end before Parse completes. No new words are silently
    created. Suffix words following the last required acceptance are copied.
    The input collections are never mutated.
    """
    space, word_space = parameters(q, bits, high_bits)
    target, raw_words = tuple(target), tuple(raw_words)
    require(target and all(type(x) is int and 0 <= x < q for x in target), "invalid target coefficients")
    require(all(type(x) is int and 0 <= x < word_space for x in raw_words), "invalid raw word")
    rewritten, accepted = [], 0
    stop = None
    for index, word in enumerate(raw_words):
        if accepted < len(target) and word % space < q:
            word = (word // space) * space + target[accepted]
            accepted += 1
            if accepted == len(target):
                stop = index + 1
        rewritten.append(word)
    return tuple(rewritten), stop


def parsed_prefix(words, n, q=7681, bits=13, high_bits=3):
    space, word_space = parameters(q, bits, high_bits)
    natural(n, "n", 65536)
    require(n > 0, "positive coefficient count required")
    require(all(type(x) is int and 0 <= x < word_space for x in words), "invalid word")
    return tuple(x % space for x in words if x % space < q)[:n]


def conditional_prefix_probability(prefix, target, q, bits, high_bits):
    """Independent closed law, derived by conditioning the raw trace.

    Before the nth acceptance, each accepted word has conditional mass q/W;
    every rejected word and every suffix word has mass 1/W. An accepted
    coefficient inconsistent with the target gives mass zero.
    """
    space, word_space = parameters(q, bits, high_bits)
    target = tuple(target)
    require(target and all(type(x) is int and 0 <= x < q for x in target), "invalid target")
    accepted = 0
    mass = Fraction(1)
    for word in prefix:
        require(type(word) is int and 0 <= word < word_space, "invalid prefix word")
        if accepted < len(target) and word % space < q:
            if word % space != target[accepted]:
                return Fraction(0)
            mass *= Fraction(q, word_space)
            accepted += 1
        else:
            mass /= word_space
    return mass


def rejection_tail(q, degree, candidate_bits, word_limit):
    """Pr[fewer than degree acceptances in word_limit independent candidates]."""
    space, _ = parameters(q, candidate_bits, 0)
    natural(degree, "degree", 65536)
    natural(word_limit, "word_limit", 65536)
    require(degree > 0, "positive degree required")
    if word_limit < degree:
        return Fraction(1)
    if q == space:
        return Fraction(0)
    numerator = sum(comb(word_limit, accepted) * q**accepted * (space - q)**(word_limit - accepted)
                    for accepted in range(degree))
    return Fraction(numerator, space**word_limit)


def certified_inverse_power(mass):
    """Largest integer b with mass<=2^-b, by integers only; None for zero."""
    require(isinstance(mass, Fraction) and 0 <= mass <= 1, "exact probability required")
    if mass == 0:
        return None
    exponent = max(0, mass.denominator.bit_length() - mass.numerator.bit_length())
    while mass.numerator * (1 << exponent) > mass.denominator:
        exponent -= 1
    while mass.numerator * (1 << (exponent + 1)) <= mass.denominator:
        exponent += 1
    return exponent


def matrix_simulation_gap(preseed_queries=0, word_limit=512, seed_bits=256,
                          q=7681, degree=256, rank=6, candidate_bits=13):
    natural(preseed_queries, "preseed_queries")
    natural(seed_bits, "seed_bits", 4096)
    natural(rank, "rank", 255)
    require(seed_bits > 0 and rank > 0, "positive dimensions required")
    require(1 <= candidate_bits <= 16, "the matrix simulator reads two-byte candidate words")
    seed_gap = min(Fraction(1), Fraction(preseed_queries, 1 << seed_bits))
    truncation = min(Fraction(1), rank**2 * rejection_tail(q, degree, candidate_bits, word_limit))
    return dict(preseed_classical_gap=seed_gap, truncation_gap=truncation,
                total_gap=min(Fraction(1), seed_gap + truncation),
                programmed_cells=rank**2, maximum_candidate_words=rank**2 * word_limit,
                maximum_matrix_stream_bytes=2 * rank**2 * word_limit,
                expected_candidate_words=Fraction(rank**2 * degree * (1 << candidate_bits), q))


def finite_law_checks():
    """Exhaustively push word prefixes; compare independent conditional law.

    Also average over every target and check that the original raw uniform
    prefix distribution is recovered exactly. Prefixes include incomplete
    parses and post-termination tails. This is not an exhaustive R1 proof.
    """
    panels, raw_traces, conditional_entries = 0, 0, 0
    for q, bits, high in ((1, 2, 0), (2, 2, 0), (3, 2, 0), (3, 2, 1), (5, 3, 0)):
        _, words = parameters(q, bits, high)
        for n in (1, 2):
            for length in (1, 2, 3, 4):
                prefixes = list(product(range(words), repeat=length))
                mixture = Counter()
                for target in product(range(q), repeat=n):
                    counts = Counter(rewrite_prefix(raw, target, q, bits, high)[0] for raw in prefixes)
                    require(sum(counts.values()) == words**length, "conditional simulator lost mass")
                    for prefix in prefixes:
                        require(Fraction(counts[prefix], words**length)
                                == conditional_prefix_probability(prefix, target, q, bits, high),
                                "conditional simulator has a wrong prefix law")
                        conditional_entries += 1
                    mixture.update(counts)
                    raw_traces += len(prefixes)
                require(len(mixture) == words**length and set(mixture.values()) == {q**n},
                        "averaging targets did not recover the complete raw uniform oracle")
                panels += 1
    return dict(panels=panels, rewritten_raw_traces=raw_traces,
                independently_checked_prefix_probabilities=conditional_entries,
                all_conditional_laws_equal=True, uniform_target_mixture_exact=True,
                includes_incomplete_and_post_termination_prefixes=True,
                scope="finite inverse-rejection laws, not R1 exhaustive or concrete SHAKE")


def finite_tail_checks():
    panels, traces = 0, 0
    for q, bits in ((1, 2), (2, 2), (3, 2)):
        space = 1 << bits
        for n in (1, 2, 3):
            for limit in range(0, 7):
                failures = sum(sum(word < q for word in raw) < n
                               for raw in product(range(space), repeat=limit))
                require(Fraction(failures, space**limit) == rejection_tail(q, n, bits, limit),
                        "binomial termination tail differs from direct enumeration")
                panels += 1
                traces += space**limit
    return dict(panels=panels, enumerated_raw_candidate_traces=traces, all_equal=True)
