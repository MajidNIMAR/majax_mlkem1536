"""Finite exact quantum checks for M10's hidden-label norm hybrid.

All amplitudes are integers with a common square-root-of-power-of-two
denominator. Enumerated circuits are diagnostics, not a formal proof of all
quantum adversaries and not an execution of a cryptanalytic attack on R1.
"""
from fractions import Fraction
from itertools import permutations, product

from m10_security_sampler import natural, require


def walsh(amplitudes):
    """Unnormalised Walsh-Hadamard; caller tracks the exact squared scale."""
    count = len(amplitudes)
    require(count > 0 and count & (count-1) == 0, "power-of-two state required")
    return [sum(value * (-1 if (x & y).bit_count() & 1 else 1)
                for x, value in enumerate(amplitudes)) for y in range(count)]


def evolve(table, queries, schedule, public):
    """A phase-oracle circuit with public-data-dependent gates, independent of S."""
    count = len(table)
    require(count > 0 and count & (count-1) == 0, "power-of-two oracle required")
    require(set(table) <= {0, 1}, "binary phase table required")
    natural(queries, "queries", 16)
    require(schedule in (0, 1), "unknown finite schedule")
    amplitudes = walsh([1] + [0]*(count-1))
    scale_squared = count
    for step in range(queries):
        amplitudes = [(-value if table[x] else value) for x, value in enumerate(amplitudes)]
        if schedule == 0:
            amplitudes = walsh(amplitudes)
            scale_squared *= count
        else:
            # Exact inversion about average: H Z_0 H, plus a public phase.
            amplitudes = walsh(amplitudes)
            amplitudes[0] *= -1
            amplitudes = walsh(amplitudes)
            scale_squared *= count**2
        amplitudes = [(-value if (x & (public+step)).bit_count() & 1 else value)
                      for x, value in enumerate(amplitudes)]
    require(sum(value*value for value in amplitudes) == scale_squared, "finite circuit lost unit norm")
    return amplitudes, scale_squared


def finite_quantum_checks():
    """For every listed oracle/value, average over every hidden ordered label.

    E[||psi-psi'||^2] <=4*q^2*s/M and (E[TV])^2 <=4*q^2*s/M are checked
    by exact integers/fractions. The public value can select the circuit's
    gates; the hidden address cannot. One- and two-label cases are distinct.
    """
    panels, pairs = 0, 0
    for bits, rows in ((1, 1), (1, 2), (2, 1), (2, 2), (3, 1)):
        count = 1 << bits
        labels = list(permutations(range(count), rows))
        for raw in product((0, 1), repeat=count):
            for programmed in product((0, 1), repeat=rows):
                public = sum(v << i for i, v in enumerate(programmed))
                for schedule in (0, 1):
                    for queries in range(4):
                        baseline, denominator = evolve(raw, queries, schedule, public)
                        norm_total = Fraction(0)
                        tv_total = Fraction(0)
                        for target in labels:
                            changed = list(raw)
                            for label, value in zip(target, programmed):
                                changed[label] = value
                            candidate, other_denominator = evolve(changed, queries, schedule, public)
                            require(denominator == other_denominator, "finite scale mismatch")
                            norm_total += Fraction(sum((x-y)**2 for x, y in zip(baseline, candidate)), denominator)
                            tv_total += Fraction(sum(abs(x*x-y*y) for x, y in zip(baseline, candidate)), 2*denominator)
                            pairs += 1
                        bound_squared = Fraction(4*queries**2*rows, count)
                        require(norm_total/len(labels) <= bound_squared, "hidden-label squared norm hybrid failed")
                        require((tv_total/len(labels))**2 <= bound_squared, "hidden-label averaged measurement bound failed")
                        panels += 1
    return dict(panels=panels, exact_oracle_circuit_pairs=pairs,
                hidden_row_counts=[1, 2], address_bits=[1, 2, 3], query_counts=[0, 1, 2, 3],
                all_exact_squared_norm_and_probability_bounds_pass=True,
                no_query_register_measurement_inserted=True,
                scope="listed finite circuits only; not all adversaries, R1 attacks, or a machine-checked general proof")


def finite_controlled_oracle_checks():
    """Two calls implement controlled XOR without assuming a controlled RO.

    The work register starts at zero. Compute O(x), XOR into output iff the
    public flag is true, then uncompute O(x). All basis states are checked;
    linearity then gives the same equality on their superpositions.
    """
    cases = 0
    for table in product(range(4), repeat=3):
        for index, output, flag in product(range(3), range(4), (0, 1)):
            work = 0
            work ^= table[index]
            value = output ^ work if flag else output
            work ^= table[index]
            require(work == 0 and value == (output ^ (table[index] if flag else 0)),
                    "compute/copy/uncompute did not implement the controlled coordinate")
            cases += 1
    return dict(exact_basis_cases=cases, oracle_calls=2, work_register_restored=True,
                extension_to_superpositions="linear equality on the complete listed basis",
                scope="coordinate bridge, not the complete reversible R1 circuit")
