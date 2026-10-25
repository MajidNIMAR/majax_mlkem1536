"""Exact integer enumeration accelerated with NumPy; no approximation.

Tables contain every symbol of each length-one generated code block. The
full code is a direct product, so disjoint minimizations are globally exact.
"""

from functools import cache

import numpy as np

from block_decoder import validate_values


@cache
def table(q, generator):
    return np.arange(q, dtype=np.int64)[:, None] * np.array(generator, dtype=np.int64)[None, :] % q


def decode(code, values):
    validate_values(values, code.q, code.n)
    labels, squared, offset = [], 0, 0
    for generator in code.generators:
        words = table(code.q, generator)
        target = np.array(values[offset:offset + len(generator)], dtype=np.int64)
        difference = np.abs(words - target)
        error = np.minimum(difference, code.q - difference)
        scores = np.sum(error * error, axis=1, dtype=np.int64)
        label = int(np.argmin(scores))
        labels.append(label)
        squared += int(scores[label])
        offset += len(generator)
    return dict(labels=labels, squared_norm=squared, candidate_scores=code.q * code.k,
                coordinate_distance_terms=code.q * code.n)


def warm_tables(code):
    for generator in code.generators:
        table(code.q, generator)
