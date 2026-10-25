"""Same full-symbol budget for Euclidean and quantized CBD objectives."""

import numpy as np

from block_decoder import validate_values
from block_decoder_numpy import table


def decode(code, values, weights, metric):
    validate_values(values, code.q, code.n)
    if metric not in ("euclidean", "cbd"):
        raise ValueError("known metric required")
    lookup = np.asarray(weights, dtype=np.int64)
    labels, proofs, offset = [], [], 0
    for generator in code.generators:
        words = table(code.q, generator)
        delta = np.abs(words-np.asarray(values[offset:offset+len(generator)], dtype=np.int64))
        error = np.minimum(delta, code.q-delta)
        costs = np.sum(error*error if metric == "euclidean" else lookup[error], axis=1, dtype=np.int64)
        label = int(np.argmin(costs))
        labels.append(label)
        if metric == "cbd":
            # Include interval certification bookkeeping in the CBD timings.
            contenders = np.flatnonzero(costs < costs[label]+len(generator))
            selected = np.sort(error[label])
            exact = bool(np.all(np.sort(error[contenders], axis=1) == selected))
            second = int(np.min(np.delete(costs, label)))
            proofs.append(dict(integer_cost=int(costs[label]), second_symbol_integer_gap=second-int(costs[label]),
                               interval_contenders=len(contenders), real_optimum_certified=exact))
        offset += len(generator)
    return dict(labels=labels, certificates=proofs)
