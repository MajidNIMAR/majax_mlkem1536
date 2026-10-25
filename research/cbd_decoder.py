"""Integer-certified approximation to the ideal-CBD code contribution.

For f(d)=-2 log cos(pi*d/q), supplied weights floor(2^40*f(d)) enclose
the true objective. No changes to frozen decoders or rank-6 KEM operations.
This module and its scalar oracle use only the Python standard library.
"""

from collections import Counter
import math

from block_decoder import centered, validate_values

SCALE = 1 << 40


def validate_weights(q, weights):
    if len(weights) != q // 2 + 1 or weights[0] != 0:
        raise ValueError("one nonnegative cost per absolute centered residue required")
    if any(type(w) is not int or w < 0 for w in weights):
        raise ValueError("nonnegative integer weights required")
    if any(a >= b for a, b in zip(weights, weights[1:])):
        raise ValueError("strictly increasing quantized costs required")
    if 256 * max(weights) >= 2 ** 63:
        raise ValueError("costs exceed the supported int64 budget")


def errors(values, generator, label, q):
    return [abs(centered(x-label*g, q)) for x, g in zip(values, generator)]


def certificate(values, generator, q, weights, costs, label):
    """Certify a real-cost minimum if all interval contenders share its histogram.

Otherwise retain the uniform <dimension/SCALE objective regret guarantee.
The provided costs must have been exhaustively evaluated over the alphabet.
"""
    minimum = costs[label]
    if len(costs) != q or (minimum, label) != min((c, i) for i, c in enumerate(costs)):
        raise ValueError("smallest-symbol integer minimum required")
    contenders = [i for i, c in enumerate(costs) if c < minimum + len(generator)]
    histogram = Counter(errors(values, generator, label, q))
    same = all(Counter(errors(values, generator, i, q)) == histogram for i in contenders)
    second = min((c for i, c in enumerate(costs) if i != label), default=minimum)
    return dict(integer_cost=int(minimum), second_symbol_integer_gap=int(second-minimum),
                interval_contenders=len(contenders), real_optimum_certified=same)


def decode_scalar(code, values, weights, metric):
    validate_values(values, code.q, code.n)
    validate_weights(code.q, weights)
    if metric not in ("euclidean", "cbd"):
        raise ValueError("known metric required")
    labels, proofs, offset = [], [], 0
    for generator in code.generators:
        block = values[offset:offset+len(generator)]
        costs = [sum(e*e if metric == "euclidean" else weights[e]
                     for e in errors(block, generator, a, code.q)) for a in range(code.q)]
        label = min(range(code.q), key=lambda i: (costs[i], i))
        labels.append(label)
        if metric == "cbd":
            proofs.append(certificate(block, generator, code.q, weights, costs, label))
        offset += len(generator)
    return dict(labels=labels, certificates=proofs)


def describe(code, values, decoded, weights, eta):
    word = code.encode(decoded["labels"])
    residual = [centered(x-y, code.q) for x, y in zip(values, word)]
    log_bias = 2*eta*math.fsum(math.log(math.cos(math.pi*r/code.q)) for r in residual)/math.log(2)
    return dict(**decoded, squared_norm=sum(r*r for r in residual),
                integer_cost=sum(weights[abs(r)] for r in residual), log2_CBD=log_bias)


def summarize(rows, q, eta, dimension):
    def logmean(values):
        top = max(values)
        return top+math.log2(math.fsum(2**(v-top) for v in values)/len(values))
    euclidean = [r["euclidean"] for r in rows]
    cbd = [r["cbd"] for r in rows]
    gains = [b["log2_CBD"]-a["log2_CBD"] for a,b in zip(euclidean,cbd)]
    inflation = [b["squared_norm"]-a["squared_norm"] for a,b in zip(euclidean,cbd)]
    if min(inflation) < 0:
        raise ArithmeticError("Euclidean minimum was violated")
    epsilon = eta*dimension/SCALE/math.log(2)
    if min(gains) < -epsilon-1e-10:
        raise ArithmeticError("CBD regret bound was violated")
    return dict(samples=len(rows), q=q, eta=eta, dimension=dimension,
                changed_vectors=sum(a["labels"]!=b["labels"] for a,b in zip(euclidean,cbd)),
                changed_blocks=sum(x!=y for a,b in zip(euclidean,cbd) for x,y in zip(a["labels"],b["labels"])),
                mean_log2_bias_gain=math.fsum(gains)/len(rows), minimum_log2_bias_gain=min(gains),
                maximum_log2_bias_gain=max(gains),
                log2_ratio_mean_bias=logmean([r["log2_CBD"] for r in cbd])-logmean([r["log2_CBD"] for r in euclidean]),
                mean_norm_euclidean=math.fsum(math.sqrt(r["squared_norm"]) for r in euclidean)/len(rows),
                mean_norm_cbd=math.fsum(math.sqrt(r["squared_norm"]) for r in cbd)/len(rows),
                mean_squared_norm_increase=math.fsum(inflation)/len(rows),
                maximum_squared_norm_increase=max(inflation),
                blocks=sum(len(r["certificates"]) for r in cbd),
                real_optimum_certified_blocks=sum(c["real_optimum_certified"] for r in cbd for c in r["certificates"]),
                maximum_log2_regret_bound=epsilon)
