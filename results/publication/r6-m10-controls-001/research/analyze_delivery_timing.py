"""Recompute the eight-key/five-class M04 timing diagnostic without filtering."""
import argparse
from collections import defaultdict
import gzip
import hashlib
import json
import math
from pathlib import Path
import statistics

CLASSES = ("honest", "canonical_changed_v", "noncanonical_first_u", "noncanonical_last_u", "zero")


def welch(a, b):
    ma, mb = statistics.mean(a), statistics.mean(b)
    variance = statistics.variance(a) / len(a) + statistics.variance(b) / len(b)
    if variance == 0:
        if ma != mb:
            raise ValueError("nonzero difference with zero estimated variance")
        value = 0.0
    else:
        value = (ma - mb) / math.sqrt(variance)
    return {"t": value, "mean_difference_ns": ma - mb,
            "relative_mean_difference": (ma - mb) / mb, "threshold_crossed": abs(value) >= 4.5}


def analyze(rows):
    groups, seen = defaultdict(list), set()
    for row in rows:
        key, label, round_, ns = (row[x] for x in ("key", "class", "round", "nanoseconds"))
        identity = (key, label, round_)
        if key not in range(8) or label not in CLASSES or round_ not in range(400):
            raise ValueError("unexpected key, class or round")
        if type(ns) is not int or ns <= 0 or identity in seen:
            raise ValueError("invalid duration or duplicate observation")
        seen.add(identity)
        groups[key, label].append(ns)
    if len(seen) != 16000 or any(len(groups[k, c]) != 400 for k in range(8) for c in CLASSES):
        raise ValueError("full 8 x 5 x 400 diagnostic required")
    contrasts = [{"key": k, "class": c, **welch(groups[k, c], groups[k, "honest"])}
                 for k in range(8) for c in CLASSES[1:]]
    return {"observations": len(seen), "fresh_keys": 8, "classes": 5,
            "observations_per_key_and_class": 400, "warmups_per_key_and_class": 50,
            "public_order_seed_hex": "4d30342d54494d45", "outliers_removed": 0,
            "contrasts": contrasts, "comparisons": 32,
            "maximum_absolute_t": max(abs(c["t"]) for c in contrasts),
            "threshold": 4.5, "threshold_crossings": sum(c["threshold_crossed"] for c in contrasts),
            "constant_time_proved": False, "multiple_comparison_control": "none; diagnostic only",
            "scope": "fixed ciphertext per class and key; finite raw-time observations; environment recorded separately"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    opener = gzip.open if args.input.suffix == ".gz" else open
    with opener(args.input, "rt", encoding="utf-8") as stream:
        result = analyze(json.loads(line) for line in stream)
    result["input_sha256"] = hashlib.sha256(args.input.read_bytes()).hexdigest()
    text = json.dumps(result, indent=2) + "\n"
    if args.output:
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
    print(text)


if __name__ == "__main__":
    main()
