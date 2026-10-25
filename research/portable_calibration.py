"""Portable floating comparisons for historical H11 calibration tails.

Integer event counts and structure remain exact. Only finite floating
fields allow a relative tolerance of 1e-13 and an absolute floor of 1e-30.
"""
import math


def calibration_tails_match(actual, expected):
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, float):
        return (math.isfinite(actual) and math.isfinite(expected)
                and math.isclose(actual, expected, rel_tol=1e-13, abs_tol=1e-30))
    if isinstance(expected, dict):
        return (actual.keys() == expected.keys()
                and all(calibration_tails_match(actual[k], expected[k]) for k in expected))
    if isinstance(expected, list):
        return (len(actual) == len(expected)
                and all(calibration_tails_match(a, b) for a, b in zip(actual, expected)))
    return actual == expected

