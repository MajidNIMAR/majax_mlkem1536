"""JSON-safe logarithms, including native and symbolic infinities."""

import math
from decimal import Decimal, localcontext


def log2_from_numeric_text(value):
    """Avoid binary-float overflow before taking the log of a huge cost."""
    with localcontext() as context:
        context.prec = 80
        logarithm = float(Decimal(value).ln()/Decimal(2).ln())
    return json_safe(logarithm)


def json_safe(value):
    if isinstance(value, dict):
        return {key: json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        if math.isnan(value):
            return "undefined"
        return "+infinity" if value > 0 else "-infinity"
    return value


def log2_record(value, logarithm):
    if value == 0:
        return "-infinity"
    numeric = float(logarithm(value, 2))
    if math.isnan(numeric):
        return "undefined"
    if math.isinf(numeric):
        return "+infinity" if numeric > 0 else "-infinity"
    return numeric
