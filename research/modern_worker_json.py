"""Export wrapper for the unchanged modern_worker.estimate calculation core."""

import argparse
import json
import math
from pathlib import Path
import time
import traceback

from cost_serialization import json_safe, log2_from_numeric_text
from modern_worker import estimate


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    job = json.loads(args.job)
    started = time.perf_counter()
    try:
        result = estimate(job)
        repaired = []
        for key, value in result.get("log2_cost", {}).items():
            if isinstance(value, float) and not math.isfinite(value):
                # Recompute from the unchanged cost's numeric text. A finite
                # huge integer must not be mislabeled as an infinite cost.
                result["log2_cost"][key] = log2_from_numeric_text(result["cost"][key])
                repaired.append(key)
        result["decimal_log_recomputed_fields"] = repaired
    except Exception as error:
        result = {"status": "error", "error_type": type(error).__name__, "error": str(error),
                  "traceback": traceback.format_exc()[-3500:]}
    result = {"job": job, **result, "elapsed_seconds": time.perf_counter()-started,
              "exporter": "modern_worker_json.py", "calculation_core": "modern_worker.estimate"}
    args.output.write_text(json.dumps(json_safe(result), indent=2, allow_nan=False)+"\n", encoding="utf-8")
