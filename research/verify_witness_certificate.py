"""Replay the rational Chernoff certificate without a full noise recurrence."""

from fractions import Fraction
import hashlib
import json
from pathlib import Path

from witness_chernoff import certificate

ROOT = Path(__file__).resolve().parents[1]
RUN = ROOT / "results/j2/run-004"


def verify():
    provenance = json.loads((RUN / "certificate-provenance.json").read_text(encoding="utf-8"))
    for group, base in (("input_sha256", ROOT), ("output_sha256", RUN)):
        for name, expected in provenance[group].items():
            path = (base / name).resolve()
            if not path.is_relative_to(base) or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError(f"witness certificate checksum mismatch: {name}")
    saved = json.loads((RUN / "correctness-certificate.json").read_text(encoding="utf-8"))
    replayed = certificate()
    for key in ("parameters", "mgf_product", "mgf_e2", "message_upper", "v_error_range",
                "common_safe_radius", "tilt_z", "one_sided_tail_threshold", "c05_exact_comparison"):
        if saved[key] != replayed[key]:
            raise ValueError(f"independent certificate replay failed: {key}")
    bound = Fraction(int(saved["message_upper"]["numerator_hex"], 16),
                     int(saved["message_upper"]["denominator_hex"], 16))
    if (bound.numerator ** 5 << 874) > bound.denominator ** 5:
        raise ValueError("exact C05 comparison failed")
    return {"snapshot": "run-004", "certificate": "rational Chernoff replay passed",
            "full_noise_recurrence_used": False, "c05_exact_comparison": True,
            "log2_upper_display": replayed["log2_message_upper_display"]}


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
