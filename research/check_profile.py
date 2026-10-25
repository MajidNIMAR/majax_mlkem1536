"""Independent structural checks using the Python standard library, not a KEM test."""

import json
from pathlib import Path
import sys
import tomllib


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    with (root / "profiles" / "kem1536-p0.toml").open("rb") as stream:
        profile = tomllib.load(stream)
    p = profile["parameters"]
    if profile["profile"] != {"id": "KEM1536-EXP-P0", "version": "0.1"}:
        raise ValueError("unexpected profile identity")
    if p != dict(n=256, k=6, q=3329, eta1=2, eta2=2, du=11, dv=5,
                 seed_bytes=32, shared_secret_bytes=32):
        raise ValueError("unexpected P0 parameters")
    vector = p["n"] * p["k"] * 12 // 8
    ek = vector + p["seed_bytes"]
    c1 = p["n"] * p["k"] * p["du"] // 8
    c2 = p["n"] * p["dv"] // 8
    calculated = dict(vector_bytes=vector, encapsulation_key_bytes=ek,
                      decapsulation_key_bytes=vector + ek + 32 + p["seed_bytes"],
                      c1_bytes=c1, c2_bytes=c2, ciphertext_bytes=c1 + c2,
                      shared_secret_bytes=p["shared_secret_bytes"])
    if profile["expected_sizes"] != calculated:
        raise ValueError("profile sizes disagree with independent calculations")
    print(json.dumps({"profile_id": profile["profile"]["id"],
                      "configuration_check": "passed", "coefficient_count": p["n"] * p["k"],
                      "sizes_bytes": calculated, "cryptographic_validation": "pending"}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, OSError) as error:
        print(f"Profile check failed: {error}", file=sys.stderr)
        sys.exit(1)

