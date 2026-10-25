"""Independent interval verification of every H05 weight, without Sage imports."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run",type=Path,required=True)
    args=parser.parse_args()
    run=args.run.resolve()
    if not run.is_relative_to(ROOT):
        raise ValueError("run below NIST required")
    import mpmath as mp
    mp.iv.dps=160
    tables=json.loads((run/"weight-tables.json").read_text())
    checked=0
    for table in tables:
        q,scale=table["q"],table["scale"]
        for d,w in enumerate(table["weights"]):
            if d==0:
                if w!=0:
                    raise ValueError("zero weight mismatch")
            else:
                value=-2*mp.iv.ln(mp.iv.cos(mp.iv.pi*d/q))*scale
                if not bool(value>=w) or not bool(value<w+1):
                    raise ArithmeticError(f"weight interval not inside integer cell: {q}/{d}")
            checked+=1
    result=dict(method="mpmath.iv outward interval arithmetic; no Sage or project arithmetic import",
                decimal_digits=160,tables=len(tables),weights_verified=checked,all_passed=True)
    with (run/"interval-verification.json").open("x",encoding="utf-8",newline="\n") as stream:
        json.dump(result,stream,indent=2)
        stream.write("\n")
    names=["research/verify_cbd_decoder_intervals.py",(run/"weight-tables.json").relative_to(ROOT).as_posix(),"research/sage-linux-packages.json"]
    provenance=dict(created_utc=datetime.now(timezone.utc).isoformat(),
                    input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in names},
                    output_sha256={"interval-verification.json":hashlib.sha256((run/"interval-verification.json").read_bytes()).hexdigest()})
    with (run/"interval-provenance.json").open("x",encoding="utf-8",newline="\n") as stream:
        json.dump(provenance,stream,indent=2)
        stream.write("\n")
    print(json.dumps(result),flush=True)


if __name__=="__main__":
    main()
