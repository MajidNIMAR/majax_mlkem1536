"""Independent mpmath interval verification of H06 cosine and cost tables."""

import argparse
from datetime import datetime,timezone
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
    count=0
    for table in json.loads((run/"transcendental-tables.json").read_text()):
        q=table["q"]
        for d in range(q//2+1):
            for key,scale in (("cbd_weights",table["cbd_scale"]),("cosine_weights",table["cosine_scale"])):
                weight=table[key][d]
                if d==0:
                    if weight!=(0 if key=="cbd_weights" else scale):
                        raise ValueError("exact zero-angle entry disagrees")
                else:
                    value=(-2*mp.iv.ln(mp.iv.cos(mp.iv.pi*d/q))*scale if key=="cbd_weights"
                           else mp.iv.cos(2*mp.iv.pi*d/q)*scale)
                    if not bool(value>=weight) or not bool(value<weight+1):
                        raise ArithmeticError("H06 weight enclosure outside its integer cell")
                count+=1
    result=dict(method="mpmath.iv at 160 decimals, without Sage or project arithmetic imports",
                weights_verified=count,decimal_digits=160,all_passed=True)
    with (run/"interval-verification.json").open("x",encoding="utf-8",newline="\n") as stream:
        json.dump(result,stream,indent=2)
        stream.write("\n")
    inputs=["research/verify_full_dual_toy_intervals.py",(run/"transcendental-tables.json").relative_to(ROOT).as_posix(),"research/sage-linux-packages.json"]
    provenance=dict(created_utc=datetime.now(timezone.utc).isoformat(),
                    input_sha256={n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in inputs},
                    output_sha256={"interval-verification.json":hashlib.sha256((run/"interval-verification.json").read_bytes()).hexdigest()})
    with (run/"interval-provenance.json").open("x",encoding="utf-8",newline="\n") as stream:
        json.dump(provenance,stream,indent=2)
        stream.write("\n")
    print(json.dumps(result),flush=True)


if __name__=="__main__":
    main()
