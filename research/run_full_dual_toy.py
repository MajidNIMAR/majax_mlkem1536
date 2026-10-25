"""Execute preregistered H06; no changes to previous result snapshots."""

import argparse
from datetime import datetime,timezone
import hashlib
import itertools
import json
from pathlib import Path

from full_dual_toy import COS_SCALE,dual_list,evaluate,lwe_law,matrix,score_table
from cbd_decoder import SCALE

ROOT=Path(__file__).resolve().parents[1]


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path,value):
    with path.open("x",encoding="utf-8",newline="\n") as stream:
        json.dump(value,stream,indent=2,allow_nan=False)
        stream.write("\n")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def transcendental_tables():
    from sage.all import RealBallField
    field=RealBallField(192)
    previous={r["q"]:r for r in read(ROOT/"results/j2/run-012/weight-tables.json")}
    tables=[]
    for q in (5,17):
        costs=[0]
        cosine=[COS_SCALE]
        for d in range(1,q//2+1):
            for target,value in ((costs,-2*(field.pi()*d/q).cos().log()*SCALE),
                                 (cosine,(2*field.pi()*d/q).cos()*COS_SCALE)):
                lo,hi=int(value.lower().floor()),int(value.upper().floor())
                if lo!=hi:
                    raise ArithmeticError("transcendental interval not in one integer cell")
                target.append(lo)
        if q in previous and costs!=previous[q]["weights"]:
            raise ArithmeticError("H05 weights changed")
        tables.append(dict(q=q,cbd_scale=SCALE,cbd_weights=costs,cosine_scale=COS_SCALE,
                           cosine_weights=cosine,construction_bits=192))
    return tables


def check_phases(bank):
    q,A=bank["q"],bank["A"]
    generator=bank["code"]["generators"][0]
    count=0
    for state in itertools.product((-1,0,1),repeat=7):
        e,s=state[:2],state[2:]
        b=[(sum(a*v for a,v in zip(row,s))+error)%q for row,error in zip(A,e)]
        truth=sum(g*v for g,v in zip(generator,s[1:]))%q
        for row in bank["vectors"]:
            public=(sum(a*v for a,v in zip(row["y"],b))-row["c"]*truth)%q
            noise=sum(a*v for a,v in zip(row["coefficient"],state))%q
            if public!=noise:
                raise ArithmeticError("LWE dual and decoded phase identity failed")
            count+=1
    return count


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    output=args.output.resolve()
    if output==ROOT or not output.is_relative_to(ROOT) or output.exists():
        raise ValueError("new output directory below NIST required")
    from verify_cbd_decoder_results import verify
    verify()
    output.mkdir(parents=True)
    tables=transcendental_tables()
    write(output/"transcendental-tables.json",tables)
    panels=[]
    phase_checks=0
    with (output/"score-tables.jsonl").open("x",encoding="utf-8",newline="\n") as stream:
        for table in tables:
            q=table["q"]
            for identifier in (0,1):
                A=matrix(q,identifier)
                for family in ("repeated","radix"):
                    for metric in ("euclidean","cbd"):
                        for size in (4,8):
                            bank=dual_list(A,q,size,family,metric,table["cbd_weights"])
                            name=f"q{q}-matrix{identifier}-{family}-{metric}-N{size}"
                            law=lwe_law(A,bank["code"]["generators"][0],q)
                            scores,delta=score_table(bank,table["cosine_weights"])
                            phase_checks+=check_phases(bank)
                            for row in scores:
                                stream.write(json.dumps(dict(panel=name,**row))+"\n")
                            stream.flush()
                            result=evaluate(bank,law,scores,table["cosine_weights"])
                            panels.append(dict(panel=name,matrix_identifier=identifier,bank=bank,observation_law=law,
                                               maximum_DFT_delta=delta,**result))
                            print(f"{name}: strict={result['strict_success']['value']:.6f}, "
                                  f"tie-uniform={result['uniform_tie_success']['value']:.6f}, "
                                  f"null tail(.5)={result['uniform_null']['tails'][1]['fixed_guess_pass']['value']:.6f}",flush=True)
    write(output/"study.json",dict(panels=panels,protocol_commit="3cbbd7c",phase_identities_checked=phase_checks,
                                  matrices=4,CBD_states_per_matrix=2187,CBD_bit_denominator=16384,
                                  attack_costs_updated=False,profile_selected=False,j2_closed=False,
                                  scope="complete finite coded-dual score for the projected guess, not a full-size lattice attack",
                                  limits=["fixed tiny matrices, eta=1 and enumerated dual quotient; no BKZ, sieve or MLWE rotations",
                                          "DFT direct at all guesses, no optimized FFT or real-parameter cost",
                                          "success recovers the projected guess u, not necessarily the complete secret",
                                          "integer phase laws and certified ranks/tails; moments evaluated in floating point",
                                          "normal and independence predictions are diagnostics, not certified probabilities or bounds",
                                          "no security level, chosen profile or C05 update"]))
    inputs=["research/full_dual_toy.py","research/run_full_dual_toy.py","research/test_full_dual_toy.py",
            "research/verify_full_dual_toy_results.py","research/verify_full_dual_toy_independent.py",
            "research/verify_full_dual_toy_intervals.py","docs/PROTOCOLE_H06.md",
            "research/block_decoder.py","research/cbd_decoder.py","research/run_block_decoder.py",
            "results/j2/run-012/weight-tables.json","results/j2/run-012/provenance.json",
            "results/j2/run-012/interval-provenance.json","research/sage-linux-packages.json"]
    outputs=["transcendental-tables.json","score-tables.jsonl","study.json"]
    write(output/"provenance.json",dict(created_utc=datetime.now(timezone.utc).isoformat(),
                                      input_sha256={n:digest(ROOT/n) for n in inputs},output_sha256={n:digest(output/n) for n in outputs}))


if __name__=="__main__":
    main()
