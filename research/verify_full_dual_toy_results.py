"""Standard-library replay of complete H06 finite scores and their provenance."""

import hashlib
import json
import math
from pathlib import Path

from full_dual_toy import dual_list,evaluate,lwe_law,matrix,score_table

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/"results/j2/run-013"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def compare(a,b):
    if isinstance(a,float) or isinstance(b,float):
        if not math.isclose(a,b,rel_tol=1e-10,abs_tol=2e-12):
            raise ValueError("H06 floating replay mismatch")
    elif isinstance(a,dict) and isinstance(b,dict):
        if set(a)!=set(b):
            raise ValueError("H06 dictionary field mismatch")
        for key in a:
            compare(a[key],b[key])
    elif isinstance(a,list) and isinstance(b,list):
        if len(a)!=len(b):
            raise ValueError("H06 list shape mismatch")
        for x,y in zip(a,b):
            compare(x,y)
    elif a!=b:
        raise ValueError("H06 exact replay mismatch")


def verify():
    for name in ("provenance.json","independent-provenance.json","interval-provenance.json"):
        data=read(RUN/name)
        for group,base in (("input_sha256",ROOT),("output_sha256",RUN)):
            for name,expected in data[group].items():
                path=(base/name).resolve()
                if not path.is_relative_to(base) or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
                    raise ValueError(f"H06 checksum mismatch: {name}")
    tables={r["q"]:r for r in read(RUN/"transcendental-tables.json")}
    study=read(RUN/"study.json")
    if study["protocol_commit"]!="3cbbd7c" or any(study[k] for k in ("attack_costs_updated","profile_selected","j2_closed")):
        raise ValueError("H06 scope mismatch")
    rows=[json.loads(s) for s in (RUN/"score-tables.jsonl").read_text().splitlines()]
    count=0
    for panel in study["panels"]:
        bank=panel["bank"]
        q,N=bank["q"],bank["size"]
        A=matrix(q,panel["matrix_identifier"])
        expected=dual_list(A,q,N,bank["code"]["family"],bank["metric"],tables[q]["cbd_weights"])
        compare(expected,bank)
        law=lwe_law(A,bank["code"]["generators"][0],q)
        compare(law,panel["observation_law"])
        scores,delta=score_table(bank,tables[q]["cosine_weights"])
        actual=[{k:v for k,v in r.items() if k!="panel"} for r in rows if r["panel"]==panel["panel"]]
        compare(scores,actual)
        compare(delta,panel["maximum_DFT_delta"])
        results=evaluate(bank,law,scores,tables[q]["cosine_weights"])
        compare(results,{k:v for k,v in panel.items() if k not in ("panel","bank","matrix_identifier","observation_law","maximum_DFT_delta")})
        count+=q*q*q
    independent=read(RUN/"independent-verification.json")
    intervals=read(RUN/"interval-verification.json")
    if len(study["panels"])!=32 or study["phase_identities_checked"]!=419904 or count!=80608:
        raise ValueError("H06 panel/phase/score coverage mismatch")
    if not independent["all_exact_laws_and_events_matched"] or independent["literal_CBD_bit_strings"]!=65536 or independent["complete_guess_scores"]!=count:
        raise ValueError("H06 independent enumeration missing")
    if not intervals["all_passed"] or intervals["weights_verified"]!=24 or intervals["decimal_digits"]!=160:
        raise ValueError("H06 independent interval evidence missing")
    return dict(snapshot="run-013",panels=32,complete_guess_scores=count,phase_identities_checked=419904,
                literal_CBD_bit_strings=65536,transcendental_entries_verified=24,
                attack_costs_updated=False,profile_selected=False,j2_closed=False)


if __name__=="__main__":
    print(json.dumps(verify(),indent=2))
