"""Standard replay of H07, including each exact-data cache identity."""

import hashlib
import json
from pathlib import Path

from dual_expansion import bank_for,bank_key,case_data,fingerprint,pack,summarize
from full_dual_toy import evaluate,lwe_law,score_table
from verify_full_dual_toy_results import compare

ROOT=Path(__file__).resolve().parents[1]
RUN=ROOT/"results/j2/run-014"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def verify():
    for name in ("provenance.json","independent-provenance.json"):
        provenance=read(RUN/name)
        for group,base in (("input_sha256",ROOT),("output_sha256",RUN)):
            for name,expected in provenance[group].items():
                path=(base/name).resolve()
                if not path.is_relative_to(base) or hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
                    raise ValueError(f"H07 checksum mismatch: {name}")
    cases=read(RUN/"cases.json")
    if len(cases)!=32:
        raise ValueError("32 matrices required")
    for case in cases:
        compare(case,case_data(case["q"],case["identifier"]))
    panels=read(RUN/"panels.json")
    banks=[json.loads(s) for s in (RUN/"banks.jsonl").read_text().splitlines()]
    table={r["q"]:r for r in read(ROOT/"results/j2/run-013/transcendental-tables.json")}
    by_case={c["case"]:c for c in cases}
    by_bank={r["bank_id"]:r for r in banks}
    expected={(c["case"],source,N,family,metric) for c in cases for source in ("reference","lll_box")
              for N in (4,8,12) for family in ("repeated","radix") for metric in ("euclidean","cbd")}
    if len(panels)!=768 or {(p["case"],p["source"],p["N"],p["family"],p["metric"]) for p in panels}!=expected:
        raise ValueError("H07 panel coverage mismatch")
    used=set()
    for p in panels:
        case=by_case[p["case"]]
        bank=bank_for(case,p["source"],p["N"],p["family"],p["metric"],table[case["q"]]["cbd_weights"])
        if bank_key(bank)!=p["bank_id"]:
            raise ValueError("H07 exact cache identity mismatch")
        used.add(p["bank_id"])
    if used!=set(by_bank) or len(by_bank)!=len(banks):
        raise ValueError("H07 missing/duplicate bank")
    law_cache={}
    count=0
    for r in banks:
        bank=r["bank"]
        if bank_key(bank)!=r["bank_id"]:
            raise ValueError("H07 saved bank identity mismatch")
        law_key=fingerprint([bank["A"],bank["q"],bank["code"]["generators"]])
        if law_key not in law_cache:
            law_cache[law_key]=lwe_law(bank["A"],bank["code"]["generators"][0],bank["q"])
        law=law_cache[law_key]
        if fingerprint(law)!=r["law_sha256"]:
            raise ValueError("H07 complete law hash mismatch")
        scores,delta=score_table(bank,table[bank["q"]]["cosine_weights"])
        if fingerprint(scores)!=r["score_table_sha256"]:
            raise ValueError("H07 complete score hash mismatch")
        compare(delta,r["maximum_DFT_delta"])
        compare(pack(evaluate(bank,law,scores,table[bank["q"]]["cosine_weights"])),r["result"])
        count+=bank["q"]**3
    summary=summarize(cases,panels,banks)
    compare(summary,read(RUN/"summary.json"))
    independent=read(RUN/"independent-verification.json")
    if not independent["exact_laws_events_and_hashes_matched"] or independent["literal_CBD_bit_strings"]!=524288 or independent["complete_guess_scores"]!=count or independent["distinct_score_banks"]!=len(banks):
        raise ValueError("H07 independent evidence mismatch")
    if read(RUN/"provenance.json")["protocol_commit"]!="9dfeefa":
        raise ValueError("H07 preregistration mismatch")
    return dict(snapshot="run-014",matrices=32,LLL_certificates=32,panels=768,distinct_score_banks=len(banks),
                complete_guess_scores=count,literal_CBD_bit_strings=524288,
                attack_costs_updated=False,profile_selected=False,j2_closed=False)


if __name__=="__main__":
    print(json.dumps(verify(),indent=2))
